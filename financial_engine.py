"""
MizanPro - Financial Statements, Cash Flow, VAT Return, ZATCA Zakat & Pre-Approval Audit Engine
النظام المالي المتكامل - ميزان برو
محرك إعداد القوائم المالية الشاملة والتدفقات النقدية وإقرار ضريبة القيمة المضافة ووعاء الزكاة الشرعي وفحص المطابقة قبل الاعتماد
"""

from datetime import date
from decimal import Decimal
from typing import Dict, Any, Optional, List
import pandas as pd
from models import to_decimal, quantize_money, round_money


class FinancialStatementsEngine:
    """محرك القوائم المالية والتدفقات النقدية والامتثال الزكوي والضريبي (IFRS / SOCPA / ZATCA)"""

    def __init__(
        self,
        trial_balance_df: pd.DataFrame,
        fiscal_year: int = 2026,
        total_days: int = 365,
        vat_rate: float = 0.15,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None
    ):
        """
        تهيئة المحرك بجدول ميزان المراجعة المولد من LedgerService مع تحديد صريح لتواريخ بداية ونهاية الفترة
        """
        self.raw_tb = trial_balance_df.copy()
        self.fiscal_year = int(fiscal_year)
        self.start_date: date = start_date or date(self.fiscal_year, 1, 1)
        self.end_date: date = end_date or date(self.fiscal_year, 12, 31)
        computed_days = (self.end_date - self.start_date).days + 1
        self.total_days = computed_days if (start_date and end_date and computed_days > 0) else total_days
        self.vat_rate = float(vat_rate) if vat_rate and vat_rate > 0 else 0.15

        self.period_label_ar = f"عن الفترة من {self.start_date.strftime('%Y-%m-%d')} إلى {self.end_date.strftime('%Y-%m-%d')}"
        self.as_of_label_ar = f"كما في {self.end_date.strftime('%Y-%m-%d')}"

        # النسبة الزكوية المعتمدة للسنة الميلادية (2.5% * عدد أيام الفترة / 354)
        self.zakat_rate_gregorian = 0.025 * (365.0 / 354.0)

        self._prepare_data()

    def _prepare_data(self):
        """تنظيف وتصنيف الحسابات واستخراج الأرصدة الختامية والافتتاحية وحركة الفترة"""
        if self.raw_tb.empty:
            self.df = pd.DataFrame(columns=[
                "Account Code", "Account Name", "Account Type",
                "Account SubType", "Natural Balance", "Opening Debit", "Opening Credit",
                "Period Debit", "Period Credit", "Closing Debit", "Closing Credit", "Net Balance"
            ])
            self._has_period_columns = False
            return

        self.df = self.raw_tb.copy()
        self.df["Account Code"] = self.df["Account Code"].astype(str)

        has_p_cols = ("Period Debit" in self.df.columns and "Period Credit" in self.df.columns)
        for col in ["Opening Debit", "Opening Credit", "Period Debit", "Period Credit", "Closing Debit", "Closing Credit", "Net Balance"]:
            if col not in self.df.columns:
                self.df[col] = 0.0

        # إذا كان الميزان يحتوي على أعمدة حركة الفترة (أو أرصدة افتتاحية)، نعتمد على حركة الفترة لقائمة الدخل والضريبة
        p_sum = float(self.df["Period Debit"].abs().sum() + self.df["Period Credit"].abs().sum())
        o_sum = float(self.df["Opening Debit"].abs().sum() + self.df["Opening Credit"].abs().sum())
        self._has_period_columns = bool(has_p_cols and (p_sum > 0.0 or o_sum > 0.0))

    def _filter_df(self, sub_types=None, account_types=None, codes_prefix=None, exclude_prefixes=None) -> pd.DataFrame:
        if self.df.empty:
            return self.df

        filtered = self.df.copy()

        if sub_types:
            if isinstance(sub_types, list):
                filtered = filtered[filtered["Account SubType"].isin(sub_types)]
            else:
                filtered = filtered[filtered["Account SubType"] == sub_types]

        if account_types:
            if isinstance(account_types, list):
                filtered = filtered[filtered["Account Type"].isin(account_types)]
            else:
                filtered = filtered[filtered["Account Type"] == account_types]

        if codes_prefix:
            prefixes = tuple(str(p) for p in codes_prefix) if isinstance(codes_prefix, list) else (str(codes_prefix),)
            filtered = filtered[filtered["Account Code"].str.startswith(prefixes)]

        if exclude_prefixes:
            ex_prefixes = tuple(str(p) for p in exclude_prefixes) if isinstance(exclude_prefixes, list) else (str(exclude_prefixes),)
            filtered = filtered[~filtered["Account Code"].str.startswith(ex_prefixes)]

        return filtered

    def _get_balance(self, sub_types=None, account_types=None, codes_prefix=None, exclude_prefixes=None) -> float:
        """حساب مجموع الأرصدة الختامية التراكمية (للمركز المالي كما في نهاية الفترة) بدقة Decimal"""
        filtered = self._filter_df(sub_types, account_types, codes_prefix, exclude_prefixes)
        if filtered.empty:
            return 0.0

        total = Decimal("0.00")
        for _, row in filtered.iterrows():
            nat_bal = row.get("Natural Balance", "DEBIT")
            c_deb = to_decimal(row.get("Closing Debit", 0.0))
            c_crd = to_decimal(row.get("Closing Credit", 0.0))

            if nat_bal == "DEBIT":
                total += (c_deb - c_crd)
            else:
                total += (c_crd - c_deb)

        return round_money(total)

    def _get_period_balance(self, sub_types=None, account_types=None, codes_prefix=None, exclude_prefixes=None) -> float:
        """
        حساب صافي حركة الفترة فقط (Period Movement: من start_date إلى end_date)
        للاستخدام الصارم في قائمة الدخل وإقرار ضريبة القيمة المضافة بحيث لا تتأثر بالقيود السابقة لبداية الفترة.
        """
        if not self._has_period_columns:
            return self._get_balance(sub_types, account_types, codes_prefix, exclude_prefixes)

        filtered = self._filter_df(sub_types, account_types, codes_prefix, exclude_prefixes)
        if filtered.empty:
            return 0.0

        total = Decimal("0.00")
        for _, row in filtered.iterrows():
            nat_bal = row.get("Natural Balance", "DEBIT")
            p_deb = to_decimal(row.get("Period Debit", 0.0))
            p_crd = to_decimal(row.get("Period Credit", 0.0))

            if nat_bal == "DEBIT":
                total += (p_deb - p_crd)
            else:
                total += (p_crd - p_deb)

        return round_money(total)

    def _get_opening_balance(self, sub_types=None, account_types=None, codes_prefix=None, exclude_prefixes=None) -> float:
        """حساب مجموع الأرصدة الافتتاحية (ما قبل start_date) لدعم التدفقات النقدية والأرباح المرحلة بدقة Decimal"""
        filtered = self._filter_df(sub_types, account_types, codes_prefix, exclude_prefixes)
        if filtered.empty:
            return 0.0

        total = Decimal("0.00")
        for _, row in filtered.iterrows():
            nat_bal = row.get("Natural Balance", "DEBIT")
            o_deb = to_decimal(row.get("Opening Debit", 0.0))
            o_crd = to_decimal(row.get("Opening Credit", 0.0))

            if nat_bal == "DEBIT":
                total += (o_deb - o_crd)
            else:
                total += (o_crd - o_deb)

        return round_money(total)

    def _get_turnover(self, codes_prefix) -> Dict[str, float]:
        """استخراج إجمالي حركة المدين والدائن خلال الفترة لحسابات محددة (لإقرار الضريبة والتدفقات)"""
        if self.df.empty:
            return {"period_debit": 0.0, "period_credit": 0.0, "closing_debit": 0.0, "closing_credit": 0.0}

        prefixes = tuple(str(p) for p in codes_prefix) if isinstance(codes_prefix, list) else (str(codes_prefix),)
        filtered = self.df[self.df["Account Code"].str.startswith(prefixes)]

        return {
            "period_debit": round_money(filtered["Period Debit"].sum()),
            "period_credit": round_money(filtered["Period Credit"].sum()),
            "closing_debit": round_money(filtered["Closing Debit"].sum()),
            "closing_credit": round_money(filtered["Closing Credit"].sum()),
        }

    # =========================================================================
    # 1. قائمة الدخل الشامل (Statement of Profit or Loss - Period Movement)
    # =========================================================================
    def generate_income_statement(self) -> Dict[str, Any]:
        """توليد قائمة الدخل الشامل بالاعتماد الحصري على حركة الفترة [start_date, end_date]"""
        sales_returns = to_decimal(self._get_period_balance(codes_prefix=["4102"]))
        sales_discounts = to_decimal(self._get_period_balance(codes_prefix=["4103"]))
        gross_sales = to_decimal(self._get_period_balance(
            sub_types=["OPERATING_REVENUE"],
            exclude_prefixes=["4102", "4103"]
        ))
        net_revenue = quantize_money(gross_sales - sales_returns - sales_discounts)

        # تكلفة المبيعات لحركة الفترة فقط
        purchase_returns = to_decimal(self._get_period_balance(codes_prefix=["5103"]))
        purchase_discounts = to_decimal(self._get_period_balance(codes_prefix=["5104"]))
        inventory_shrinkage = to_decimal(self._get_period_balance(codes_prefix=["5105"]))
        direct_cogs = to_decimal(self._get_period_balance(
            sub_types=["COST_OF_SALES"],
            exclude_prefixes=["5103", "5104", "5105"]
        ))
        cogs = quantize_money(direct_cogs - purchase_returns - purchase_discounts + inventory_shrinkage)

        gross_profit = quantize_money(net_revenue - cogs)

        # المصاريف التشغيلية لحركة الفترة فقط
        salaries = to_decimal(self._get_period_balance(codes_prefix=["5201"]))
        rent = to_decimal(self._get_period_balance(codes_prefix=["5202"]))
        utilities = to_decimal(self._get_period_balance(codes_prefix=["5203"]))
        maintenance = to_decimal(self._get_period_balance(codes_prefix=["5204"]))
        marketing = to_decimal(self._get_period_balance(codes_prefix=["5205"]))
        gov_fees = to_decimal(self._get_period_balance(codes_prefix=["5206"]))
        depreciation = to_decimal(self._get_period_balance(codes_prefix=["5207"]))
        eos_expense = to_decimal(self._get_period_balance(codes_prefix=["5208"]))
        other_admin = to_decimal(self._get_period_balance(
            sub_types=["OPERATING_EXPENSE", "OTHER_EXPENSE"],
            exclude_prefixes=["5201", "5202", "5203", "5204", "5205", "5206", "5207", "5208"]
        ))

        total_operating_expenses = quantize_money(
            salaries + rent + utilities + maintenance + marketing +
            gov_fees + depreciation + eos_expense + other_admin
        )

        operating_profit = quantize_money(gross_profit - total_operating_expenses)

        other_income = to_decimal(self._get_period_balance(sub_types=["OTHER_INCOME"]))
        finance_costs = to_decimal(self._get_period_balance(sub_types=["FINANCIAL_EXPENSE"], exclude_prefixes=["5302"]))

        profit_before_zakat = quantize_money(operating_profit + other_income - finance_costs)

        booked_zakat_expense = to_decimal(self._get_period_balance(codes_prefix=["5302"]))
        zakat_data = self.calculate_zakat_base(float(profit_before_zakat))
        zakat_expense = booked_zakat_expense if abs(booked_zakat_expense) > Decimal("0.001") else to_decimal(zakat_data["zakat_due"])

        net_profit_after_zakat = quantize_money(profit_before_zakat - zakat_expense)
        gross_margin_pct = round(float(gross_profit / net_revenue) * 100, 2) if net_revenue > Decimal("0.00") else 0.0
        net_margin_pct = round(float(net_profit_after_zakat / net_revenue) * 100, 2) if net_revenue > Decimal("0.00") else 0.0

        op_exp_breakdown: List[Dict[str, Any]] = []
        if not self.df.empty:
            exp_rows = self.df[self.df["Account SubType"] == "OPERATING_EXPENSE"]
            for _, r in exp_rows.iterrows():
                nat_bal = r.get("Natural Balance", "DEBIT")
                if self._has_period_columns:
                    r_deb = to_decimal(r.get("Period Debit", 0.0))
                    r_crd = to_decimal(r.get("Period Credit", 0.0))
                else:
                    r_deb = to_decimal(r.get("Closing Debit", 0.0))
                    r_crd = to_decimal(r.get("Closing Credit", 0.0))
                val = round_money((r_deb - r_crd) if nat_bal == "DEBIT" else (r_crd - r_deb))
                if abs(val) >= 0.01:
                    op_exp_breakdown.append({
                        "code": str(r["Account Code"]),
                        "name": str(r["Account Name"]),
                        "amount": round_money(val)
                    })

        return {
            "start_date": self.start_date.strftime("%Y-%m-%d"),
            "end_date": self.end_date.strftime("%Y-%m-%d"),
            "period_start": self.start_date.strftime("%Y-%m-%d"),
            "period_end": self.end_date.strftime("%Y-%m-%d"),
            "period_label_ar": self.period_label_ar,
            "gross_sales": round_money(gross_sales),
            "sales_returns": round_money(sales_returns),
            "sales_discounts": round_money(sales_discounts),
            "net_revenue": round_money(net_revenue),
            "cost_of_sales_breakdown": {
                "direct_cogs": round_money(direct_cogs),
                "purchase_returns": round_money(purchase_returns),
                "purchase_discounts": round_money(purchase_discounts),
                "inventory_adjustments": round_money(inventory_shrinkage),
            },
            "cost_of_sales": round_money(cogs),
            "gross_profit": round_money(gross_profit),
            "gross_margin_pct": gross_margin_pct,
            "operating_expenses": {
                "salaries": round_money(salaries),
                "rent": round_money(rent),
                "utilities": round_money(utilities),
                "maintenance": round_money(maintenance),
                "marketing": round_money(marketing),
                "government_fees": round_money(gov_fees),
                "depreciation": round_money(depreciation),
                "end_of_service": round_money(eos_expense),
                "other_admin": round_money(other_admin),
                "total": round_money(total_operating_expenses),
                "breakdown": op_exp_breakdown,
            },
            "operating_profit": round_money(operating_profit),
            "other_income": round_money(other_income),
            "finance_costs": round_money(finance_costs),
            "financial_charges": round_money(finance_costs),
            "profit_before_zakat": round_money(profit_before_zakat),
            "zakat_expense": round_money(zakat_expense),
            "net_profit": round_money(net_profit_after_zakat),
            "net_margin_pct": net_margin_pct,
        }

    # =========================================================================
    # 2. قائمة المركز المالي (Statement of Financial Position)
    # =========================================================================
    def generate_balance_sheet(self, net_profit_period: float, estimated_zakat: float = 0.0) -> Dict[str, Any]:
        """توليد قائمة المركز المالي كما في تاريخ نهاية الفترة مع ترحيل نتائج الفترات السابقة غير المقفلة"""
        cash_and_equivalents = to_decimal(self._get_balance(codes_prefix=["1101", "1102"]))
        ecl_allowance = to_decimal(self._get_balance(codes_prefix=["110303"]))
        trade_receivables_gross = to_decimal(self._get_balance(codes_prefix=["1103"], exclude_prefixes=["110303"]))
        net_trade_receivables = quantize_money(trade_receivables_gross - ecl_allowance)

        inventory = to_decimal(self._get_balance(codes_prefix=["1104"]))
        input_vat_recoverable = to_decimal(self._get_balance(codes_prefix=["110503"]))
        prepayments_and_other = to_decimal(self._get_balance(
            sub_types=["CURRENT_ASSET"],
            exclude_prefixes=["1101", "1102", "1103", "1104", "110503"]
        ))

        total_current_assets = quantize_money(
            cash_and_equivalents + net_trade_receivables +
            inventory + prepayments_and_other + input_vat_recoverable
        )

        ppe_gross = to_decimal(self._get_balance(codes_prefix=["1201"]))
        accum_depreciation = to_decimal(self._get_balance(codes_prefix=["1202"]))
        net_ppe = quantize_money(ppe_gross - accum_depreciation)
        intangibles = to_decimal(self._get_balance(
            sub_types=["NON_CURRENT_ASSET"],
            exclude_prefixes=["1201", "1202"]
        ))

        total_non_current_assets = quantize_money(net_ppe + intangibles)
        total_assets = quantize_money(total_current_assets + total_non_current_assets)

        trade_payables = to_decimal(self._get_balance(codes_prefix=["2101"]))
        output_vat_payable = to_decimal(self._get_balance(codes_prefix=["210204"]))
        book_zakat_provision = to_decimal(self._get_balance(codes_prefix=["210205"]))
        booked_zakat_expense = to_decimal(self._get_period_balance(codes_prefix=["5302"]))
        unbooked_zakat_accrual = (
            max(Decimal("0.00"), to_decimal(estimated_zakat) - booked_zakat_expense)
            if abs(booked_zakat_expense) < Decimal("0.001") else Decimal("0.00")
        )
        total_zakat_payable = quantize_money(book_zakat_provision + unbooked_zakat_accrual)

        accruals_and_other = to_decimal(self._get_balance(
            sub_types=["CURRENT_LIABILITY"],
            exclude_prefixes=["2101", "210204", "210205"]
        ))

        total_current_liabilities = quantize_money(
            trade_payables + accruals_and_other +
            output_vat_payable + total_zakat_payable
        )

        eos_provision = to_decimal(self._get_balance(codes_prefix=["2202"]))
        long_term_loans = to_decimal(self._get_balance(
            sub_types=["NON_CURRENT_LIABILITY"],
            exclude_prefixes=["2202"]
        ))

        total_non_current_liabilities = quantize_money(long_term_loans + eos_provision)
        total_liabilities = quantize_money(total_current_liabilities + total_non_current_liabilities)

        capital = to_decimal(self._get_balance(codes_prefix=["3101"]))
        statutory_reserve = to_decimal(self._get_balance(codes_prefix=["3102"]))

        # أي أرباح أو خسائر غير مقفلة سُجلت قبل start_date تُرحل تلقائياً إلى الأرباح المبقاة في بداية الفترة
        prior_unclosed_revenues = to_decimal(self._get_opening_balance(account_types=["REVENUE"]))
        prior_unclosed_expenses = to_decimal(self._get_opening_balance(account_types=["EXPENSE"]))
        prior_unclosed_net = quantize_money(prior_unclosed_revenues - prior_unclosed_expenses)

        retained_earnings_opening = quantize_money(
            to_decimal(self._get_balance(codes_prefix=["3103"])) + prior_unclosed_net
        )
        partners_current = to_decimal(self._get_balance(
            sub_types=["EQUITY"],
            exclude_prefixes=["3101", "3102", "3103"]
        ))

        net_profit_dec = to_decimal(net_profit_period)
        total_equity = quantize_money(
            capital + statutory_reserve + retained_earnings_opening +
            partners_current + net_profit_dec
        )

        total_liabilities_and_equity = quantize_money(total_liabilities + total_equity)
        balance_difference = quantize_money(abs(total_assets - total_liabilities_and_equity))
        is_balanced = balance_difference < Decimal("0.01")
        working_capital = quantize_money(total_current_assets - total_current_liabilities)

        current_assets_dict = {
            "cash_and_equivalents": round_money(cash_and_equivalents),
            "cash_and_banks": round_money(cash_and_equivalents),
            "trade_receivables_gross": round_money(trade_receivables_gross),
            "ecl_allowance": round_money(ecl_allowance),
            "net_trade_receivables": round_money(net_trade_receivables),
            "net_receivables": round_money(net_trade_receivables),
            "inventory": round_money(inventory),
            "prepayments_and_other": round_money(prepayments_and_other),
            "input_vat_recoverable": round_money(input_vat_recoverable),
            "prepaid_and_other": round_money(prepayments_and_other + input_vat_recoverable),
            "total": round_money(total_current_assets)
        }
        non_current_assets_dict = {
            "ppe_gross": round_money(ppe_gross),
            "gross_fixed_assets": round_money(ppe_gross),
            "accumulated_depreciation": round_money(accum_depreciation),
            "net_ppe": round_money(net_ppe),
            "intangibles": round_money(intangibles),
            "intangible_assets": round_money(intangibles),
            "total": round_money(total_non_current_assets)
        }
        current_liabilities_dict = {
            "trade_payables": round_money(trade_payables),
            "accounts_payable": round_money(trade_payables),
            "accruals_and_other": round_money(accruals_and_other),
            "accrued_expenses": round_money(accruals_and_other),
            "output_vat_payable": round_money(output_vat_payable),
            "net_vat_payable": round_money(output_vat_payable),
            "zakat_provision_payable": round_money(total_zakat_payable),
            "zakat_provision": round_money(total_zakat_payable),
            "total": round_money(total_current_liabilities)
        }
        non_current_liabilities_dict = {
            "long_term_loans": round_money(long_term_loans),
            "eos_provision": round_money(eos_provision),
            "total": round_money(total_non_current_liabilities)
        }

        return {
            "as_of_date": self.end_date.strftime("%Y-%m-%d"),
            "as_of_label_ar": self.as_of_label_ar,
            "current_assets": current_assets_dict,
            "non_current_assets": non_current_assets_dict,
            "assets": {
                "current_assets": current_assets_dict,
                "non_current_assets": non_current_assets_dict,
                "total_assets": round_money(total_assets),
            },
            "total_assets": round_money(total_assets),
            "current_liabilities": current_liabilities_dict,
            "non_current_liabilities": non_current_liabilities_dict,
            "liabilities": {
                "current_liabilities": current_liabilities_dict,
                "non_current_liabilities": non_current_liabilities_dict,
                "total_liabilities": round_money(total_liabilities),
            },
            "total_liabilities": round_money(total_liabilities),
            "equity": {
                "paid_up_capital": round_money(capital),
                "capital": round_money(capital),
                "statutory_reserve": round_money(statutory_reserve),
                "retained_earnings_opening": round_money(retained_earnings_opening),
                "retained_earnings_prior": round_money(retained_earnings_opening),
                "partners_current_account": round_money(partners_current),
                "current_period_net_profit": round_money(net_profit_dec),
                "current_year_net_profit": round_money(net_profit_dec),
                "total": round_money(total_equity)
            },
            "working_capital": round_money(working_capital),
            "total_liabilities_and_equity": round_money(total_liabilities_and_equity),
            "is_balanced": bool(is_balanced),
            "balance_difference": round_money(balance_difference)
        }

    # =========================================================================
    # 3. قائمة التدفقات النقدية (Statement of Cash Flows - IAS 7 Indirect Method)
    # =========================================================================
    def generate_cash_flow_statement(self, pnl: Dict[str, Any], bs: Dict[str, Any]) -> Dict[str, Any]:
        """توليد قائمة التدفقات النقدية بالطريقة غير المباشرة باستخدام فروق الحركة الفعلية (Closing - Opening)"""
        profit_before_zakat = pnl["profit_before_zakat"]
        depreciation = pnl["operating_expenses"]["depreciation"]
        eos_expense = pnl["operating_expenses"]["end_of_service"]

        ca = bs["current_assets"]
        cl = bs["current_liabilities"]
        nca = bs["non_current_assets"]
        ncl = bs["non_current_liabilities"]
        eq = bs["equity"]

        opening_cash = self._get_opening_balance(codes_prefix=["1101", "1102"])
        op_ar = self._get_opening_balance(codes_prefix=["1103"], exclude_prefixes=["110303"]) - self._get_opening_balance(codes_prefix=["110303"])
        op_inv = self._get_opening_balance(codes_prefix=["1104"])
        op_prep_vat = self._get_opening_balance(sub_types=["CURRENT_ASSET"], exclude_prefixes=["1101", "1102", "1103", "1104"])
        op_ap = self._get_opening_balance(codes_prefix=["2101"])
        op_accruals_vat = self._get_opening_balance(sub_types=["CURRENT_LIABILITY"], exclude_prefixes=["2101", "210205"])

        op_zakat_prov = self._get_opening_balance(codes_prefix=["210205"])
        cl_zakat_prov = self._get_balance(codes_prefix=["210205"])
        booked_zakat_exp = self._get_period_balance(codes_prefix=["5302"])
        zakat_cash_flow_effect = (cl_zakat_prov - op_zakat_prov) - booked_zakat_exp

        op_eos_prov = self._get_opening_balance(codes_prefix=["2202"])
        cl_eos_prov = ncl["eos_provision"]
        eos_cash_paid_effect = (cl_eos_prov - op_eos_prov) - eos_expense

        change_in_receivables = round_money(-(ca["net_trade_receivables"] - op_ar))
        change_in_inventory = round_money(-(ca["inventory"] - op_inv))
        change_in_prepayments_and_input_vat = round_money(-((ca["prepayments_and_other"] + ca["input_vat_recoverable"]) - op_prep_vat))
        change_in_payables = round_money(cl["trade_payables"] - op_ap)
        change_in_accruals_and_output_vat = round_money(
            (cl["accruals_and_other"] + cl["output_vat_payable"]) - op_accruals_vat +
            zakat_cash_flow_effect + eos_cash_paid_effect
        )

        operating_cash_flow = round_money(
            profit_before_zakat + depreciation + eos_expense +
            change_in_receivables + change_in_inventory +
            change_in_prepayments_and_input_vat + change_in_payables +
            change_in_accruals_and_output_vat
        )

        op_ppe_gross = self._get_opening_balance(codes_prefix=["1201"])
        op_accum_dep = self._get_opening_balance(codes_prefix=["1202"])
        op_intang = self._get_opening_balance(sub_types=["NON_CURRENT_ASSET"], exclude_prefixes=["1201", "1202"])
        accum_dep_unbooked_diff = (nca["accumulated_depreciation"] - op_accum_dep) - depreciation
        capex_ppe = round_money(-(nca["ppe_gross"] - op_ppe_gross) + accum_dep_unbooked_diff)
        capex_intangibles = round_money(-(nca["intangibles"] - op_intang))
        investing_cash_flow = round_money(capex_ppe + capex_intangibles)

        prior_unclosed_net = round_money(
            self._get_opening_balance(account_types=["REVENUE"]) - self._get_opening_balance(account_types=["EXPENSE"])
        )
        op_cap_res = round_money(self._get_opening_balance(codes_prefix=["3101", "3102", "3103"]) + prior_unclosed_net)
        op_partners = self._get_opening_balance(sub_types=["EQUITY"], exclude_prefixes=["3101", "3102", "3103"])
        op_loans = self._get_opening_balance(sub_types=["NON_CURRENT_LIABILITY"], exclude_prefixes=["2202"])

        capital_proceeds = round_money((eq["paid_up_capital"] + eq["statutory_reserve"] + eq["retained_earnings_opening"]) - op_cap_res)
        partners_net = round_money(eq["partners_current_account"] - op_partners)
        loans_net = round_money(ncl["long_term_loans"] - op_loans)
        financing_cash_flow = round_money(capital_proceeds + partners_net + loans_net)

        net_change_in_cash = round_money(operating_cash_flow + investing_cash_flow + financing_cash_flow)
        closing_cash_book = round_money(ca["cash_and_equivalents"])
        reconciled = abs((opening_cash + net_change_in_cash) - closing_cash_book) < 0.05

        return {
            "start_date": self.start_date.strftime("%Y-%m-%d"),
            "end_date": self.end_date.strftime("%Y-%m-%d"),
            "period_start": self.start_date.strftime("%Y-%m-%d"),
            "period_end": self.end_date.strftime("%Y-%m-%d"),
            "period_label_ar": self.period_label_ar,
            "operating_activities": {
                "profit_before_zakat": round_money(profit_before_zakat),
                "depreciation_add_back": round_money(depreciation + eos_expense),
                "eos_provision_add_back": round_money(eos_expense),
                "change_in_receivables": change_in_receivables,
                "change_in_inventory": change_in_inventory,
                "change_in_prepayments_and_input_vat": change_in_prepayments_and_input_vat,
                "change_in_payables": change_in_payables,
                "change_in_accruals_and_output_vat": change_in_accruals_and_output_vat,
                "working_capital_changes": {
                    "receivables_change": change_in_receivables,
                    "prepaid_and_other_change": change_in_prepayments_and_input_vat,
                    "inventory_change": change_in_inventory,
                    "payables_change": change_in_payables,
                    "accruals_and_vat_change": change_in_accruals_and_output_vat,
                },
                "net_cash_from_operating": operating_cash_flow
            },
            "investing_activities": {
                "purchase_of_ppe": capex_ppe,
                "purchase_of_intangibles": capex_intangibles,
                "net_cash_used_in_investing": investing_cash_flow,
                "net_cash_from_investing": investing_cash_flow,
            },
            "financing_activities": {
                "capital_and_reserves_proceeds": capital_proceeds,
                "partners_current_movement": partners_net,
                "long_term_loans_proceeds": loans_net,
                "net_cash_from_financing": financing_cash_flow
            },
            "opening_cash_balance": round_money(opening_cash),
            "net_change_in_cash": net_change_in_cash,
            "closing_cash_balance": closing_cash_book,
            "is_reconciled": bool(reconciled)
        }

    # =========================================================================
    # 4. إقرار ضريبة القيمة المضافة (ZATCA VAT Return Engine - Period Movement)
    # =========================================================================
    def generate_vat_return(self) -> Dict[str, Any]:
        """
        توليد نموذج إقرار ضريبة القيمة المضافة المعتمد لدى هيئة الزكاة والضريبة والجمارك (ZATCA)
        بالاعتماد الحصري على حركة الفترة [start_date, end_date] دون خلط أرصدة الفترات السابقة.
        """
        gross_sales = to_decimal(self._get_period_balance(sub_types=["OPERATING_REVENUE"], exclude_prefixes=["4102", "4103"]))
        sales_returns = to_decimal(self._get_period_balance(codes_prefix=["4102"]))
        sales_discounts = to_decimal(self._get_period_balance(codes_prefix=["4103"]))
        net_taxable_sales = max(Decimal("0.00"), quantize_money(gross_sales - sales_returns - sales_discounts))

        output_vat_turnover = self._get_turnover(["210204"])
        if self._has_period_columns:
            gross_output_vat = to_decimal(output_vat_turnover["period_credit"])
            sales_return_vat_adj = to_decimal(output_vat_turnover["period_debit"])
            net_output_vat = quantize_money(gross_output_vat - sales_return_vat_adj)
        else:
            gross_output_vat = to_decimal(output_vat_turnover["closing_credit"])
            sales_return_vat_adj = to_decimal(output_vat_turnover["closing_debit"])
            net_output_vat = to_decimal(self._get_balance(codes_prefix=["210204"]))

        input_vat_turnover = self._get_turnover(["110503"])
        if self._has_period_columns:
            gross_input_vat = to_decimal(input_vat_turnover["period_debit"])
            purchase_return_vat_adj = to_decimal(input_vat_turnover["period_credit"])
            net_input_vat = quantize_money(gross_input_vat - purchase_return_vat_adj)
        else:
            gross_input_vat = to_decimal(input_vat_turnover["closing_debit"])
            purchase_return_vat_adj = to_decimal(input_vat_turnover["closing_credit"])
            net_input_vat = to_decimal(self._get_balance(codes_prefix=["110503"]))

        vat_rate_dec = to_decimal(self.vat_rate)
        estimated_taxable_purchases = quantize_money(gross_input_vat / vat_rate_dec) if gross_input_vat > Decimal("0.00") else Decimal("0.00")
        estimated_purchase_returns = quantize_money(purchase_return_vat_adj / vat_rate_dec) if purchase_return_vat_adj > Decimal("0.00") else Decimal("0.00")
        net_taxable_purchases = max(Decimal("0.00"), quantize_money(estimated_taxable_purchases - estimated_purchase_returns))

        net_vat_payable = quantize_money(net_output_vat - net_input_vat)
        status = "مستحقة السداد للهيئة (Payable to ZATCA)" if net_vat_payable >= Decimal("0.00") else "رصيد دائن قابل للاسترداد (Refundable)"

        return {
            "start_date": self.start_date.strftime("%Y-%m-%d"),
            "end_date": self.end_date.strftime("%Y-%m-%d"),
            "period_start": self.start_date.strftime("%Y-%m-%d"),
            "period_end": self.end_date.strftime("%Y-%m-%d"),
            "period_label_ar": self.period_label_ar,
            "box_1_std_sales": {
                "label": "المبيعات الخاضعة للنسبة الأساسية (15%) - صافي حركة الفترة",
                "taxable_amount": round_money(net_taxable_sales),
                "vat_amount": round_money(net_output_vat),
            },
            "box_7_std_purchases": {
                "label": "المشتريات والمصروفات الخاضعة للنسبة الأساسية (15%) - صافي حركة الفترة",
                "taxable_amount": round_money(net_taxable_purchases),
                "recoverable_vat": round_money(net_input_vat),
            },
            "sales_section": {
                "standard_rated_sales_15": round_money(gross_sales - sales_discounts),
                "sales_returns_and_credit_notes": round_money(sales_returns),
                "net_taxable_sales": round_money(net_taxable_sales),
                "gross_output_vat": round_money(gross_output_vat),
                "output_vat_adjustments": round_money(sales_return_vat_adj),
                "total_output_vat": round_money(net_output_vat)
            },
            "purchases_section": {
                "standard_rated_purchases_15": round_money(estimated_taxable_purchases),
                "purchase_returns_and_debit_notes": round_money(estimated_purchase_returns),
                "net_taxable_purchases": round_money(net_taxable_purchases),
                "gross_input_vat": round_money(gross_input_vat),
                "input_vat_adjustments": round_money(purchase_return_vat_adj),
                "total_recoverable_input_vat": round_money(net_input_vat)
            },
            "net_vat_due": round_money(net_vat_payable),
            "settlement_status": status
        }

    # =========================================================================
    # 5. احتساب وعاء الزكاة الشرعي (ZATCA Zakat Calculation)
    # =========================================================================
    def calculate_zakat_base(self, book_profit: float) -> Dict[str, Any]:
        """احتساب وعاء الزكاة الشرعي طبقاً للائحة التنفيذية لجباية الزكاة (هيئة ZATCA)"""
        capital = to_decimal(self._get_balance(codes_prefix=["3101"]))
        reserves = to_decimal(self._get_balance(codes_prefix=["3102"]))
        prior_unclosed_net = quantize_money(
            to_decimal(self._get_opening_balance(account_types=["REVENUE"])) -
            to_decimal(self._get_opening_balance(account_types=["EXPENSE"]))
        )
        retained_earnings_opening = quantize_money(to_decimal(self._get_balance(codes_prefix=["3103"])) + prior_unclosed_net)
        long_term_debt = to_decimal(self._get_balance(sub_types=["NON_CURRENT_LIABILITY"], exclude_prefixes=["2202"]))
        eos_provision = to_decimal(self._get_balance(codes_prefix=["2202"]))
        partners_credit = max(Decimal("0.00"), to_decimal(self._get_balance(sub_types=["EQUITY"], exclude_prefixes=["3101", "3102", "3103"])))

        total_added_sources = quantize_money(
            capital + reserves + retained_earnings_opening +
            long_term_debt + eos_provision + partners_credit
        )

        ppe_gross = to_decimal(self._get_balance(codes_prefix=["1201"]))
        accum_dep = to_decimal(self._get_balance(codes_prefix=["1202"]))
        net_fixed_assets = max(Decimal("0.00"), quantize_money(ppe_gross - accum_dep))
        intangibles = to_decimal(self._get_balance(sub_types=["NON_CURRENT_ASSET"], exclude_prefixes=["1201", "1202"]))

        total_deductions = quantize_money(net_fixed_assets + intangibles)
        base_before_profit = quantize_money(total_added_sources - total_deductions)
        adjusted_profit = max(Decimal("0.00"), quantize_money(book_profit))
        zakat_base = max(Decimal("0.00"), quantize_money(base_before_profit + adjusted_profit))
        zakat_due = quantize_money(zakat_base * to_decimal(self.zakat_rate_gregorian))
        total_additions_with_profit = quantize_money(total_added_sources + adjusted_profit)

        return {
            "start_date": self.start_date.strftime("%Y-%m-%d"),
            "end_date": self.end_date.strftime("%Y-%m-%d"),
            "period_start": self.start_date.strftime("%Y-%m-%d"),
            "period_end": self.end_date.strftime("%Y-%m-%d"),
            "period_label_ar": self.period_label_ar,
            "sources_added": {
                "capital": round_money(capital),
                "reserves": round_money(reserves),
                "retained_earnings_opening": round_money(retained_earnings_opening),
                "long_term_debt": round_money(long_term_debt),
                "eos_provision": round_money(eos_provision),
                "partners_credit_balance": round_money(partners_credit),
                "total_added": round_money(total_added_sources)
            },
            "additions_to_zakat_base": {
                "capital": round_money(capital),
                "statutory_reserve": round_money(reserves),
                "retained_earnings": round_money(retained_earnings_opening),
                "adjusted_net_profit": round_money(adjusted_profit),
                "long_term_loans": round_money(long_term_debt),
                "eos_provision": round_money(eos_provision),
                "partners_credit_balance": round_money(partners_credit),
                "total_additions": round_money(total_additions_with_profit),
            },
            "deductions": {
                "net_fixed_assets": round_money(net_fixed_assets),
                "intangibles": round_money(intangibles),
                "total_deductions": round_money(total_deductions)
            },
            "deductions_from_zakat_base": {
                "net_fixed_assets": round_money(net_fixed_assets),
                "intangible_assets": round_money(intangibles),
                "total_deductions": round_money(total_deductions),
            },
            "base_before_profit": round_money(base_before_profit),
            "adjusted_net_profit": round_money(adjusted_profit),
            "zakat_base": round_money(zakat_base),
            "total_days": self.total_days,
            "applicable_zakat_rate_pct": round(self.zakat_rate_gregorian * 100, 4),
            "zakat_due": round_money(zakat_due)
        }

    # =========================================================================
    # 6. المؤشرات والنسب المالية (Financial Ratios)
    # =========================================================================
    def calculate_financial_ratios(self, pnl: Dict[str, Any], bs: Dict[str, Any]) -> Dict[str, Any]:
        """احتساب مؤشرات السيولة، الربحية، والرافعة المالية"""
        ca = bs["current_assets"]["total"]
        cl = bs["current_liabilities"]["total"]
        inv = bs["current_assets"]["inventory"]
        total_assets = bs["total_assets"]
        total_equity = bs["equity"]["total"]
        total_debt = bs["total_liabilities"]
        net_revenue = pnl["net_revenue"]
        net_profit = pnl["net_profit"]
        gross_profit = pnl["gross_profit"]
        op_profit = pnl["operating_profit"]

        current_ratio = round(ca / cl, 2) if cl > 0 else 0.0
        quick_ratio = round((ca - inv) / cl, 2) if cl > 0 else 0.0
        working_capital = round_money(ca - cl)

        gross_margin_pct = round((gross_profit / net_revenue) * 100, 2) if net_revenue > 0 else 0.0
        operating_margin_pct = round((op_profit / net_revenue) * 100, 2) if net_revenue > 0 else 0.0
        net_margin_pct = round((net_profit / net_revenue) * 100, 2) if net_revenue > 0 else 0.0
        roa_pct = round((net_profit / total_assets) * 100, 2) if total_assets > 0 else 0.0
        roe_pct = round((net_profit / total_equity) * 100, 2) if total_equity > 0 else 0.0

        debt_to_equity = round(total_debt / total_equity, 2) if total_equity > 0 else 0.0
        debt_to_assets = round(total_debt / total_assets, 2) if total_assets > 0 else 0.0
        debt_to_assets_pct = round((total_debt / total_assets) * 100, 2) if total_assets > 0 else 0.0

        return {
            "current_ratio": current_ratio,
            "quick_ratio": quick_ratio,
            "working_capital": working_capital,
            "gross_margin_pct": gross_margin_pct,
            "operating_margin_pct": operating_margin_pct,
            "net_margin_pct": net_margin_pct,
            "return_on_assets_pct": roa_pct,
            "return_on_equity_pct": roe_pct,
            "debt_to_equity_ratio": debt_to_equity,
            "debt_to_assets_ratio": debt_to_assets,
            "debt_to_assets_pct": debt_to_assets_pct,
            "liquidity": {
                "current_ratio": current_ratio,
                "quick_ratio": quick_ratio,
                "working_capital": working_capital
            },
            "profitability": {
                "gross_margin_pct": gross_margin_pct,
                "operating_margin_pct": operating_margin_pct,
                "net_margin_pct": net_margin_pct,
                "return_on_assets_pct": roa_pct,
                "return_on_equity_pct": roe_pct
            },
            "solvency": {
                "debt_to_equity_ratio": debt_to_equity,
                "debt_to_assets_ratio": debt_to_assets
            }
        }

    # =========================================================================
    # 7. محرك المراجعة والمطابقة الصارمة قبل الاعتماد الرسمي (Pre-Approval Audit)
    # =========================================================================
    def verify_pre_approval_reconciliation(
        self,
        pnl: Dict[str, Any],
        bs: Dict[str, Any],
        cf: Dict[str, Any],
        vat: Dict[str, Any],
        zakat: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        فحص ومطابقة الحسابات والقوائم المالية وضريبة القيمة المضافة والزكاة قبل الاعتماد الرسمي.
        تُعتبر المخرجات (مسودة قيد المراجعة - غير معتمدة) ما لم تجتز كافة الفحوصات الرياضية والمحاسبية بنسبة 100%.
        """
        checks: List[Dict[str, Any]] = []

        # 1. توازن ميزان المراجعة (الأرصدة الافتتاحية، حركة الفترة، الأرصدة الختامية)
        op_diff = round_money(abs(self.df["Opening Debit"].sum() - self.df["Opening Credit"].sum())) if not self.df.empty else 0.0
        pr_diff = round_money(abs(self.df["Period Debit"].sum() - self.df["Period Credit"].sum())) if not self.df.empty else 0.0
        cl_diff = round_money(abs(self.df["Closing Debit"].sum() - self.df["Closing Credit"].sum())) if not self.df.empty else 0.0
        tot_cl_debit = round_money(self.df["Closing Debit"].sum()) if not self.df.empty else 0.0
        tot_cl_credit = round_money(self.df["Closing Credit"].sum()) if not self.df.empty else 0.0
        tb_ok = (op_diff < 0.01 and pr_diff < 0.01 and cl_diff < 0.01)
        checks.append({
            "code": "CHK-01",
            "title": "توازن ميزان المراجعة (الافتتاحي، حركة الفترة، الختامي)",
            "check_name": "CHK-01: توازن ميزان المراجعة (الافتتاحي، حركة الفترة، الختامي)",
            "expected": tot_cl_debit,
            "actual": tot_cl_credit,
            "difference": round_money(op_diff + pr_diff + cl_diff),
            "actual_diff": round_money(op_diff + pr_diff + cl_diff),
            "passed": tb_ok
        })

        # 2. مطابقة معادلة قائمة الدخل للفترة
        expected_net_profit = round_money(
            to_decimal(pnl["net_revenue"]) - to_decimal(pnl["cost_of_sales"]) -
            to_decimal(pnl["operating_expenses"]["total"]) + to_decimal(pnl["other_income"]) -
            to_decimal(pnl["finance_costs"]) - to_decimal(pnl["zakat_expense"])
        )
        pnl_diff = round_money(abs(to_decimal(expected_net_profit) - to_decimal(pnl["net_profit"])))
        checks.append({
            "code": "CHK-02",
            "title": "سلامة معادلة قائمة الدخل وصافي ربح الفترة",
            "check_name": "CHK-02: سلامة معادلة قائمة الدخل وصافي ربح الفترة",
            "expected": expected_net_profit,
            "actual": pnl["net_profit"],
            "difference": pnl_diff,
            "actual_diff": pnl_diff,
            "passed": pnl_diff < 0.01
        })

        # 3. مطابقة معادلة الميزانية العمومية (الأصول = الالتزامات + حقوق الملكية)
        bs_diff = round_money(abs(to_decimal(bs["total_assets"]) - to_decimal(bs["total_liabilities_and_equity"])))
        checks.append({
            "code": "CHK-03",
            "title": "توازن قائمة المركز المالي (الأصول = الالتزامات + حقوق الملكية)",
            "check_name": "CHK-03: توازن قائمة المركز المالي (الأصول = الالتزامات + حقوق الملكية)",
            "expected": bs["total_assets"],
            "actual": bs["total_liabilities_and_equity"],
            "difference": bs_diff,
            "actual_diff": bs_diff,
            "passed": bool(bs["is_balanced"] and bs_diff < 0.01)
        })

        # 4. مطابقة قائمة التدفقات النقدية (IAS 7) مع رصيد النقدية بالمركز المالي
        expected_closing_cash = round_money(to_decimal(cf["opening_cash_balance"]) + to_decimal(cf["net_change_in_cash"]))
        cf_diff = round_money(abs(to_decimal(expected_closing_cash) - to_decimal(bs["current_assets"]["cash_and_equivalents"])))
        checks.append({
            "code": "CHK-04",
            "title": "مطابقة التدفقات النقدية (IAS 7) مع النقدية والبنوك بالمركز المالي",
            "check_name": "CHK-04: مطابقة التدفقات النقدية (IAS 7) مع النقدية والبنوك بالمركز المالي",
            "expected": bs["current_assets"]["cash_and_equivalents"],
            "actual": expected_closing_cash,
            "difference": cf_diff,
            "actual_diff": cf_diff,
            "passed": bool(cf["is_reconciled"] and cf_diff < 0.05)
        })

        # 5. مطابقة إقرار ضريبة القيمة المضافة للفترة (المربع 14 = ضريبة المخرجات - ضريبة المدخلات)
        expected_vat_due = round_money(
            to_decimal(vat["sales_section"]["total_output_vat"]) -
            to_decimal(vat["purchases_section"]["total_recoverable_input_vat"])
        )
        vat_diff = round_money(abs(to_decimal(expected_vat_due) - to_decimal(vat["net_vat_due"])))
        checks.append({
            "code": "CHK-05",
            "title": "مطابقة إقرار ضريبة القيمة المضافة (ZATCA VAT Return) لحركة الفترة",
            "check_name": "CHK-05: مطابقة إقرار ضريبة القيمة المضافة (ZATCA VAT Return) لحركة الفترة",
            "expected": expected_vat_due,
            "actual": vat["net_vat_due"],
            "difference": vat_diff,
            "actual_diff": vat_diff,
            "passed": vat_diff < 0.01
        })

        # 6. مطابقة وعاء الزكاة الشرعي ومقدار الزكاة المستحقة (2.5%)
        expected_zakat_base = round_money(max(
            Decimal("0.00"),
            to_decimal(zakat["sources_added"]["total_added"]) -
            to_decimal(zakat["deductions"]["total_deductions"]) +
            to_decimal(zakat["adjusted_net_profit"])
        ))
        expected_zakat_due = round_money(to_decimal(expected_zakat_base) * to_decimal(self.zakat_rate_gregorian))
        zakat_diff = round_money(
            abs(to_decimal(expected_zakat_base) - to_decimal(zakat["zakat_base"])) +
            abs(to_decimal(expected_zakat_due) - to_decimal(zakat["zakat_due"]))
        )
        checks.append({
            "code": "CHK-06",
            "title": "مطابقة وعاء الزكاة الشرعي واحتساب النسبة النظامية (ZATCA Zakat)",
            "check_name": "CHK-06: مطابقة وعاء الزكاة الشرعي واحتساب النسبة النظامية (ZATCA Zakat)",
            "expected": expected_zakat_due,
            "actual": zakat["zakat_due"],
            "difference": zakat_diff,
            "actual_diff": zakat_diff,
            "passed": zakat_diff < 0.01
        })

        all_passed = all(c["passed"] for c in checks)
        return {
            "is_approved_ready": all_passed,
            "document_status_ar": (
                "مسودة مفحوصة ومطابقة رياضيًا — جاهزة للاعتماد الرسمي ✅"
                if all_passed else
                "مسودة قيد المراجعة — غير معتمدة لوجود فروقات تحتاج للمعالجة ⚠️"
            ),
            "checks": checks,
            "passed_count": sum(1 for c in checks if c["passed"]),
            "total_checks": len(checks)
        }

    # =========================================================================
    # 8. التقرير المالي الشامل المجمع (Master Financial Package)
    # =========================================================================
    def generate_full_financial_report(self) -> Dict[str, Any]:
        """توليد حزمة التقارير المالية والضريبية والزكوية المتكاملة مع تقرير فحص المطابقة قبل الاعتماد"""
        pnl = self.generate_income_statement()
        bs = self.generate_balance_sheet(
            net_profit_period=pnl["net_profit"],
            estimated_zakat=pnl["zakat_expense"]
        )
        cash_flow = self.generate_cash_flow_statement(pnl=pnl, bs=bs)
        vat_return = self.generate_vat_return()
        zakat = self.calculate_zakat_base(book_profit=pnl["profit_before_zakat"])
        ratios = self.calculate_financial_ratios(pnl=pnl, bs=bs)
        pre_approval_audit = self.verify_pre_approval_reconciliation(
            pnl=pnl, bs=bs, cf=cash_flow, vat=vat_return, zakat=zakat
        )

        return {
            "fiscal_year": self.fiscal_year,
            "start_date": self.start_date.strftime("%Y-%m-%d"),
            "end_date": self.end_date.strftime("%Y-%m-%d"),
            "period_start": self.start_date.strftime("%Y-%m-%d"),
            "period_end": self.end_date.strftime("%Y-%m-%d"),
            "period_label_ar": self.period_label_ar,
            "as_of_label_ar": self.as_of_label_ar,
            "income_statement": pnl,
            "balance_sheet": bs,
            "cash_flow_statement": cash_flow,
            "vat_return": vat_return,
            "zakat_declaration": zakat,
            "financial_ratios": ratios,
            "pre_approval_audit": pre_approval_audit
        }


class ExportService:
    """خدمة تصدير حزمة القوائم المالية والزكاة والضريبة إلى ملف Excel متعدد الأوراق"""

    @staticmethod
    def generate_excel_workbook(
        trial_balance_df: pd.DataFrame,
        report: Dict[str, Any],
        company_name: str = "شركة ميزان برو التجارية"
    ) -> bytes:
        import io
        output = io.BytesIO()
        pnl = report["income_statement"]
        bs = report["balance_sheet"]
        cf = report["cash_flow_statement"]
        vat = report["vat_return"]
        zakat = report["zakat_declaration"]
        audit = report.get("pre_approval_audit", {})

        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            trial_balance_df.to_excel(writer, sheet_name="ميزان المراجعة", index=False)

            pnl_df = pd.DataFrame([
                {"البند": f"الفترة المالية ({pnl.get('period_label_ar', '')})", "المبلغ (ريال)": 0.0},
                {"البند": "إجمالي المبيعات والإيرادات (حركة الفترة)", "المبلغ (ريال)": pnl["gross_sales"]},
                {"البند": "مردودات المبيعات والخصم المسموح به", "المبلغ (ريال)": -(pnl["sales_returns"] + pnl["sales_discounts"])},
                {"البند": "صافي الإيرادات التشغيلية", "المبلغ (ريال)": pnl["net_revenue"]},
                {"البند": "تكلفة البضاعة المباعة (COGS)", "المبلغ (ريال)": -pnl["cost_of_sales"]},
                {"البند": "مجمل الربح", "المبلغ (ريال)": pnl["gross_profit"]},
                {"البند": "إجمالي المصروفات التشغيلية والإدارية", "المبلغ (ريال)": -pnl["operating_expenses"]["total"]},
                {"البند": "الربح التشغيلي (EBIT)", "المبلغ (ريال)": pnl["operating_profit"]},
                {"البند": "الإيرادات الأخرى ناقصاً تكاليف التمويل", "المبلغ (ريال)": pnl["other_income"] - pnl["finance_costs"]},
                {"البند": "صافي الربح قبل الزكاة", "المبلغ (ريال)": pnl["profit_before_zakat"]},
                {"البند": "مخصص الزكاة الشرعية", "المبلغ (ريال)": -pnl["zakat_expense"]},
                {"البند": "صافي ربح الفترة", "المبلغ (ريال)": pnl["net_profit"]},
            ])
            pnl_df.to_excel(writer, sheet_name="قائمة الدخل", index=False)

            bs_df = pd.DataFrame([
                {"القسم": "الأصول المتداولة", "البند": "النقدية والبنوك", "المبلغ (ريال)": bs["current_assets"]["cash_and_equivalents"]},
                {"القسم": "الأصول المتداولة", "البند": "صافي الذمم المدينة التجارية", "المبلغ (ريال)": bs["current_assets"]["net_trade_receivables"]},
                {"القسم": "الأصول المتداولة", "البند": "المخزون السلعي (WAC)", "المبلغ (ريال)": bs["current_assets"]["inventory"]},
                {"القسم": "الأصول المتداولة", "البند": "مصروفات مدفوعة مقدماً وضريبة مدخلات", "المبلغ (ريال)": bs["current_assets"]["prepaid_and_other"]},
                {"القسم": "الأصول المتداولة", "البند": "إجمالي الأصول المتداولة", "المبلغ (ريال)": bs["current_assets"]["total"]},
                {"القسم": "الأصول غير المتداولة", "البند": "صافي الأصول غير المتداولة", "المبلغ (ريال)": bs["non_current_assets"]["total"]},
                {"القسم": "إجمالي الأصول", "البند": "إجمالي الأصول", "المبلغ (ريال)": bs["total_assets"]},
                {"القسم": "الالتزامات المتداولة", "البند": "إجمالي الالتزامات المتداولة", "المبلغ (ريال)": bs["current_liabilities"]["total"]},
                {"القسم": "الالتزامات غير المتداولة", "البند": "إجمالي الالتزامات غير المتداولة", "المبلغ (ريال)": bs["non_current_liabilities"]["total"]},
                {"القسم": "حقوق الملكية", "البند": "إجمالي حقوق الملكية", "المبلغ (ريال)": bs["equity"]["total"]},
                {"القسم": "الإجمالي", "البند": "إجمالي الالتزامات وحقوق الملكية", "المبلغ (ريال)": bs["total_liabilities_and_equity"]},
            ])
            bs_df.to_excel(writer, sheet_name="المركز المالي", index=False)

            cf_df = pd.DataFrame([
                {"البيان": "صافي النقد من الأنشطة التشغيلية", "المبلغ (ريال)": cf["operating_activities"]["net_cash_from_operating"]},
                {"البيان": "صافي النقد من الأنشطة الاستثمارية", "المبلغ (ريال)": cf["investing_activities"]["net_cash_used_in_investing"]},
                {"البيان": "صافي النقد من الأنشطة التمويلية", "المبلغ (ريال)": cf["financing_activities"]["net_cash_from_financing"]},
                {"البيان": "صافي التغير في النقدية", "المبلغ (ريال)": cf["net_change_in_cash"]},
                {"البيان": "رصيد النقدية أول الفترة", "المبلغ (ريال)": cf["opening_cash_balance"]},
                {"البيان": "رصيد النقدية آخر الفترة", "المبلغ (ريال)": cf["closing_cash_balance"]},
            ])
            cf_df.to_excel(writer, sheet_name="التدفقات النقدية", index=False)

            vat_df = pd.DataFrame([
                {"البيان": vat["box_1_std_sales"]["label"], "المبلغ الخاضع": vat["box_1_std_sales"]["taxable_amount"], "الضريبة": vat["box_1_std_sales"]["vat_amount"]},
                {"البيان": vat["box_7_std_purchases"]["label"], "المبلغ الخاضع": vat["box_7_std_purchases"]["taxable_amount"], "الضريبة": -vat["box_7_std_purchases"]["recoverable_vat"]},
                {"البيان": "صافي ضريبة القيمة المضافة عن الفترة", "المبلغ الخاضع": 0.0, "الضريبة": vat["net_vat_due"]},
            ])
            vat_df.to_excel(writer, sheet_name="إقرار الضريبة VAT", index=False)

            zakat_df = pd.DataFrame([
                {"البيان": "إجمالي الإضافات للوعاء الزكوي", "المبلغ (ريال)": zakat["additions_to_zakat_base"]["total_additions"]},
                {"البيان": "إجمالي الحسميات من الوعاء الزكوي", "المبلغ (ريال)": -zakat["deductions_from_zakat_base"]["total_deductions"]},
                {"البيان": "وعاء الزكاة الشرعي", "المبلغ (ريال)": zakat["zakat_base"]},
                {"البيان": "مقدار الزكاة الشرعية المستحقة", "المبلغ (ريال)": zakat["zakat_due"]},
            ])
            zakat_df.to_excel(writer, sheet_name="إقرار الزكاة", index=False)

            if audit and audit.get("checks"):
                audit_df = pd.DataFrame(audit["checks"])
                audit_df.to_excel(writer, sheet_name="فحص المطابقة والاعتماد", index=False)

        output.seek(0)
        return output.getvalue()