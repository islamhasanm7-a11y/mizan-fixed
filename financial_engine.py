"""
MizanPro - Financial Statements, Cash Flow, VAT Return & ZATCA Zakat Compliance Engine
النظام المالي المتكامل - ميزان برو
محرك إعداد القوائم المالية الشاملة والتدفقات النقدية وإقرار ضريبة القيمة المضافة ووعاء الزكاة الشرعي
"""

from typing import Dict, Any
import pandas as pd


class FinancialStatementsEngine:
    """محرك القوائم المالية والتدفقات النقدية والامتثال الزكوي والضريبي (IFRS / SOCPA / ZATCA)"""

    def __init__(self, trial_balance_df: pd.DataFrame, fiscal_year: int = 2026, total_days: int = 365, vat_rate: float = 0.15):
        """
        تهيئة المحرك بجدول ميزان المراجعة المولد من LedgerService
        """
        self.raw_tb = trial_balance_df.copy()
        self.fiscal_year = fiscal_year
        self.total_days = total_days
        self.vat_rate = vat_rate if vat_rate > 0 else 0.15

        # النسبة الزكوية المعتمدة للسنة الميلادية (2.5% * 365 / 354)
        self.zakat_rate_gregorian = 0.025 * (self.total_days / 354.0)

        self._prepare_data()

    def _prepare_data(self):
        """تنظيف وتصنيف الحسابات واستخراج الأرصدة الختامية والافتتاحية"""
        if self.raw_tb.empty:
            self.df = pd.DataFrame(columns=[
                "Account Code", "Account Name", "Account Type",
                "Account SubType", "Natural Balance", "Opening Debit", "Opening Credit",
                "Period Debit", "Period Credit", "Closing Debit", "Closing Credit", "Net Balance"
            ])
            return

        self.df = self.raw_tb.copy()
        self.df["Account Code"] = self.df["Account Code"].astype(str)

        for col in ["Opening Debit", "Opening Credit", "Period Debit", "Period Credit", "Closing Debit", "Closing Credit", "Net Balance"]:
            if col not in self.df.columns:
                self.df[col] = 0.0

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
        """دالة مساعدة لحساب مجموع الأرصدة الختامية لقسم أو مجموعة حسابات محددة طبقاً لطبيعتها"""
        filtered = self._filter_df(sub_types, account_types, codes_prefix, exclude_prefixes)
        if filtered.empty:
            return 0.0

        total = 0.0
        for _, row in filtered.iterrows():
            nat_bal = row.get("Natural Balance", "DEBIT")
            c_deb = float(row.get("Closing Debit", 0.0))
            c_crd = float(row.get("Closing Credit", 0.0))

            if nat_bal == "DEBIT":
                total += (c_deb - c_crd)
            else:
                total += (c_crd - c_deb)

        return float(total)

    def _get_opening_balance(self, sub_types=None, account_types=None, codes_prefix=None, exclude_prefixes=None) -> float:
        """حساب مجموع الأرصدة الافتتاحية (أول المدة) لدعم التدفقات النقدية الدقيقة"""
        filtered = self._filter_df(sub_types, account_types, codes_prefix, exclude_prefixes)
        if filtered.empty:
            return 0.0

        total = 0.0
        for _, row in filtered.iterrows():
            nat_bal = row.get("Natural Balance", "DEBIT")
            o_deb = float(row.get("Opening Debit", 0.0))
            o_crd = float(row.get("Opening Credit", 0.0))

            if nat_bal == "DEBIT":
                total += (o_deb - o_crd)
            else:
                total += (o_crd - o_deb)

        return float(total)

    def _get_turnover(self, codes_prefix) -> Dict[str, float]:
        """استخراج إجمالي حركة المدين والدائن خلال الفترة لحسابات محددة (لإقرار الضريبة والتدفقات)"""
        if self.df.empty:
            return {"period_debit": 0.0, "period_credit": 0.0, "closing_debit": 0.0, "closing_credit": 0.0}

        prefixes = tuple(str(p) for p in codes_prefix) if isinstance(codes_prefix, list) else (str(codes_prefix),)
        filtered = self.df[self.df["Account Code"].str.startswith(prefixes)]

        return {
            "period_debit": float(filtered["Period Debit"].sum()),
            "period_credit": float(filtered["Period Credit"].sum()),
            "closing_debit": float(filtered["Closing Debit"].sum()),
            "closing_credit": float(filtered["Closing Credit"].sum()),
        }

    # =========================================================================
    # 1. قائمة الدخل الشامل (Statement of Profit or Loss)
    # =========================================================================
    def generate_income_statement(self) -> Dict[str, Any]:
        """توليد قائمة الدخل الشامل مع التضمين الديناميكي لأي حسابات فرعية مضافة في الشجرة"""
        sales_returns = self._get_balance(codes_prefix=["4102"])
        sales_discounts = self._get_balance(codes_prefix=["4103"])
        gross_sales = self._get_balance(
            sub_types=["OPERATING_REVENUE"],
            exclude_prefixes=["4102", "4103"]
        )
        net_revenue = gross_sales - sales_returns - sales_discounts

        # تكلفة المبيعات (شاملة أي حساب فرعي مضاف تحت 51)
        purchase_returns = self._get_balance(codes_prefix=["5103"])
        purchase_discounts = self._get_balance(codes_prefix=["5104"])
        inventory_shrinkage = self._get_balance(codes_prefix=["5105"])
        direct_cogs = self._get_balance(
            sub_types=["COST_OF_SALES"],
            exclude_prefixes=["5103", "5104", "5105"]
        )
        cogs = direct_cogs - purchase_returns - purchase_discounts + inventory_shrinkage

        gross_profit = net_revenue - cogs

        # المصاريف التشغيلية
        salaries = self._get_balance(codes_prefix=["5201"])
        rent = self._get_balance(codes_prefix=["5202"])
        utilities = self._get_balance(codes_prefix=["5203"])
        maintenance = self._get_balance(codes_prefix=["5204"])
        marketing = self._get_balance(codes_prefix=["5205"])
        gov_fees = self._get_balance(codes_prefix=["5206"])
        depreciation = self._get_balance(codes_prefix=["5207"])
        eos_expense = self._get_balance(codes_prefix=["5208"])
        other_admin = self._get_balance(
            sub_types=["OPERATING_EXPENSE", "OTHER_EXPENSE"],
            exclude_prefixes=["5201", "5202", "5203", "5204", "5205", "5206", "5207", "5208"]
        )

        total_operating_expenses = (
            salaries + rent + utilities + maintenance + marketing +
            gov_fees + depreciation + eos_expense + other_admin
        )

        operating_profit = gross_profit - total_operating_expenses

        other_income = self._get_balance(sub_types=["OTHER_INCOME"])
        finance_costs = self._get_balance(sub_types=["FINANCIAL_EXPENSE"], exclude_prefixes=["5302"])

        profit_before_zakat = operating_profit + other_income - finance_costs

        booked_zakat_expense = self._get_balance(codes_prefix=["5302"])
        zakat_data = self.calculate_zakat_base(profit_before_zakat)
        # إذا تم تسجيل قيد مصروف الزكاة الفعلي في الدفاتر (5302) نعتمد عليه، وإلا نستخدم الزكاة التقديرية المحسوبة
        zakat_expense = booked_zakat_expense if abs(booked_zakat_expense) > 0.001 else zakat_data["zakat_due"]

        net_profit_after_zakat = profit_before_zakat - zakat_expense

        return {
            "gross_sales": round(gross_sales, 2),
            "sales_returns": round(sales_returns, 2),
            "sales_discounts": round(sales_discounts, 2),
            "net_revenue": round(net_revenue, 2),
            "cost_of_sales_breakdown": {
                "direct_cogs": round(direct_cogs, 2),
                "purchase_returns": round(purchase_returns, 2),
                "purchase_discounts": round(purchase_discounts, 2),
                "inventory_adjustments": round(inventory_shrinkage, 2),
            },
            "cost_of_sales": round(cogs, 2),
            "gross_profit": round(gross_profit, 2),
            "operating_expenses": {
                "salaries": round(salaries, 2),
                "rent": round(rent, 2),
                "utilities": round(utilities, 2),
                "maintenance": round(maintenance, 2),
                "marketing": round(marketing, 2),
                "government_fees": round(gov_fees, 2),
                "depreciation": round(depreciation, 2),
                "end_of_service": round(eos_expense, 2),
                "other_admin": round(other_admin, 2),
                "total": round(total_operating_expenses, 2),
            },
            "operating_profit": round(operating_profit, 2),
            "other_income": round(other_income, 2),
            "finance_costs": round(finance_costs, 2),
            "profit_before_zakat": round(profit_before_zakat, 2),
            "zakat_expense": round(zakat_expense, 2),
            "net_profit": round(net_profit_after_zakat, 2)
        }

    # =========================================================================
    # 2. قائمة المركز المالي (Statement of Financial Position)
    # =========================================================================
    def generate_balance_sheet(self, net_profit_period: float, estimated_zakat: float = 0.0) -> Dict[str, Any]:
        """توليد قائمة المركز المالي مع إدراج صافي ربح الفترة وأي حسابات فرعية مضافة"""
        cash_and_equivalents = self._get_balance(codes_prefix=["1101", "1102"])
        ecl_allowance = self._get_balance(codes_prefix=["110303"])
        trade_receivables_gross = self._get_balance(codes_prefix=["1103"], exclude_prefixes=["110303"])
        net_trade_receivables = trade_receivables_gross - ecl_allowance

        inventory = self._get_balance(codes_prefix=["1104"])
        input_vat_recoverable = self._get_balance(codes_prefix=["110503"])
        prepayments_and_other = self._get_balance(
            sub_types=["CURRENT_ASSET"],
            exclude_prefixes=["1101", "1102", "1103", "1104", "110503"]
        )

        total_current_assets = (
            cash_and_equivalents + net_trade_receivables +
            inventory + prepayments_and_other + input_vat_recoverable
        )

        ppe_gross = self._get_balance(codes_prefix=["1201"])
        accum_depreciation = self._get_balance(codes_prefix=["1202"])
        net_ppe = ppe_gross - accum_depreciation
        intangibles = self._get_balance(
            sub_types=["NON_CURRENT_ASSET"],
            exclude_prefixes=["1201", "1202"]
        )

        total_non_current_assets = net_ppe + intangibles
        total_assets = total_current_assets + total_non_current_assets

        trade_payables = self._get_balance(codes_prefix=["2101"])
        output_vat_payable = self._get_balance(codes_prefix=["210204"])
        book_zakat_provision = self._get_balance(codes_prefix=["210205"])
        booked_zakat_expense = self._get_balance(codes_prefix=["5302"])
        # إذا لم يُسجل قيد زكاة في الدفاتر (5302 == 0)، يُدرج المخصص التقديري المقابل لمصروف الزكاة التقديري في قائمة الدخل
        unbooked_zakat_accrual = max(0.0, estimated_zakat - booked_zakat_expense) if abs(booked_zakat_expense) < 0.001 else 0.0
        total_zakat_payable = book_zakat_provision + unbooked_zakat_accrual

        accruals_and_other = self._get_balance(
            sub_types=["CURRENT_LIABILITY"],
            exclude_prefixes=["2101", "210204", "210205"]
        )

        total_current_liabilities = (
            trade_payables + accruals_and_other +
            output_vat_payable + total_zakat_payable
        )

        eos_provision = self._get_balance(codes_prefix=["2202"])
        long_term_loans = self._get_balance(
            sub_types=["NON_CURRENT_LIABILITY"],
            exclude_prefixes=["2202"]
        )

        total_non_current_liabilities = long_term_loans + eos_provision
        total_liabilities = total_current_liabilities + total_non_current_liabilities

        capital = self._get_balance(codes_prefix=["3101"])
        statutory_reserve = self._get_balance(codes_prefix=["3102"])
        retained_earnings_opening = self._get_balance(codes_prefix=["3103"])
        partners_current = self._get_balance(
            sub_types=["EQUITY"],
            exclude_prefixes=["3101", "3102", "3103"]
        )

        total_equity = (
            capital + statutory_reserve + retained_earnings_opening +
            partners_current + net_profit_period
        )

        total_liabilities_and_equity = total_liabilities + total_equity
        balance_difference = abs(total_assets - total_liabilities_and_equity)
        is_balanced = balance_difference < 0.01

        return {
            "current_assets": {
                "cash_and_equivalents": round(cash_and_equivalents, 2),
                "trade_receivables_gross": round(trade_receivables_gross, 2),
                "ecl_allowance": round(ecl_allowance, 2),
                "net_trade_receivables": round(net_trade_receivables, 2),
                "inventory": round(inventory, 2),
                "prepayments_and_other": round(prepayments_and_other, 2),
                "input_vat_recoverable": round(input_vat_recoverable, 2),
                "total": round(total_current_assets, 2)
            },
            "non_current_assets": {
                "ppe_gross": round(ppe_gross, 2),
                "accumulated_depreciation": round(accum_depreciation, 2),
                "net_ppe": round(net_ppe, 2),
                "intangibles": round(intangibles, 2),
                "total": round(total_non_current_assets, 2)
            },
            "total_assets": round(total_assets, 2),
            "current_liabilities": {
                "trade_payables": round(trade_payables, 2),
                "accruals_and_other": round(accruals_and_other, 2),
                "output_vat_payable": round(output_vat_payable, 2),
                "zakat_provision_payable": round(total_zakat_payable, 2),
                "total": round(total_current_liabilities, 2)
            },
            "non_current_liabilities": {
                "long_term_loans": round(long_term_loans, 2),
                "eos_provision": round(eos_provision, 2),
                "total": round(total_non_current_liabilities, 2)
            },
            "total_liabilities": round(total_liabilities, 2),
            "equity": {
                "paid_up_capital": round(capital, 2),
                "statutory_reserve": round(statutory_reserve, 2),
                "retained_earnings_opening": round(retained_earnings_opening, 2),
                "partners_current_account": round(partners_current, 2),
                "current_period_net_profit": round(net_profit_period, 2),
                "total": round(total_equity, 2)
            },
            "total_liabilities_and_equity": round(total_liabilities_and_equity, 2),
            "is_balanced": is_balanced,
            "balance_difference": round(balance_difference, 2)
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

        # حركة مخصص الزكاة الفعلي والمسدد ومخصص نهاية الخدمة الفعلي والمسدد (IAS 7)
        op_zakat_prov = self._get_opening_balance(codes_prefix=["210205"])
        cl_zakat_prov = self._get_balance(codes_prefix=["210205"])
        booked_zakat_exp = self._get_balance(codes_prefix=["5302"])
        zakat_cash_flow_effect = (cl_zakat_prov - op_zakat_prov) - booked_zakat_exp

        op_eos_prov = self._get_opening_balance(codes_prefix=["2202"])
        cl_eos_prov = ncl["eos_provision"]
        eos_cash_paid_effect = (cl_eos_prov - op_eos_prov) - eos_expense

        change_in_receivables = -(ca["net_trade_receivables"] - op_ar)
        change_in_inventory = -(ca["inventory"] - op_inv)
        change_in_prepayments_and_input_vat = -((ca["prepayments_and_other"] + ca["input_vat_recoverable"]) - op_prep_vat)
        change_in_payables = cl["trade_payables"] - op_ap
        change_in_accruals_and_output_vat = (
            (cl["accruals_and_other"] + cl["output_vat_payable"]) - op_accruals_vat +
            zakat_cash_flow_effect + eos_cash_paid_effect
        )

        operating_cash_flow = (
            profit_before_zakat + depreciation + eos_expense +
            change_in_receivables + change_in_inventory +
            change_in_prepayments_and_input_vat + change_in_payables +
            change_in_accruals_and_output_vat
        )

        op_ppe_gross = self._get_opening_balance(codes_prefix=["1201"])
        op_accum_dep = self._get_opening_balance(codes_prefix=["1202"])
        op_intang = self._get_opening_balance(sub_types=["NON_CURRENT_ASSET"], exclude_prefixes=["1201", "1202"])
        # تضمين أي تغير في مجمع الإهلاك لا يقابله مصروف إهلاك الفترة (مثل رصيد افتتاحي لمجمع الإهلاك)
        accum_dep_unbooked_diff = (nca["accumulated_depreciation"] - op_accum_dep) - depreciation
        capex_ppe = -(nca["ppe_gross"] - op_ppe_gross) + accum_dep_unbooked_diff
        capex_intangibles = -(nca["intangibles"] - op_intang)
        investing_cash_flow = capex_ppe + capex_intangibles

        op_cap_res = self._get_opening_balance(codes_prefix=["3101", "3102", "3103"])
        op_partners = self._get_opening_balance(sub_types=["EQUITY"], exclude_prefixes=["3101", "3102", "3103"])
        op_loans = self._get_opening_balance(sub_types=["NON_CURRENT_LIABILITY"], exclude_prefixes=["2202"])

        capital_proceeds = (eq["paid_up_capital"] + eq["statutory_reserve"] + eq["retained_earnings_opening"]) - op_cap_res
        partners_net = eq["partners_current_account"] - op_partners
        loans_net = ncl["long_term_loans"] - op_loans
        financing_cash_flow = capital_proceeds + partners_net + loans_net

        net_change_in_cash = operating_cash_flow + investing_cash_flow + financing_cash_flow
        closing_cash_book = ca["cash_and_equivalents"]
        reconciled = abs((opening_cash + net_change_in_cash) - closing_cash_book) < 0.05

        return {
            "operating_activities": {
                "profit_before_zakat": round(profit_before_zakat, 2),
                "depreciation_add_back": round(depreciation, 2),
                "eos_provision_add_back": round(eos_expense, 2),
                "change_in_receivables": round(change_in_receivables, 2),
                "change_in_inventory": round(change_in_inventory, 2),
                "change_in_prepayments_and_input_vat": round(change_in_prepayments_and_input_vat, 2),
                "change_in_payables": round(change_in_payables, 2),
                "change_in_accruals_and_output_vat": round(change_in_accruals_and_output_vat, 2),
                "net_cash_from_operating": round(operating_cash_flow, 2)
            },
            "investing_activities": {
                "purchase_of_ppe": round(capex_ppe, 2),
                "purchase_of_intangibles": round(capex_intangibles, 2),
                "net_cash_used_in_investing": round(investing_cash_flow, 2)
            },
            "financing_activities": {
                "capital_and_reserves_proceeds": round(capital_proceeds, 2),
                "partners_current_movement": round(partners_net, 2),
                "long_term_loans_proceeds": round(loans_net, 2),
                "net_cash_from_financing": round(financing_cash_flow, 2)
            },
            "opening_cash_balance": round(opening_cash, 2),
            "net_change_in_cash": round(net_change_in_cash, 2),
            "closing_cash_balance": round(closing_cash_book, 2),
            "is_reconciled": reconciled
        }

    # =========================================================================
    # 4. إقرار ضريبة القيمة المضافة (ZATCA VAT Return Engine)
    # =========================================================================
    def generate_vat_return(self) -> Dict[str, Any]:
        """
        توليد نموذج إقرار ضريبة القيمة المضافة المعتمد لدى هيئة الزكاة والضريبة والجمارك (ZATCA)
        """
        gross_sales = self._get_balance(sub_types=["OPERATING_REVENUE"], exclude_prefixes=["4102", "4103"])
        sales_returns = self._get_balance(codes_prefix=["4102"])
        sales_discounts = self._get_balance(codes_prefix=["4103"])
        net_taxable_sales = max(0.0, gross_sales - sales_returns - sales_discounts)

        output_vat_turnover = self._get_turnover(["210204"])
        gross_output_vat = output_vat_turnover["period_credit"]
        sales_return_vat_adj = output_vat_turnover["period_debit"]
        net_output_vat = self._get_balance(codes_prefix=["210204"])

        input_vat_turnover = self._get_turnover(["110503"])
        gross_input_vat = input_vat_turnover["period_debit"]
        purchase_return_vat_adj = input_vat_turnover["period_credit"]
        net_input_vat = self._get_balance(codes_prefix=["110503"])

        estimated_taxable_purchases = round(gross_input_vat / self.vat_rate, 2) if gross_input_vat > 0 else 0.0
        estimated_purchase_returns = round(purchase_return_vat_adj / self.vat_rate, 2) if purchase_return_vat_adj > 0 else 0.0
        net_taxable_purchases = max(0.0, estimated_taxable_purchases - estimated_purchase_returns)

        net_vat_payable = round(net_output_vat - net_input_vat, 2)
        status = "مستحقة السداد للهيئة (Payable to ZATCA)" if net_vat_payable >= 0 else "رصيد دائن قابل للاسترداد (Refundable)"

        return {
            "sales_section": {
                "standard_rated_sales_15": round(gross_sales - sales_discounts, 2),
                "sales_returns_and_credit_notes": round(sales_returns, 2),
                "net_taxable_sales": round(net_taxable_sales, 2),
                "gross_output_vat": round(gross_output_vat, 2),
                "output_vat_adjustments": round(sales_return_vat_adj, 2),
                "total_output_vat": round(net_output_vat, 2)
            },
            "purchases_section": {
                "standard_rated_purchases_15": round(estimated_taxable_purchases, 2),
                "purchase_returns_and_debit_notes": round(estimated_purchase_returns, 2),
                "net_taxable_purchases": round(net_taxable_purchases, 2),
                "gross_input_vat": round(gross_input_vat, 2),
                "input_vat_adjustments": round(purchase_return_vat_adj, 2),
                "total_recoverable_input_vat": round(net_input_vat, 2)
            },
            "net_vat_due": net_vat_payable,
            "settlement_status": status
        }

    # =========================================================================
    # 5. احتساب وعاء الزكاة الشرعي (ZATCA Zakat Calculation)
    # =========================================================================
    def calculate_zakat_base(self, book_profit: float) -> Dict[str, Any]:
        """احتساب وعاء الزكاة الشرعي طبقاً للائحة التنفيذية لجباية الزكاة (هيئة ZATCA)"""
        capital = self._get_balance(codes_prefix=["3101"])
        reserves = self._get_balance(codes_prefix=["3102"])
        retained_earnings_opening = self._get_balance(codes_prefix=["3103"])
        long_term_debt = self._get_balance(sub_types=["NON_CURRENT_LIABILITY"], exclude_prefixes=["2202"])
        eos_provision = self._get_balance(codes_prefix=["2202"])
        partners_credit = max(0.0, self._get_balance(sub_types=["EQUITY"], exclude_prefixes=["3101", "3102", "3103"]))

        total_added_sources = (
            capital + reserves + retained_earnings_opening +
            long_term_debt + eos_provision + partners_credit
        )

        ppe_gross = self._get_balance(codes_prefix=["1201"])
        accum_dep = self._get_balance(codes_prefix=["1202"])
        net_fixed_assets = max(0.0, ppe_gross - accum_dep)
        intangibles = self._get_balance(sub_types=["NON_CURRENT_ASSET"], exclude_prefixes=["1201", "1202"])

        total_deductions = net_fixed_assets + intangibles
        base_before_profit = total_added_sources - total_deductions
        adjusted_profit = max(0.0, book_profit)
        zakat_base = max(0.0, base_before_profit + adjusted_profit)
        zakat_due = zakat_base * self.zakat_rate_gregorian

        return {
            "sources_added": {
                "capital": round(capital, 2),
                "reserves": round(reserves, 2),
                "retained_earnings_opening": round(retained_earnings_opening, 2),
                "long_term_debt": round(long_term_debt, 2),
                "eos_provision": round(eos_provision, 2),
                "partners_credit_balance": round(partners_credit, 2),
                "total_added": round(total_added_sources, 2)
            },
            "deductions": {
                "net_fixed_assets": round(net_fixed_assets, 2),
                "intangibles": round(intangibles, 2),
                "total_deductions": round(total_deductions, 2)
            },
            "base_before_profit": round(base_before_profit, 2),
            "adjusted_net_profit": round(adjusted_profit, 2),
            "zakat_base": round(zakat_base, 2),
            "total_days": self.total_days,
            "applicable_zakat_rate_pct": round(self.zakat_rate_gregorian * 100, 4),
            "zakat_due": round(zakat_due, 2)
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
        working_capital = round(ca - cl, 2)

        gross_margin_pct = round((gross_profit / net_revenue) * 100, 2) if net_revenue > 0 else 0.0
        operating_margin_pct = round((op_profit / net_revenue) * 100, 2) if net_revenue > 0 else 0.0
        net_margin_pct = round((net_profit / net_revenue) * 100, 2) if net_revenue > 0 else 0.0
        roa_pct = round((net_profit / total_assets) * 100, 2) if total_assets > 0 else 0.0
        roe_pct = round((net_profit / total_equity) * 100, 2) if total_equity > 0 else 0.0

        debt_to_equity = round(total_debt / total_equity, 2) if total_equity > 0 else 0.0
        debt_to_assets = round(total_debt / total_assets, 2) if total_assets > 0 else 0.0

        return {
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
    # 7. التقرير المالي الشامل المجمع (Master Financial Package)
    # =========================================================================
    def generate_full_financial_report(self) -> Dict[str, Any]:
        """توليد حزمة التقارير المالية والضريبية والزكوية المتكاملة دفعة واحدة"""
        pnl = self.generate_income_statement()
        bs = self.generate_balance_sheet(
            net_profit_period=pnl["net_profit"],
            estimated_zakat=pnl["zakat_expense"]
        )
        cash_flow = self.generate_cash_flow_statement(pnl=pnl, bs=bs)
        vat_return = self.generate_vat_return()
        zakat = self.calculate_zakat_base(book_profit=pnl["profit_before_zakat"])
        ratios = self.calculate_financial_ratios(pnl=pnl, bs=bs)

        return {
            "fiscal_year": self.fiscal_year,
            "income_statement": pnl,
            "balance_sheet": bs,
            "cash_flow_statement": cash_flow,
            "vat_return": vat_return,
            "zakat_declaration": zakat,
            "financial_ratios": ratios
        }