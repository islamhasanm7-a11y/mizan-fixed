"""
MizanPro - Full Isolated Accounting, Security, Period Isolation, Decimal Rounding, Pre-Approval Reconciliation & ZATCA Test Suite
النظام المالي المتكامل - ميزان برو
ملف الاختبار الشامل المعزول (يستخدم قاعدة بيانات اختبار مؤقتة مستقلة تماماً ولا يمس قاعدة بيانات الإنتاج)
"""

import os
import sqlite3
import tempfile
from datetime import date, datetime

# =============================================================================
# 0. عزل بيئة الاختبار تماماً عن قاعدة بيانات التطبيق الرئيسية (Point 4)
# =============================================================================
_TMP_TEST_DB = tempfile.NamedTemporaryFile(prefix="mizanpro_isolated_test_", suffix=".db", delete=False)
_TMP_TEST_DB.close()
os.environ["MIZANPRO_DB_PATH"] = _TMP_TEST_DB.name
os.environ.pop("MIZANPRO_DATABASE_URL", None)

import pandas as pd
from database import (
    SessionLocal, Base, engine, PRODUCTION_DB_PATH, ACTIVE_DB_PATH,
    is_isolated_test_db, create_sanitized_backup_bytes
)
from seed_coa import init_database_and_seed, get_initial_admin_bootstrap_pin
from ledger_service import LedgerService, LedgerValidationError
from financial_engine import FinancialStatementsEngine
from export_service import ExcelExportService
from tb_analyzer_service import ExternalTBAnalyzerService
from models import (
    PaymentMethod, InvoiceType, NoteType,
    Product, AppUser, UserRole, SYSTEM_MODULES, SYSTEM_ACTIONS,
    get_default_permissions_for_role, calculate_line_and_tax_amounts, round_money,
    AuditLog, AuditLogReadOnlyError, SalesInvoice, PurchaseInvoice, CreditDebitNote,
    AUDIT_TRANSACTION_TYPES, classify_audit_transaction_type
)
from zatca_qr_tlv import (
    ZATCATLVEncodingError,
    ZATCATLVQRGenerator,
    decode_zatca_tlv_qr_base64,
    encode_tlv_tag,
    format_zatca_amount,
    format_zatca_timestamp,
    generate_zatca_tlv_qr_base64,
)
from sqlalchemy import text as sa_text


def run_full_accounting_cycle():
    # التأكد الصارم من أن الاختبار يعمل على قاعدة مؤقتة معزولة ولا يمس قاعدة التطبيق
    assert is_isolated_test_db() is True, "خطأ حرج: يجب أن يعمل الاختبار على قاعدة بيانات مؤقتة معزولة!"
    assert os.path.abspath(ACTIVE_DB_PATH) != os.path.abspath(PRODUCTION_DB_PATH)

    prod_db_exists_before = os.path.exists(PRODUCTION_DB_PATH)
    prod_db_mtime_before = os.path.getmtime(PRODUCTION_DB_PATH) if prod_db_exists_before else None

    init_database_and_seed(seed_demo_data=True)
    db = SessionLocal()
    print("\n" + "=" * 85)
    print("🚀 بدء الاختبار الشامل المعزول لنظام MizanPro ERP & CPA (قاعدة اختبار مؤقتة مستقلة)")
    print(f"🔒 مسار قاعدة الاختبار المؤقتة: {ACTIVE_DB_PATH}")
    print("=" * 85)

    try:
        # ---------------------------------------------------------------------
        # 1. اختبار إغلاق الدخول المفتوح، الرمز العشوائي للمدير، وتغييره الإلزامي عند أول دخول (Point 1)
        # ---------------------------------------------------------------------
        admin_user = db.query(AppUser).filter(AppUser.username == "admin").first()
        assert admin_user is not None
        assert admin_user.must_change_pin is True
        assert admin_user.verify_pin("1234") is False, "يجب ألا يقبل المدير الرمز الافتراضي المكشوف 1234!"

        bootstrap_pin = get_initial_admin_bootstrap_pin()
        assert bootstrap_pin is not None and len(bootstrap_pin) >= 6
        logged_admin = LedgerService.authenticate_user(db, "admin", bootstrap_pin)
        assert logged_admin.id == admin_user.id
        assert logged_admin.must_change_pin is True

        # رفض الرمز الضعيف أو المكرر عند التغيير
        weak_rejected = False
        try:
            LedgerService.change_user_pin(db, admin_user.id, bootstrap_pin, "1234")
        except LedgerValidationError:
            weak_rejected = True
        assert weak_rejected is True

        # قبول رمز سري قوي جديد وإلغاء علامة must_change_pin
        updated_admin = LedgerService.change_user_pin(db, admin_user.id, bootstrap_pin, "739284")
        assert updated_admin.must_change_pin is False
        assert updated_admin.verify_pin("739284") is True
        print("✅ [1/7] الدخول الإلزامي وتدوير الرمز العشوائي للمدير وتغييره عند أول دخول: ناجح 100%")

        # ---------------------------------------------------------------------
        # 2. اختبار منع تسريب البيانات وصلاحية النسخ الاحتياطي المستقلة وتطهير النسخ (Point 2)
        # ---------------------------------------------------------------------
        assert "act_cloud_backup" in SYSTEM_ACTIONS
        custom_perms = get_default_permissions_for_role(UserRole.CUSTOM)
        custom_perms["mod_sales"] = True
        custom_perms["mod_treasury"] = True
        custom_perms["act_create_sales"] = True
        custom_perms["act_create_vouchers"] = True
        custom_perms["act_export_reports"] = True
        custom_perms["act_cloud_backup"] = False

        custom_user = LedgerService.create_or_update_user(
            db=db,
            username="branch_cashier",
            full_name_ar="خالد العتيبي - محاسب مبيعات وصندوق",
            role=UserRole.CUSTOM,
            pin_code="482915",
            job_title="محاسب فرع وصندوق",
            permissions_dict=custom_perms,
            max_discount_pct=12.0,
            is_active=True,
            must_change_pin=False
        )
        assert custom_user.has_permission("act_export_reports") is True
        assert custom_user.has_permission("act_cloud_backup") is False

        sanitized_bytes = create_sanitized_backup_bytes(ACTIVE_DB_PATH)
        assert len(sanitized_bytes) > 4096
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_chk:
            tmp_chk.write(sanitized_bytes)
            tmp_chk_path = tmp_chk.name
        try:
            conn_chk = sqlite3.connect(tmp_chk_path)
            pins_in_backup = [r[0] for r in conn_chk.execute("SELECT pin_code FROM app_users").fetchall()]
            conn_chk.close()
            assert all(p == "REDACTED_IN_BACKUP" for p in pins_in_backup), "يجب تطهير كافة رموز الدخول من النسخة الاحتياطية!"
        finally:
            if os.path.exists(tmp_chk_path):
                os.remove(tmp_chk_path)
        print("✅ [2/7] فصل صلاحية Google Drive والنسخ الاحتياطي وتطهير ملفات (.db) من الرموز السرية: ناجح 100%")

        # ---------------------------------------------------------------------
        # 3. اختبار الضبط العشري للأموال وقواعد التقريب ROUND_HALF_UP للضريبة والفواتير (Point 5)
        # ---------------------------------------------------------------------
        from decimal import Decimal
        calc_test = calculate_line_and_tax_amounts(quantity=3, unit_price="33.33", discount="0.00", tax_rate="0.15")
        assert calc_test["taxable_amount"] == Decimal("99.99")
        assert calc_test["tax_amount"] == Decimal("15.00")  # 99.99 * 0.15 = 14.9985 -> 15.00 (ROUND_HALF_UP)
        assert calc_test["total_with_tax"] == Decimal("114.99")
        assert round_money("10.005") == 10.01
        print(f"✅ [3/7] دقة الحسابات العشرية (Decimal Numeric) وتقريب الضريبة (ROUND_HALF_UP): 99.99 + 15.00 = {calc_test['total_with_tax']}")

        # ---------------------------------------------------------------------
        # 4. اختبار عزل تقارير الفترات (قائمة الدخل وVAT) بقيود قبل الفترة وداخلها وبعدها (Point 3)
        # ---------------------------------------------------------------------
        prod1 = db.query(Product).filter(Product.code == "PRD-001").first()
        prod2 = db.query(Product).filter(Product.code == "PRD-002").first()

        # قيد الأرصدة الافتتاحية في 2026-01-01 لمطابقة الرصيد الافتتاحي للمخزون والأصول الثابتة والبنوك
        LedgerService.create_opening_balances_entry(
            db=db,
            opening_date=date(2026, 1, 1),
            lines_data=[
                {"account_code": "110101", "debit": 100000.00, "credit": 0.0},
                {"account_code": "110201", "debit": 200000.00, "credit": 0.0},
                {"account_code": "110202", "debit": 100000.00, "credit": 0.0},
                {"account_code": "110401", "debit": 17850.00, "credit": 0.0},   # مطابق لتقييم المخزون الافتتاحي (40*180 + 25*240 + 15*310)
                {"account_code": "120102", "debit": 50000.00, "credit": 0.0},
                {"account_code": "120103", "debit": 120000.00, "credit": 0.0},
                {"account_code": "120202", "debit": 0.0, "credit": 5000.00},
                {"account_code": "3101", "debit": 0.0, "credit": 582850.00},
            ],
            performed_by="المدير المالي"
        )

        # (أ) عملية قبل الفترة المستهدفة: فاتورة مبيعات في شهر يناير (2026-01-15) بمبلغ خاضع 1,500 ريال وضريبة 225 ريال
        sales_jan = LedgerService.create_sales_invoice(
            db=db, customer_name="شركة الأمل التجارية", customer_vat_number="300112233445563",
            invoice_date=date(2026, 1, 15), payment_method=PaymentMethod.CREDIT,
            invoice_type=InvoiceType.STANDARD,
            items_data=[
                {"product_id": prod1.id, "item_name": prod1.name_ar, "quantity": 5.0, "unit_price": 300.0, "cost_price": prod1.cost_price, "discount": 0.0, "tax_rate": 0.15},
            ],
            performed_by="خالد العتيبي (branch_cashier)"
        )
        assert sales_jan.taxable_amount == 1500.00 and sales_jan.vat_amount == 225.00

        tb_jan = LedgerService.get_live_trial_balance(
            db, start_date=date(2026, 1, 1), end_date=date(2026, 1, 31), include_zero_balances=True
        )
        eng_jan = FinancialStatementsEngine(tb_jan, fiscal_year=2026, start_date=date(2026, 1, 1), end_date=date(2026, 1, 31))
        jan_pnl = eng_jan.generate_income_statement()
        assert jan_pnl["gross_sales"] == 1500.00

        # (ب) عمليات داخل فترة فبراير 2026 (2026-02-01 إلى 2026-02-28)
        pur_feb = LedgerService.create_purchase_invoice(
            db=db, supplier_name="شركة التوريدات الهندسية العالمية",
            supplier_invoice_number="SUP-2026-901", invoice_date=date(2026, 2, 1),
            payment_method=PaymentMethod.CREDIT,
            items_data=[
                {"product_id": prod1.id, "item_name": prod1.name_ar, "quantity": 10.0, "unit_price": 200.0, "discount": 0.0, "tax_rate": 0.15},
                {"product_id": prod2.id, "item_name": prod2.name_ar, "quantity": 5.0, "unit_price": 400.0, "discount": 0.0, "tax_rate": 0.15},
            ],
            performed_by="خالد العتيبي (branch_cashier)"
        )
        # مشتريات فبراير الخاضعة للضريبة = (10*200) + (5*400) = 4,000 ريال، وضريبة مدخلاتها = 600 ريال
        sales_feb = LedgerService.create_sales_invoice(
            db=db, customer_name="شركة الأمل التجارية", customer_vat_number="300112233445563",
            invoice_date=date(2026, 2, 5), payment_method=PaymentMethod.BANK,
            invoice_type=InvoiceType.STANDARD,
            items_data=[
                {"product_id": prod1.id, "item_name": prod1.name_ar, "quantity": 5.0, "unit_price": 300.0, "cost_price": prod1.cost_price, "discount": 0.0, "tax_rate": 0.15},
                {"product_id": prod2.id, "item_name": prod2.name_ar, "quantity": 2.0, "unit_price": 650.0, "cost_price": prod2.cost_price, "discount": 0.0, "tax_rate": 0.15},
            ],
            treasury_account_code="110202",
            performed_by="خالد العتيبي (branch_cashier)"
        )
        # مبيعات فبراير الخاضعة للضريبة = (5*300) + (2*650) = 2,800 ريال، وضريبة مخرجاتها = 420 ريال
        dn_feb = LedgerService.create_credit_debit_note(
            db=db, note_type=NoteType.DEBIT_NOTE, party_name="شركة التوريدات الهندسية العالمية",
            original_invoice_number=pur_feb.invoice_number, purchase_invoice_id=pur_feb.id,
            note_date=date(2026, 2, 10),
            payment_method=PaymentMethod.CREDIT, reason="مرتجع بضاعة للمورد متعدد الأصناف",
            items_data=[
                {"product_id": prod1.id, "item_name": prod1.name_ar, "quantity": 2.0, "unit_price": 200.0, "cost_price": prod1.cost_price, "tax_rate": 0.15},
                {"product_id": prod2.id, "item_name": prod2.name_ar, "quantity": 1.0, "unit_price": 400.0, "cost_price": prod2.cost_price, "tax_rate": 0.15},
            ],
            performed_by="خالد العتيبي (branch_cashier)"
        )
        # إشعار مدين (مرتجع مشتريات فبراير) = 800 ريال، عكس ضريبة مدخلات = 120 ريال -> صافي ضريبة مدخلات فبراير = 600 - 120 = 480 ريال
        dep_je = LedgerService.run_period_depreciation(db=db, dep_date=date(2026, 2, 28), months=1, performed_by="المدير المالي")
        pr_run = LedgerService.process_monthly_payroll(
            db=db, period_month="2026-02", payment_date=date(2026, 2, 28),
            treasury_account_code="110201", performed_by="المدير المالي"
        )

        # (ج) عمليات بعد الفترة في مارس 2026 (2026-03-15) لاختبار عدم تسللها لتقرير فبراير
        sales_mar = LedgerService.create_sales_invoice(
            db=db, customer_name="شركة الأمل التجارية", customer_vat_number="300112233445563",
            invoice_date=date(2026, 3, 15), payment_method=PaymentMethod.CASH,
            invoice_type=InvoiceType.STANDARD,
            items_data=[
                {"product_id": prod1.id, "item_name": prod1.name_ar, "quantity": 1.0, "unit_price": 1000.0, "cost_price": prod1.cost_price, "discount": 0.0, "tax_rate": 0.15},
            ],
            treasury_account_code="110101",
            performed_by="خالد العتيبي (branch_cashier)"
        )
        assert sales_mar.grand_total == 1150.00

        # الآن نستخرج تقرير فترة شهر فبراير فقط [2026-02-01 إلى 2026-02-28]
        tb_feb = LedgerService.get_live_trial_balance(
            db, start_date=date(2026, 2, 1), end_date=date(2026, 2, 28), include_zero_balances=True
        )
        eng_feb = FinancialStatementsEngine(
            trial_balance_df=tb_feb,
            fiscal_year=2026,
            vat_rate=settings_vat_rate if (settings_vat_rate := LedgerService.get_company_settings(db).default_vat_rate) else 0.15,
            start_date=date(2026, 2, 1),
            end_date=date(2026, 2, 28)
        )
        rep_feb = eng_feb.generate_full_financial_report()
        pnl_feb = rep_feb["income_statement"]
        vat_feb = rep_feb["vat_return"]
        bs_feb = rep_feb["balance_sheet"]
        cf_feb = rep_feb["cash_flow_statement"]

        # التحقق الصارم من أن قائمة الدخل وإقرار الضريبة لشهر فبراير يعكسان حركات فبراير فقط (بدون يناير وبدون مارس!)
        assert pnl_feb["start_date"] == "2026-02-01" and pnl_feb["end_date"] == "2026-02-28"
        assert "2026-02-01" in pnl_feb["period_label_ar"] and "2026-02-28" in pnl_feb["period_label_ar"]
        assert pnl_feb["gross_sales"] == 2800.00, f"Expected Feb sales 2800.00, got {pnl_feb['gross_sales']}"
        assert vat_feb["box_1_std_sales"]["vat_amount"] == 420.00, f"Expected Feb output VAT 420.00, got {vat_feb['box_1_std_sales']['vat_amount']}"
        assert vat_feb["box_7_std_purchases"]["recoverable_vat"] == 480.00, f"Expected Feb input VAT 480.00, got {vat_feb['box_7_std_purchases']['recoverable_vat']}"
        assert vat_feb["net_vat_due"] == -60.00  # 420 - 480 = -60 (رصيد دائن قابل للاسترداد عن فترة فبراير)
        assert bs_feb["is_balanced"] is True, f"Balance sheet as of 2026-02-28 must be balanced! Diff={bs_feb['balance_difference']}"
        assert abs((cf_feb["opening_cash_balance"] + cf_feb["net_change_in_cash"]) - cf_feb["closing_cash_balance"]) < 0.01
        print(
            f"✅ [4/7] دقة تقارير الفترات المعزولة ({pnl_feb['period_label_ar']}): "
            f"مبيعات فبراير={pnl_feb['gross_sales']:,.2f} | صافي VAT فبراير={vat_feb['net_vat_due']:,.2f} | الميزانية متزنة 100%"
        )

        # ---------------------------------------------------------------------
        # 5. اختبار مراجعة الحسابات ومطابقة العينات (القوائم + VAT + الزكاة + الأستاذ المساعد) قبل الاعتماد الرسمي (Point 7)
        # ---------------------------------------------------------------------
        tb_full = LedgerService.get_live_trial_balance(
            db, start_date=date(2026, 1, 1), end_date=date(2026, 12, 31), include_zero_balances=True
        )
        eng_full = FinancialStatementsEngine(
            trial_balance_df=tb_full,
            fiscal_year=2026,
            vat_rate=0.15,
            start_date=date(2026, 1, 1),
            end_date=date(2026, 12, 31)
        )
        rep_full = eng_full.generate_full_financial_report()
        pre_audit = rep_full["pre_approval_audit"]
        subledger_rec = LedgerService.reconcile_subledgers_with_gl(db)

        assert pre_audit["is_approved_ready"] is True, f"Pre-approval checks failed: {pre_audit['checks']}"
        assert subledger_rec["all_reconciled"] is True, f"Subledger reconciliation failed: {subledger_rec['checks']}"
        print(
            f"✅ [5/7] مراجعة ومطابقة القوائم المالية وVAT والزكاة والأستاذ المساعد قبل الاعتماد الرسمي: "
            f"{len(pre_audit['checks']) + len(subledger_rec['checks'])} فحوصات رقابية مطابقة 100%"
        )

        # ---------------------------------------------------------------------
        # 6. اختبار تثبيت بيئة التشغيل وملف القفل (Point 6)
        # ---------------------------------------------------------------------
        from setup_env import check_installed_dependencies
        missing_pkgs = check_installed_dependencies()
        assert missing_pkgs == [], f"Missing required packages: {missing_pkgs}"
        assert os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.lock"))
        print("✅ [6/7] تثبيت بيئة التشغيل وملف القفل (requirements.lock + setup_env.py): ناجح 100%")

        # ---------------------------------------------------------------------
        # 7. اختبار محلل ميزان المراجعة الخارجي والتقرير التنفيذي ومركز Google Drive
        # ---------------------------------------------------------------------
        sample_tb = ExternalTBAnalyzerService.get_sample_tasaheel_tb_dataframe()
        c_df = ExternalTBAnalyzerService.normalize_and_classify_tb(sample_tb)
        cpa_pkg = ExternalTBAnalyzerService.generate_cpa_full_package(c_df, {
            "company_name": "مؤسسة تساهيل طيبة التجارية",
            "include_auditor_report": True,
            "opinion_type": "GOING_CONCERN"
        })
        assert abs((cpa_pkg["cash_flow_statement"]["opening_cash"] + cpa_pkg["cash_flow_statement"]["net_cash_change"]) - cpa_pkg["cash_flow_statement"]["closing_cash"]) < 0.01
        excel_bytes = ExcelExportService.generate_master_excel_report(db, fiscal_year=2026)
        assert len(excel_bytes.getvalue()) > 8000

        # ---------------------------------------------------------------------
        # 8. اختبار محرك التحقق الصارم للمرحلة الثانية من الفوترة الإلكترونية (ZATCA Phase 2 Validator & QR Tags 1-9)
        # ---------------------------------------------------------------------
        from zatca_phase2_validator import ZATCAPhase2Validator
        from models import VoucherType, VoucherPartyType

        # (أ) اختبار التحقق من المعرفات الضريبية السعودية (15 رقماً يبدأ وينتهي بـ 3) والسجل التجاري (10 أرقام)
        valid_ind_vat = ZATCAPhase2Validator.validate_saudi_vat_number("310122393500003", required=True)
        assert valid_ind_vat["is_valid"] is True and valid_ind_vat["is_tax_group"] is False
        valid_grp_vat = ZATCAPhase2Validator.validate_saudi_vat_number("310122393510003", required=True)
        assert valid_grp_vat["is_valid"] is True and valid_grp_vat["is_tax_group"] is True
        invalid_vat_1 = ZATCAPhase2Validator.validate_saudi_vat_number("210122393500003", required=True)
        assert invalid_vat_1["is_valid"] is False
        invalid_vat_2 = ZATCAPhase2Validator.validate_saudi_vat_number("310122393500009", required=True)
        assert invalid_vat_2["is_valid"] is False
        invalid_vat_len = ZATCAPhase2Validator.validate_saudi_vat_number("310123", required=True)
        assert invalid_vat_len["is_valid"] is False

        valid_cr = ZATCAPhase2Validator.validate_saudi_cr_number("1010998877", required=True)
        assert valid_cr["is_valid"] is True
        invalid_cr = ZATCAPhase2Validator.validate_saudi_cr_number("10109", required=True)
        assert invalid_cr["is_valid"] is False

        # (ب) التأكد من رفض إصدار فاتورة مبيعات قياسية (B2B) بدون رقم ضريبي صالح للمشتري
        b2b_rejected = False
        try:
            LedgerService.create_sales_invoice(
                db=db, customer_name="عميل شركات بدون رقم ضريبي صالح", customer_vat_number="123456",
                invoice_date=date(2026, 2, 18), payment_method=PaymentMethod.CREDIT,
                invoice_type=InvoiceType.STANDARD,
                items_data=[{"product_id": prod1.id, "item_name": prod1.name_ar, "quantity": 1.0, "unit_price": 300.0, "cost_price": prod1.cost_price, "discount": 0.0, "tax_rate": 0.15}],
                performed_by="المدير المالي"
            )
        except LedgerValidationError:
            b2b_rejected = True
        assert b2b_rejected is True, "يجب رفض الفاتورة الضريبية القياسية B2B إذا كان الرقم الضريبي للعميل غير مطابق لمعيار ZATCA!"

        # (ج) إصدار سند قبض مالي لاختبار تغطية ZATCA Phase 2 لكافة المستندات المالية (Sales, Purchases, Credit/Debit Notes, Cash Vouchers)
        voucher_feb = LedgerService.create_cash_voucher(
            db=db, voucher_type=VoucherType.RECEIPT, amount=500.00,
            party_type=VoucherPartyType.CUSTOMER, customer_id=sales_feb.customer_id,
            party_name="شركة الأمل التجارية", description="دفعة تحت الحساب",
            voucher_date=date(2026, 2, 20), payment_method=PaymentMethod.BANK,
            treasury_account_code="110201", performed_by="المدير المالي"
        )
        assert voucher_feb.id is not None

        # (د) فحص وتدقيق كافة المستندات المالية في قاعدة البيانات عبر ZATCAPhase2Validator
        p2_audit = ZATCAPhase2Validator.audit_all_database_documents(db, auto_upgrade_phase2=True)
        assert p2_audit["total_documents"] >= 5
        assert p2_audit["non_compliant_documents"] == 0, f"Found non-compliant documents: {p2_audit['reports']}"
        assert p2_audit["overall_compliance_pct"] == 100.0

        # التحقق من أن باركود QR يحتوي على كافة الحقول الـ 9 (Tags 1..9) الخاصة بالمرحلة الثانية
        sample_rep = p2_audit["reports"][0]
        decoded_qr = ZATCAPhase2Validator.decode_zatca_tlv(sample_rep["qr_code_base64"])
        assert decoded_qr["is_valid_tlv"] is True
        assert decoded_qr["has_phase2_tags"] is True
        for tag_num in range(1, 10):
            assert tag_num in decoded_qr["tags"], f"Missing ZATCA Phase 2 TLV Tag {tag_num}!"
        assert "<Invoice" in sample_rep["ubl_xml"] and "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" in sample_rep["ubl_xml"]

        three_inspector_html = ZATCAPhase2Validator.render_zatca_3d_inspector_html(sample_rep)
        assert "three.module.js" in three_inspector_html and "RoomEnvironment" in three_inspector_html
        print(
            f"✅ [7/9] محرك التحقق للمرحلة الثانية (ZATCA Phase 2 Validator & QR TLV Tags 1–9 & UBL 2.1 XML): "
            f"{p2_audit['compliant_documents']}/{p2_audit['total_documents']} مستندات متوافقة 100%"
        )

        # ---------------------------------------------------------------------
        # 8. اختبار سجل الرقابة والتدقيق الإلزامي للقراءة فقط (Read-Only ZATCA Audit Log System)
        # ---------------------------------------------------------------------
        # (أ) اختبار ربط الجلسة بمعرّف المستخدم النشط (User ID) وتسجيل عكس قيد وتعديل معاملة مالية
        db.info["audit_user_id"] = "USR-005"
        db.info["audit_username"] = "cpa_auditor"
        db.info["audit_performed_by"] = "المراجع القانوني (CPA)"

        # عكس قيد محاسبي (Reverse Journal Entry) للتحقق من تسجيل التعديل مع القيم قبل وبعد (Old/New Values) ومعرف المستخدم USR-005
        reversal_je = LedgerService.reverse_journal_entry(
            db=db,
            entry_id=sales_feb.journal_entry_id,
            reason="تصحيح خطأ توجيه محاسبي بناءً على مراجعة ZATCA",
            performed_by="المراجع القانوني (CPA)",
        )
        assert reversal_je.id is not None

        # اختبار التعديل المباشر على مستند مالي في الجلسة (Session before_flush interceptor)
        voucher_feb.description = "دفعة تحت الحساب - محدّثة بعد المطابقة البنكية"
        db.commit()

        # التحقق من أن جميع سجلات التدقيق تحتوي على user_id و timestamp و entry_hash و previous_hash
        all_audit_logs = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
        assert len(all_audit_logs) >= 15, f"Expected at least 15 audit logs, got {len(all_audit_logs)}"
        for log_row in all_audit_logs:
            assert log_row.user_id is not None and len(log_row.user_id.strip()) >= 4, f"Missing user_id on AuditLog #{log_row.id}"
            assert log_row.timestamp is not None, f"Missing timestamp on AuditLog #{log_row.id}"
            assert log_row.entry_hash is not None and len(log_row.entry_hash) == 64
            assert log_row.previous_hash is not None and len(log_row.previous_hash) == 64

        # التحقق من وجود سجل عكس القيد وسجل التعديل التلقائي مع لقطات الحالة (old_values_json / new_values_json)
        reverse_log = (
            db.query(AuditLog)
            .filter(AuditLog.action == "REVERSE_JOURNAL_ENTRY", AuditLog.record_id == sales_feb.journal_entry_id)
            .first()
        )
        assert reverse_log is not None, "لم يتم تسجيل عملية عكس القيد في سجل التدقيق!"
        assert reverse_log.user_id == "USR-005"
        assert reverse_log.old_values_json is not None and '"status": "POSTED"' in reverse_log.old_values_json
        assert reverse_log.new_values_json is not None and '"status": "REVERSED"' in reverse_log.new_values_json

        modify_voucher_log = (
            db.query(AuditLog)
            .filter(AuditLog.action == "MODIFY_CASH_VOUCHERS", AuditLog.table_name == "cash_vouchers", AuditLog.record_id == voucher_feb.id)
            .first()
        )
        assert modify_voucher_log is not None, "لم يتم رصد التعديل المباشر على سند القبض في سجل التدقيق!"
        assert modify_voucher_log.user_id == "USR-005"
        assert "دفعة تحت الحساب" in (modify_voucher_log.old_values_json or "")
        assert "محدّثة بعد المطابقة البنكية" in (modify_voucher_log.new_values_json or "")

        # (ب) التحقق من سلامة سلسلة التشفير SHA-256 وحالة القراءة فقط عبر LedgerService.verify_audit_log_integrity
        audit_integrity = LedgerService.verify_audit_log_integrity(db)
        assert audit_integrity["is_intact"] is True, f"Audit log chain broken: {audit_integrity}"
        assert audit_integrity["is_read_only_enforced"] is True, "SQLite Read-Only triggers are not active!"
        assert audit_integrity["missing_user_id_count"] == 0
        assert audit_integrity["missing_timestamp_count"] == 0

        # (ج) اختبار منع التعديل أو الحذف عبر SQLAlchemy ORM (AuditLogReadOnlyError)
        orm_update_blocked = False
        try:
            target_log = all_audit_logs[0]
            target_log.details = "محاولة تلاعب بسجل التدقيق"
            db.flush()
        except AuditLogReadOnlyError:
            orm_update_blocked = True
            db.rollback()
        assert orm_update_blocked is True, "يجب أن يمنع النظام تعديل أي سجل تدقيق عبر ORM!"

        orm_delete_blocked = False
        try:
            target_log = db.query(AuditLog).first()
            db.delete(target_log)
            db.flush()
        except AuditLogReadOnlyError:
            orm_delete_blocked = True
            db.rollback()
        assert orm_delete_blocked is True, "يجب أن يمنع النظام حذف أي سجل تدقيق عبر ORM!"

        # (د) اختبار منع التعديل أو الحذف عبر أوامر SQL مباشرة (SQLite Triggers: ZATCA_AUDIT_LOG_READ_ONLY)
        sql_update_blocked = False
        try:
            db.execute(sa_text("UPDATE audit_logs SET details = 'HACKED' WHERE id = 1"))
            db.commit()
        except Exception as exc:
            sql_update_blocked = "ZATCA_AUDIT_LOG_READ_ONLY" in str(exc)
            db.rollback()
        assert sql_update_blocked is True, "يجب أن تمنع قدّاحات قاعدة البيانات (SQLite Triggers) أي جملة UPDATE مباشرة على audit_logs!"

        sql_delete_blocked = False
        try:
            db.execute(sa_text("DELETE FROM audit_logs WHERE id = 1"))
            db.commit()
        except Exception as exc:
            sql_delete_blocked = "ZATCA_AUDIT_LOG_READ_ONLY" in str(exc)
            db.rollback()
        assert sql_delete_blocked is True, "يجب أن تمنع قدّاحات قاعدة البيانات (SQLite Triggers) أي جملة DELETE مباشرة على audit_logs!"

        print(
            f"✅ [8/10] سجل الرقابة والتدقيق الإلزامي للقراءة فقط (ZATCA Read-Only Audit Log): "
            f"{audit_integrity['verified_entries']}/{audit_integrity['total_entries']} سجل موثّق بـ User ID و Timestamp وسلسلة SHA-256 غير قابلة للتعديل أو الحذف"
        )

        # ---------------------------------------------------------------------
        # 9. اختبار أداة توليد وفك تشفير باركود الفاتورة الإلكترونية (ZATCA Phase 2 Base64 TLV QR Utility)
        # ---------------------------------------------------------------------
        # (أ) اختبار توليد وفك تشفير TLV Base64 مباشر (Seller Name, VAT Number, Timestamp, Invoice Total, VAT Total)
        direct_qr_b64 = generate_zatca_tlv_qr_base64(
            seller_name="شركة ميزان برو للتقنية المالية",
            vat_number="300000000000003",
            timestamp="2026-02-15T14:30:00Z",
            invoice_total="2300.00",
            vat_total="300.00",
            phase2=True,
        )
        decoded_direct = decode_zatca_tlv_qr_base64(direct_qr_b64)
        assert decoded_direct["is_valid_tlv"] is True
        assert decoded_direct["has_phase1_tags"] is True
        assert decoded_direct["has_phase2_tags"] is True
        assert decoded_direct["seller_name"] == "شركة ميزان برو للتقنية المالية"
        assert decoded_direct["vat_number"] == "300000000000003"
        assert decoded_direct["timestamp"] == "2026-02-15T14:30:00Z"
        assert decoded_direct["invoice_total"] == "2300.00"
        assert decoded_direct["vat_total"] == "300.00"
        assert len(decoded_direct["tags"]) == 9

        # (ب) اختبار الحساب التلقائي لضريبة القيمة المضافة 15% عند تمرير invoice_total فقط بدون vat_total
        auto_vat_qr_b64 = generate_zatca_tlv_qr_base64(
            seller_name="مؤسسة التوريدات الحديثة",
            vat_number="311223344556673",
            timestamp="2026-02-20",
            invoice_total=1150.00,
        )
        decoded_auto_vat = decode_zatca_tlv_qr_base64(auto_vat_qr_b64)
        assert decoded_auto_vat["is_valid_tlv"] is True
        assert decoded_auto_vat["timestamp"] == "2026-02-20T12:00:00Z"
        assert decoded_auto_vat["invoice_total"] == "1150.00"
        assert decoded_auto_vat["vat_total"] == "150.00"

        # (ج) اختبار رفض الرقم الضريبي غير المطابق لمعيار ZATCA (15 رقماً يبدأ وينتهي بـ 3)
        invalid_vat_rejected = False
        try:
            generate_zatca_tlv_qr_base64(
                seller_name="منشأة تجريبية",
                vat_number="123456789012345",
                timestamp="2026-02-20T10:00:00Z",
                invoice_total=115.00,
            )
        except ZATCATLVEncodingError:
            invalid_vat_rejected = True
        assert invalid_vat_rejected is True, "يجب أن ترفض أداة TLV QR أي رقم ضريبي لا يبدأ وينتهي بـ 3 أو لا يتكون من 15 رقماً!"

        # (د) التحقق من أن كل فاتورة في قاعدة البيانات (SalesInvoice, PurchaseInvoice, CreditDebitNote)
        # تمتلك رمز QR TLV Base64 محفوظاً وصالحاً ومشتملاً على اسم البائع والرقم الضريبي والطابع الزمني والإجمالي
        all_sales = db.query(SalesInvoice).all()
        all_purchases = db.query(PurchaseInvoice).all()
        all_notes = db.query(CreditDebitNote).all()
        assert len(all_sales) >= 3 and len(all_purchases) >= 1 and len(all_notes) >= 1

        for inv_doc in [*all_sales, *all_purchases, *all_notes]:
            assert getattr(inv_doc, "qr_code_base64", None), f"Missing qr_code_base64 on {inv_doc}"
            dec_doc = LedgerService.decode_zatca_qr_code(inv_doc.qr_code_base64)
            assert dec_doc["is_valid_tlv"] is True, f"Invalid TLV QR on {inv_doc}"
            assert dec_doc["has_phase1_tags"] is True and dec_doc["has_phase2_tags"] is True
            assert len(dec_doc["seller_name"]) >= 2
            assert len(dec_doc["vat_number"]) == 15 and dec_doc["vat_number"].startswith("3") and dec_doc["vat_number"].endswith("3")
            assert "T" in dec_doc["timestamp"] and dec_doc["timestamp"].endswith("Z")
            assert dec_doc["invoice_total"] == f"{float(inv_doc.grand_total):.2f}"
            assert dec_doc["vat_total"] == f"{float(inv_doc.vat_amount):.2f}"

        print(
            f"✅ [9/11] أداة باركود الفاتورة الإلكترونية (ZATCA Phase 2 Base64 TLV QR Utility): "
            f"تم التحقق من سلامة ترميز وفك تشفير TLV (Tags 1–9) لـ ({len(all_sales) + len(all_purchases) + len(all_notes)}) فاتورة وإشعار ضريبي بنسبة 100%"
        )

        # ---------------------------------------------------------------------
        # 10. اختبار وحدة واجهة ومحرك استعلام سجل التدقيق الرقابي للقراءة فقط (Read-Only ZATCA Audit Log Filter & UI Module)
        # ---------------------------------------------------------------------
        # (أ) التحقق من صلاحيات الوصول للمستخدمين المخولين فقط (Authorized Users Only)
        admin_user_obj = db.query(AppUser).filter(AppUser.username == "admin").first()
        auditor_user_obj = db.query(AppUser).filter(AppUser.role == UserRole.AUDITOR).first()
        sales_user_obj = db.query(AppUser).filter(AppUser.role == UserRole.SALES).first()

        assert LedgerService.is_user_authorized_for_audit_logs(db, admin_user_obj) is True
        assert LedgerService.is_user_authorized_for_audit_logs(db, auditor_user_obj) is True
        assert LedgerService.is_user_authorized_for_audit_logs(db, sales_user_obj) is False

        # التأكد من رفض وصول المستخدم غير المخول (SALES) عند استدعاء query_audit_logs
        unauth_blocked = False
        try:
            LedgerService.query_audit_logs(db=db, requesting_user=sales_user_obj)
        except LedgerValidationError as exc_unauth:
            unauth_blocked = "ZATCA_AUDIT_ACCESS_DENIED" in str(exc_unauth)
        assert unauth_blocked is True, "يجب منع المستخدم غير المخول من استعراض سجل التدقيق الرقابي!"

        # (ب) إدراج سجلات تدقيق إضافية بتواريخ محددة (يناير، فبراير، مارس 2026) لاختبار فلترة النطاق الزمني بدقة
        db.add(AuditLog(
            table_name="sales_invoices",
            record_id=sales_jan.id,
            action="ARCHIVE_SALES_INVOICE",
            user_id="USR-001",
            username="admin",
            performed_by="المدير المالي (admin)",
            timestamp=datetime(2026, 1, 15, 10, 30, 0),
            reference_number=sales_jan.invoice_number,
            financial_amount=sales_jan.grand_total,
            details="Archived Jan sales invoice for ZATCA inspection",
        ))
        db.add(AuditLog(
            table_name="journal_entries",
            record_id=reversal_je.id,
            action="AUDIT_REVIEW_JOURNAL_ENTRY",
            user_id="USR-005",
            username="cpa_auditor",
            performed_by="المراجع القانوني (CPA)",
            timestamp=datetime(2026, 2, 18, 14, 15, 0),
            reference_number=reversal_je.entry_number,
            financial_amount=reversal_je.total_debit,
            details="Reviewed Feb journal entry reversal",
        ))
        db.add(AuditLog(
            table_name="purchase_invoices",
            record_id=pur_feb.id,
            action="VERIFY_PURCHASE_INVOICE",
            user_id="USR-005",
            username="cpa_auditor",
            performed_by="المراجع القانوني (CPA)",
            timestamp=datetime(2026, 3, 25, 9, 0, 0),
            reference_number=pur_feb.invoice_number,
            financial_amount=pur_feb.grand_total,
            details="Verified March purchase tax invoice",
        ))
        db.commit()

        # (ج) اختبار الفلترة حسب نطاق التاريخ (Date Range Filtering: Feb 1, 2026 -> Feb 28, 2026)
        feb_audit_res = LedgerService.query_audit_logs(
            db=db,
            start_date=date(2026, 2, 1),
            end_date=date(2026, 2, 28),
            requesting_user=auditor_user_obj,
        )
        assert feb_audit_res["summary"]["total_matched"] == 1
        assert feb_audit_res["records"][0]["date_only"] == "2026-02-18"
        assert feb_audit_res["records"][0]["action"] == "AUDIT_REVIEW_JOURNAL_ENTRY"

        # التحقق من رفض نطاق تاريخ معكوس (start_date > end_date)
        bad_range_blocked = False
        try:
            LedgerService.query_audit_logs(
                db=db,
                start_date=date(2026, 3, 31),
                end_date=date(2026, 1, 1),
                requesting_user=admin_user_obj,
            )
        except LedgerValidationError:
            bad_range_blocked = True
        assert bad_range_blocked is True

        # (د) اختبار الفلترة حسب المستخدم (User Filtering: USR-005 / cpa_auditor)
        usr5_res = LedgerService.query_audit_logs(
            db=db,
            user_filter="USR-005 (cpa_auditor)",
            requesting_user=auditor_user_obj,
        )
        assert usr5_res["summary"]["total_matched"] >= 4
        for r_u in usr5_res["records"]:
            assert r_u["user_id"] == "USR-005" and r_u["username"] == "cpa_auditor"

        # (هـ) اختبار الفلترة حسب نوع المعاملة المالية (Transaction Type Filtering)
        sales_tx_res = LedgerService.query_audit_logs(
            db=db,
            transaction_type="SALES_INVOICES",
            requesting_user=admin_user_obj,
        )
        assert sales_tx_res["summary"]["total_matched"] >= 4
        for r_tx in sales_tx_res["records"]:
            assert r_tx["transaction_type_key"] == "SALES_INVOICES"
            assert r_tx["table_name"] == "sales_invoices"

        voucher_tx_res = LedgerService.query_audit_logs(
            db=db,
            transaction_type="CASH_BANK_VOUCHERS",
            only_modifications=True,
            requesting_user=auditor_user_obj,
        )
        assert voucher_tx_res["summary"]["total_matched"] >= 1
        assert voucher_tx_res["records"][0]["action"] == "MODIFY_CASH_VOUCHERS"
        assert voucher_tx_res["records"][0]["is_modification"] is True
        assert "description" in voucher_tx_res["records"][0]["changed_fields"]

        # التحقق النهائي من أن سلسلة التشفير SHA-256 لا تزال سليمة 100% بعد كافة العمليات
        final_integrity = LedgerService.verify_audit_log_integrity(db)
        assert final_integrity["is_intact"] is True

        print(
            f"✅ [10/12] وحدة سجل التدقيق الرقابي للقراءة فقط (Read-Only ZATCA Audit Log UI & Filter Engine): "
            f"فلترة دقيقة حسب النطاق الزمني والمستخدم ونوع المعاملة ({len(AUDIT_TRANSACTION_TYPES)} فئات) مع عزل الصلاحيات بنسبة 100%"
        )

        # ---------------------------------------------------------------------
        # 11. اختبار تصدير سجل التدقيق بصيغة PDF مؤمّنة وغير قابلة للتعديل للمراجع الخارجي (Immutable Auditor PDF Export)
        # ---------------------------------------------------------------------
        # (أ) التأكد من منع المستخدم غير المخول (SALES) من تصدير ملف PDF لسجل التدقيق
        unauth_pdf_blocked = False
        try:
            LedgerService.export_immutable_audit_pdf(db=db, requesting_user=sales_user_obj)
        except LedgerValidationError as exc_pdf:
            unauth_pdf_blocked = "ZATCA_AUDIT_ACCESS_DENIED" in str(exc_pdf)
        assert unauth_pdf_blocked is True, "يجب منع المستخدم غير المخول من تصدير ملف PDF لسجل التدقيق الرقابي!"

        # (ب) تصدير تقرير PDF مؤمّن وغير قابل للتعديل بواسطة المراجع القانوني الخارجي (CPA Auditor)
        full_audit_pdf_bytes = LedgerService.export_immutable_audit_pdf(
            db=db,
            requesting_user=auditor_user_obj,
            auditor_notes="تمت المراجعة الخارجية لسجلات التدقيق والتحقق من سلسلة SHA-256 وفق متطلبات ZATCA.",
        )
        assert isinstance(full_audit_pdf_bytes, bytes) and len(full_audit_pdf_bytes) > 25000
        assert full_audit_pdf_bytes.startswith(b"%PDF-1.4")
        assert full_audit_pdf_bytes.rstrip().endswith(b"%%EOF")
        assert b"READ-ONLY-IMMUTABLE-LOCKED" in full_audit_pdf_bytes

        # (ج) التحقق الجنائي من سلامة ملف PDF المصدّر عبر LedgerService.verify_immutable_audit_pdf
        pdf_verify_res = LedgerService.verify_immutable_audit_pdf(full_audit_pdf_bytes)
        assert pdf_verify_res["is_valid_pdf"] is True
        assert pdf_verify_res["is_immutable_sealed"] is True
        assert pdf_verify_res["is_tamper_free"] is True
        assert pdf_verify_res["permissions_mode"] == "READ_ONLY_IMMUTABLE"
        assert pdf_verify_res["company_vat"] == "300000000000003"
        assert pdf_verify_res["total_records_exported"] >= 35
        assert len(pdf_verify_res["core_pdf_sha256"]) == 64
        assert len(pdf_verify_res["manifest_seal_sha256"]) == 64
        assert len(pdf_verify_res["records_digest_sha256"]) == 64

        # (د) اختبار تصدير PDF مفلتر للمراجع الخارجي (فلترة بالمستخدم USR-005 ونوع المعاملة)
        filtered_pdf_bytes = LedgerService.export_immutable_audit_pdf(
            db=db,
            user_filter="USR-005 (cpa_auditor)",
            transaction_type="JOURNAL_ENTRIES",
            requesting_user=auditor_user_obj,
        )
        filtered_pdf_verify = LedgerService.verify_immutable_audit_pdf(filtered_pdf_bytes)
        assert filtered_pdf_verify["is_tamper_free"] is True
        assert filtered_pdf_verify["total_records_exported"] >= 2
        assert filtered_pdf_verify["filters_applied"]["transaction_type"] == "JOURNAL_ENTRIES"

        # (هـ) اختبار كشف التلاعب الجنائي (Tamper Detection): تعديل بايت واحد في محتوى صفحات الـ PDF
        tampered_pdf = bytearray(full_audit_pdf_bytes)
        tamper_idx = 500  # داخل منطقة بيانات صفحات الـ PDF الأساسية قبل كتلة الختم
        tampered_pdf[tamper_idx] = (tampered_pdf[tamper_idx] + 1) % 256
        tamper_verify_res = LedgerService.verify_immutable_audit_pdf(bytes(tampered_pdf))
        assert tamper_verify_res["is_tamper_free"] is False, "يجب أن يكتشف المحرك فوراً أي تعديل ولو لبايت واحد في ملف الـ PDF!"

        print(
            f"✅ [11/12] تصدير سجل التدقيق بصيغة PDF مؤمّنة وغير قابلة للتعديل (Immutable Auditor PDF): "
            f"وثيقة ({pdf_verify_res['document_id']}) بحجم ({len(full_audit_pdf_bytes):,} بايت) مختومة بـ SHA-256 ومحمية ضد التلاعب 100%"
        )

    finally:
        db.close()
        engine.dispose()
        if os.path.exists(ACTIVE_DB_PATH) and is_isolated_test_db():
            os.remove(ACTIVE_DB_PATH)

    # التحقق النهائي من أن قاعدة بيانات الإنتاج لم تُحذف ولم تتأثر بالاختبار
    if prod_db_exists_before:
        assert os.path.exists(PRODUCTION_DB_PATH), "خطأ: قاعدة بيانات التطبيق الرئيسية تأثرت!"
        assert os.path.getmtime(PRODUCTION_DB_PATH) == prod_db_mtime_before, "خطأ: تم تعديل قاعدة بيانات الإنتاج أثناء الاختبار!"
    print("✅ [12/12] عزل الاختبارات: تم تنظيف قاعدة الاختبار المؤقتة وبقيت قاعدة التطبيق الرئيسية سليمة 100% دون أي مساس!")


if __name__ == "__main__":
    run_full_accounting_cycle()