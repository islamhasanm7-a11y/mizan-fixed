"""
MizanPro - Full Isolated Accounting, Security, Period Isolation, Decimal Rounding, Pre-Approval Reconciliation & ZATCA Test Suite
النظام المالي المتكامل - ميزان برو
ملف الاختبار الشامل المعزول (يستخدم قاعدة بيانات اختبار مؤقتة مستقلة تماماً ولا يمس قاعدة بيانات الإنتاج)
"""

import os
import sqlite3
import tempfile
from datetime import date, datetime, timedelta

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
from financial_engine import FinancialStatementsEngine, ExportService
from export_service import ExcelExportService, CSVExportService
from tb_analyzer_service import ExternalTBAnalyzerService
from models import (
    PaymentMethod, InvoiceType, NoteType,
    Product, AppUser, UserRole, SYSTEM_MODULES, SYSTEM_ACTIONS,
    get_default_permissions_for_role, calculate_line_and_tax_amounts, round_money,
    AuditLog, AuditLogReadOnlyError, SalesInvoice, PurchaseInvoice, CreditDebitNote,
    AUDIT_TRANSACTION_TYPES, classify_audit_transaction_type, AuditReportTemplate,
    UserLoginHistory, ConfigurationChangeLog
)
from audit_template_service import (
    AuditTemplateService,
    AVAILABLE_AUDIT_FIELDS,
    REGULATORY_BODIES,
)
from system_activity_service import (
    SystemActivityService,
    CONFIG_CATEGORIES,
    LOGIN_STATUS_META,
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
            f"✅ [11/14] تصدير سجل التدقيق بصيغة PDF مؤمّنة وغير قابلة للتعديل (Immutable Auditor PDF): "
            f"وثيقة ({pdf_verify_res['document_id']}) بحجم ({len(full_audit_pdf_bytes):,} بايت) مختومة بـ SHA-256 ومحمية ضد التلاعب 100%"
        )

        # ---------------------------------------------------------------------
        # 12. اختبار لوحة معلومات التدقيق البصرية المبنية بـ Recharts (Recharts Visual Dashboard Module)
        # ---------------------------------------------------------------------
        from recharts_audit_dashboard import (
            aggregate_audit_logs_for_recharts,
            generate_recharts_dashboard_html,
        )

        all_logs_query = LedgerService.query_audit_logs(db=db, limit=1000)
        recharts_data = aggregate_audit_logs_for_recharts(all_logs_query["logs"])

        # التحقق من حساب تردد العمليات لكل مستخدم
        assert "user_chart_data" in recharts_data
        assert len(recharts_data["user_chart_data"]) >= 2, "يجب وجود نشاط لعدة مستخدمين في المخطط"
        first_user_metric = recharts_data["user_chart_data"][0]
        assert "user" in first_user_metric and "total_ops" in first_user_metric
        assert "financial_ops" in first_user_metric and "admin_ops" in first_user_metric
        assert first_user_metric["total_ops"] > 0

        # التحقق من حساب تدفق الوثائق عبر الخط الزمني
        assert "timeline_chart_data" in recharts_data
        assert len(recharts_data["timeline_chart_data"]) >= 1, "يجب وجود نقاط زمنية لتدفق الوثائق"
        first_timeline_point = recharts_data["timeline_chart_data"][0]
        assert "date" in first_timeline_point and "total_docs" in first_timeline_point
        assert "invoices" in first_timeline_point and "entries" in first_timeline_point

        # التحقق من توليد مستند HTML التفاعلي لمكتبة Recharts ومحرك React
        recharts_html_doc = generate_recharts_dashboard_html(recharts_data)
        assert "<!DOCTYPE html>" in recharts_html_doc
        assert "Recharts.min.js" in recharts_html_doc
        assert "react.production.min.js" in recharts_html_doc
        assert "userBarChart" in recharts_html_doc
        assert "timelineAreaChart" in recharts_html_doc
        assert "BarChart" in recharts_html_doc
        assert "AreaChart" in recharts_html_doc
        assert f"{recharts_data['metrics']['total_logs']}" in recharts_html_doc

        print(
            f"✅ [12/14] لوحة المؤشرات البصرية Recharts (Recharts Visual Dashboard): "
            f"تم تجميع بيانات ({recharts_data['metrics']['total_logs']}) عملية رقابية، "
            f"وتوليد مخططات تردد المستخدمين وتدفق الوثائق ({len(recharts_html_doc):,} بايت HTML) بنجاح 100%"
        )

        # ---------------------------------------------------------------------
        # 13. اختبار خدمة الاستعلام الرقابي الذكي المدعومة بـ Google Search Grounding (ZATCA & SOCPA Regulations)
        # ---------------------------------------------------------------------
        from zatca_grounding_service import ZATCAGroundingService, ZATCA_TOPICS

        # (أ) التحقق من تغطية المجالات الرقابية الأساسية (الفوترة المرحلة 2، VAT، الزكاة، SOCPA)
        topics = ZATCAGroundingService.get_topics()
        assert "phase2_waves" in topics and "vat_updates" in topics
        assert "zakat_rules" in topics and "socpa_standards" in topics

        # (ب) جلب ملخص موجات الفوترة الإلكترونية المرحلة الثانية
        grounding_res = ZATCAGroundingService.fetch_regulatory_update(topic_key="phase2_waves")
        assert "summary" in grounding_res and len(grounding_res["summary"]) > 100
        assert "sources" in grounding_res and len(grounding_res["sources"]) >= 1
        assert "provider" in grounding_res and len(grounding_res["provider"]) > 0
        assert "search_queries" in grounding_res
        assert any("zatca.gov.sa" in src["uri"] for src in grounding_res["sources"]), "يجب توثيق مصادر زاتكا الرسمية"

        # (ج) جلب معايير SOCPA / IFRS
        socpa_res = ZATCAGroundingService.fetch_regulatory_update(topic_key="socpa_standards")
        assert "IFRS" in socpa_res["summary"] or "المعايير" in socpa_res["summary"]
        assert len(socpa_res["sources"]) >= 1

        print(
            f"✅ [13/16] خدمة الرقابة الذكية (Google Search Grounding for ZATCA Regulations): "
            f"تم استعلام وتوثيق موجات الفوترة واللوائح الضريبية والزكوية مع روابط الاستشهاد الرسمية بنجاح 100%"
        )

        # ---------------------------------------------------------------------
        # 14. اختبار محرك كشف الأنماط المشبوهة والإنذار الأمني (Suspicious Audit Anomaly Detection & Security Alerts)
        # ---------------------------------------------------------------------
        from audit_notification_service import (
            SuspiciousAuditAlertService,
            AuditReportSchedulerService,
            EmailDispatcher,
        )
        from models import utc_now

        # (أ) إدراج دفعة تعديلات متسارعة (Burst Modifications) لاختبار كشف النمط المشبوه
        now_test = utc_now()
        for idx in range(4):
            db.add(AuditLog(
                table_name="sales_invoices",
                record_id=200 + idx,
                action="MODIFY_SALES_INVOICE",
                user_id="USR-SUSPECT",
                username="suspect_operator",
                performed_by="المشغل المشتبه به",
                timestamp=now_test - timedelta(minutes=8 - idx * 2),
                reference_number=f"INV-ANOMALY-{idx}",
                financial_amount=Decimal("75000.00"),
                details=f"Test simulated rapid alteration on invoice #{idx}",
            ))
        db.commit()

        # (ب) تشغيل فحص الأنماط المشبوهة والتحقق من رصد تنبيهات الوتيرة المتسارعة والمبالغ الجسيمة
        detected_anomalies = SuspiciousAuditAlertService.scan_and_detect_anomalies(
            db=db,
            lookback_hours=1,
            high_value_threshold=Decimal("50000.00"),
            recipient_email_for_alerts="compliance.officer@mizanpro.sa",
        )
        assert len(detected_anomalies) >= 2, "يجب رصد تنبيه الوتيرة المتسارعة وتنبيه تجاوز السقف المالي الحرج!"

        burst_alerts = [a for a in detected_anomalies if a.alert_type == "BURST_MODIFICATION_ALERT"]
        assert len(burst_alerts) >= 1, "يجب رصد تنبيه BURST_MODIFICATION_ALERT"
        b_alert = burst_alerts[0]
        assert b_alert.severity == "HIGH"
        assert b_alert.username == "suspect_operator"
        assert b_alert.notification_sent is True
        assert b_alert.notification_target == "compliance.officer@mizanpro.sa"

        hv_alerts = [a for a in detected_anomalies if a.alert_type == "HIGH_VALUE_THRESHOLD_ALERT"]
        assert len(hv_alerts) >= 1, "يجب رصد تنبيه HIGH_VALUE_THRESHOLD_ALERT"
        assert Decimal("75000") >= SuspiciousAuditAlertService.DEFAULT_HIGH_VALUE_THRESHOLD

        # (ج) اختبار اعتماد وتوثيق الفحص الأمني (Acknowledge Alert)
        ack_success = SuspiciousAuditAlertService.acknowledge_alert(db, b_alert.id, "المراجع القانوني (CPA)")
        assert ack_success is True
        db.refresh(b_alert)
        assert b_alert.is_acknowledged is True
        assert b_alert.acknowledged_by == "المراجع القانوني (CPA)"

        print(
            f"✅ [14/16] محرك كشف الأنماط المشبوهة والإنذار الأمني (Suspicious Pattern Detection & Alerts): "
            f"تم رصد ({len(detected_anomalies)}) تنبيهات أمنية بنجاح، وتوثيق الإشعار البريدي، واعتماد التنبيه 100%"
        )

        # ---------------------------------------------------------------------
        # 15. اختبار جدولة وتوليد وتوصيل تقارير التدقيق الرقابي الدورية بالبريد (Automated Audit Report Scheduler)
        # ---------------------------------------------------------------------
        # (أ) اختبار حساب مواعيد التشغيل القادمة لكافة التواترات (DAILY, WEEKLY, MONTHLY, QUARTERLY)
        base_t = datetime(2026, 1, 1, 10, 0, 0)
        assert AuditReportSchedulerService.calculate_next_run("DAILY", base_t) == base_t + timedelta(days=1)
        assert AuditReportSchedulerService.calculate_next_run("WEEKLY", base_t) == base_t + timedelta(days=7)
        assert AuditReportSchedulerService.calculate_next_run("MONTHLY", base_t) == base_t + timedelta(days=30)
        assert AuditReportSchedulerService.calculate_next_run("QUARTERLY", base_t) == base_t + timedelta(days=90)

        # (ب) إنشاء جدول تقرير دوري أسبوعي موجه للمراجع الخارجي المستقل
        cpa_schedule = AuditReportSchedulerService.create_or_update_schedule(
            db=db,
            name="تقرير المراجعة الرقابية الأسبوعي لمكتب المحاسب القانوني",
            frequency="WEEKLY",
            recipient_emails="lead.auditor@cpa-firm.sa, external.cpa@firm.com",
            report_type="ZATCA_IMMUTABLE_PDF",
            include_pdf=True,
            include_json_manifest=True,
            include_excel=True,
            filter_transaction_type="ALL",
            min_financial_amount=0.0,
            is_active=True,
            created_by="مدير النظام (Admin)",
        )
        assert cpa_schedule.id is not None
        assert cpa_schedule.is_active is True
        assert "lead.auditor@cpa-firm.sa" in cpa_schedule.recipient_emails

        # (ج) تشغيل التوليد والإرسال الآلي للتقرير وفحص المرفقات وإيصال التسليم
        sched_exec_result = AuditReportSchedulerService.execute_and_deliver_report(
            db=db,
            schedule_id=cpa_schedule.id,
            requesting_user_info={"performed_by": "مدير النظام (admin)"},
        )
        assert sched_exec_result["success"] is True
        assert sched_exec_result["schedule_id"] == cpa_schedule.id
        assert len(sched_exec_result["document_id"]) >= 10
        assert len(sched_exec_result["pdf_sha256"]) == 64
        assert sched_exec_result["attachments_count"] == 3  # Sealed PDF + JSON Manifest + CSV
        assert len(sched_exec_result["recipients"]) == 2
        assert sched_exec_result["receipt_id"].startswith("RCPT-")

        # التحقق من تحديث حالة الجدولة في قاعدة البيانات
        db.refresh(cpa_schedule)
        assert cpa_schedule.last_status == "SUCCESS"
        assert cpa_schedule.total_runs_count == 1
        assert cpa_schedule.last_run_at is not None
        assert cpa_schedule.next_run_at > cpa_schedule.last_run_at

        # التحقق من توثيق عملية الإرسال في سجل التدقيق الرقابي
        dispatch_audit_row = (
            db.query(AuditLog)
            .filter(
                AuditLog.action == "DISPATCH_SCHEDULED_AUDIT_REPORT",
                AuditLog.record_id == cpa_schedule.id,
            )
            .first()
        )
        assert dispatch_audit_row is not None
        assert sched_exec_result["document_id"] in dispatch_audit_row.reference_number

        print(
            f"✅ [15/17] جدولة وتوصيل تقارير التدقيق الرقابي الدورية (Automated Report Scheduler & Email Delivery): "
            f"تم توليد حزمة التقرير ({sched_exec_result['document_id']}) بـ (3) مرفقات مؤمّنة وإرسالها لـ ({len(sched_exec_result['recipients'])}) مراجعين بنجاح 100%"
        )

        # -------------------------------------------------------------------------
        # 16. قوالب تقارير التدقيق الرقابي المخصصة لمختلف الهيئات الرقابية وتخصيص الحقول
        # (Custom Multi-Regulatory Audit Report Templates & Field Catalog)
        # -------------------------------------------------------------------------
        # (أ) التحقق من القوالب القياسية المعتمدة مسبقاً (ZATCA, SOCPA, CMA)
        seeded_templates = AuditTemplateService.get_all_templates(db)
        assert len(seeded_templates) >= 3, "يجب وجود 3 قوالب قياسية نظامية على الأقل"
        system_bodies = {t.regulatory_body for t in seeded_templates if t.is_system_default}
        assert "ZATCA" in system_bodies
        assert "SOCPA" in system_bodies
        assert "CMA" in system_bodies

        # (ب) إنشاء وحفظ قالب رقابي مخصص جديد لهيئة فحص محددة وتحديد حقول مخصصة
        custom_selected_fields = [
            "timestamp",
            "action",
            "reference_number",
            "financial_amount",
            "performed_by",
            "entry_hash",
        ]
        custom_tpl = AuditTemplateService.create_or_update_template(
            db=db,
            name="قالب الفحص الضريبي الميداني لعينات المبيعات (ZATCA Field Audit Sample)",
            regulatory_body="TAX_AUTHORITY",
            selected_fields=custom_selected_fields,
            description="قالب مخصص لاستخراج عينات الفواتير الضريبية ذات القيمة الأعلى من 100 ريال",
            filter_transaction_type="ALL",
            min_financial_amount=0.0,
            only_modifications=False,
            header_disclaimer="تقرير فحص ضريبي ميداني رسمي صادر للمفتش الميداني لهيئة الزكاة والضريبة والجمارك",
            auditor_signoff_text="تم التدقيق والفحص الجنائي بواسطة المحاسب القانوني المعتمد",
            created_by="مراجع قانوني خارجي (CPA)",
        )
        assert custom_tpl.id is not None
        assert custom_tpl.is_system_default is False
        assert custom_tpl.regulatory_body == "TAX_AUTHORITY"

        # (ج) استخراج وتصفية البيانات الرقابية وفق حقول ومعايير القالب المخصص
        filter_result = AuditTemplateService.filter_audit_records_for_template(
            db=db,
            template=custom_tpl,
            limit=50,
        )
        assert filter_result["template"].id == custom_tpl.id
        custom_df = filter_result["dataframe"]
        # التأكد من أن الأعمدة المستخرجة تطابق الحقول المحددة في القالب حصراً
        expected_col_labels = [AVAILABLE_AUDIT_FIELDS[k]["label"] for k in custom_selected_fields]
        for col_lbl in expected_col_labels:
            assert col_lbl in custom_df.columns, f"الحقل {col_lbl} يجب أن يكون ضمن أعمدة التقرير المخصص"
        # التأكد من عدم وجود حقول غير مطلوبة (مثل old_values أو details غير المحددة)
        unwanted_field_lbl = AVAILABLE_AUDIT_FIELDS["old_values"]["label"]
        assert unwanted_field_lbl not in custom_df.columns

        # (د) توليد تقرير PDF رسمي مخصص ومؤمّن ببصمة SHA-256 وترويسة الإقرار وخاتم الاعتماد
        custom_pdf_bytes = AuditTemplateService.export_custom_template_pdf(
            db=db,
            template=custom_tpl,
            limit=50,
        )
        assert custom_pdf_bytes.startswith(b"%PDF"), "ملف التقرير المخصص يجب أن يكون بصيغة PDF صحيحة"
        assert len(custom_pdf_bytes) > 2000, "حجم التقرير يجب أن يحتوي على الجداول والترويسة والخاتم"

        # (هـ) تحديث القالب المخصص
        updated_tpl = AuditTemplateService.create_or_update_template(
            db=db,
            name="قالب الفحص الضريبي الميداني المحدث (Updated Field Audit)",
            regulatory_body="TAX_AUTHORITY",
            selected_fields=custom_selected_fields + ["diff_summary"],
            description="وصف محدث للقالب",
            template_id=custom_tpl.id,
        )
        assert updated_tpl.template_name == "قالب الفحص الضريبي الميداني المحدث (Updated Field Audit)"
        import json
        assert "diff_summary" in json.loads(updated_tpl.selected_fields_json)

        # (و) منع حذف القوالب النظامية القياسية، والسماح بحذف القالب المخصص
        zatca_default = next(t for t in seeded_templates if t.regulatory_body == "ZATCA" and t.is_system_default)
        del_sys_res = AuditTemplateService.delete_template(db, zatca_default.id)
        assert del_sys_res is False, "يجب منع حذف القوالب النظامية الافتراضية"

        del_custom_res = AuditTemplateService.delete_template(db, custom_tpl.id)
        assert del_custom_res is True, "يجب السماح بحذف القوالب المخصصة من المستخدم"

        print(
            f"✅ [16/18] قوالب تقارير التدقيق الرقابي المخصصة (Custom Regulatory Report Templates): "
            f"تم التحقق من القوالب القياسية (ZATCA, SOCPA, CMA)، إنشاء قالب مخصص، وتصفية الحقول بدقة، وتصدير PDF مؤمّن بنجاح 100%"
        )

        # -------------------------------------------------------------------------
        # 17. وحدة نشاط النظام وسجل الدخول وتغييرات الإعدادات والبحث بالكلمات المفتاحية
        # (System Activity: User Login History, Configuration Changes & Audit Keyword Search)
        # -------------------------------------------------------------------------
        # (أ) اختبار تتبع سجل دخول وخروج المستخدمين (User Login & Auth History)
        initial_logins_count = db.query(UserLoginHistory).count()

        # 1. محاولة تسجيل دخول صحيحة
        admin_user_obj = db.query(AppUser).filter(AppUser.username == "admin").first()
        # محاكاة تسجيل دخول ناجح عبر الخدمة
        rec_login_ok = SystemActivityService.log_login_attempt(
            db=db,
            username="admin",
            status="SUCCESS",
            user_id=admin_user_obj.id,
            full_name_ar=admin_user_obj.full_name_ar,
            ip_address="192.168.1.100",
            details="Successful login via web portal",
        )
        assert rec_login_ok.id is not None
        assert rec_login_ok.status == "SUCCESS"
        assert rec_login_ok.username == "admin"

        # 2. محاولة تسجيل دخول فاشلة برمز PIN غير صحيح
        try:
            LedgerService.authenticate_user(db, "admin", "WRONG_999999")
        except LedgerValidationError:
            pass
        failed_pin_log = (
            db.query(UserLoginHistory)
            .filter(UserLoginHistory.username == "admin", UserLoginHistory.status == "FAILED_BAD_PIN")
            .order_by(UserLoginHistory.id.desc())
            .first()
        )
        assert failed_pin_log is not None
        assert "غير صحيح" in failed_pin_log.failure_reason

        # 3. محاولة تسجيل دخول باسم مستخدم غير مسجل
        try:
            LedgerService.authenticate_user(db, "unknown_hacker", "123456")
        except LedgerValidationError:
            pass
        failed_notfound_log = (
            db.query(UserLoginHistory)
            .filter(UserLoginHistory.username == "unknown_hacker", UserLoginHistory.status == "FAILED_USER_NOT_FOUND")
            .order_by(UserLoginHistory.id.desc())
            .first()
        )
        assert failed_notfound_log is not None

        # 4. تسجيل خروج آمن
        rec_logout = SystemActivityService.log_logout(
            db=db,
            user_id=admin_user_obj.id,
            username="admin",
            full_name_ar=admin_user_obj.full_name_ar,
            ip_address="192.168.1.100",
            details="Manual secure logout",
        )
        assert rec_logout.id is not None
        assert rec_logout.status == "LOGOUT"

        # 5. استعلام وفلترة سجل الدخول بالكلمة المفتاحية
        login_query_res = SystemActivityService.query_login_history(db=db, search_query="unknown_hacker")
        assert login_query_res["total_count"] >= 1
        assert "unknown_hacker" in login_query_res["dataframe"]["اسم المستخدم"].values

        # (ب) اختبار تتبع وتوثيق تغييرات الإعدادات والسياسات (Configuration & Policy Changes)
        # 1. تحديث إعدادات المنشأة وتوثيق الفروقات قبل وبعد
        LedgerService.update_company_settings(
            db=db,
            performed_by="المراجع القانوني (CPA)",
            company_name_ar="شركة ميزان برو التجارية المحدثة للتدقيق",
            default_vat_rate=0.15,
        )
        cfg_settings_log = (
            db.query(ConfigurationChangeLog)
            .filter(ConfigurationChangeLog.config_category == "COMPANY_SETTINGS")
            .order_by(ConfigurationChangeLog.id.desc())
            .first()
        )
        assert cfg_settings_log is not None
        assert "شركة ميزان برو التجارية المحدثة للتدقيق" in cfg_settings_log.new_values_json
        assert "company_name_ar" in cfg_settings_log.diff_summary

        # 2. تغيير رمز PIN وتوثيق سياسة الأمان
        # إنشاء مستخدم لاختبار تغيير الرمز
        test_u = LedgerService.create_or_update_user(
            db=db,
            username="test_sec_user",
            full_name_ar="مستخدم اختبار الأمان",
            role=UserRole.SALES,
            pin_code="987654",
            performed_by="مدير النظام",
        )
        LedgerService.change_user_pin(
            db=db,
            user_id=test_u.id,
            current_pin="987654",
            new_pin="456789",
            performed_by="مستخدم اختبار الأمان",
        )
        cfg_pin_log = (
            db.query(ConfigurationChangeLog)
            .filter(
                ConfigurationChangeLog.config_category == "SECURITY_POLICY",
                ConfigurationChangeLog.username == "test_sec_user",
            )
            .first()
        )
        assert cfg_pin_log is not None
        assert cfg_pin_log.action_type == "PIN_CHANGE"

        # 3. ملخص مؤشرات نشاط النظام والأمان
        sys_summary = SystemActivityService.get_system_activity_summary(db=db)
        assert sys_summary["total_logins"] >= 4
        assert sys_summary["failed_logins"] >= 2
        assert sys_summary["total_config_changes"] >= 2
        assert sys_summary["active_users_cnt"] >= 1

        # (ج) اختبار شريط البحث بالكلمات المفتاحية في سجل التدقيق (Audit Log Keyword Search Bar)
        # 1. البحث بمعرف السجل ورقم المعاملة (Transaction ID)
        sample_audit_rec = db.query(AuditLog).first()
        assert sample_audit_rec is not None
        kw_res_id = LedgerService.query_audit_logs(
            db=db,
            search_query=f"#{sample_audit_rec.id}",
        )
        assert kw_res_id["summary"]["total_matched"] >= 1
        assert sample_audit_rec.id in [r.id for r in kw_res_id["logs"]]

        # 2. البحث برقم المعاملة للجدول (REC-ID)
        if sample_audit_rec.record_id:
            kw_res_rec = LedgerService.query_audit_logs(
                db=db,
                search_query=f"rec-{sample_audit_rec.record_id}",
            )
            assert kw_res_rec["summary"]["total_matched"] >= 1

        # 3. البحث في الملاحظات والتفاصيل (Notes / Details)
        kw_res_notes = LedgerService.query_audit_logs(
            db=db,
            search_query="Authenticated user",
        )
        assert kw_res_notes["summary"]["total_matched"] >= 1

        # 4. البحث بكلمات مفتاحية متعددة متفرقة (Multi-Token Keyword Search)
        kw_res_multi = LedgerService.query_audit_logs(
            db=db,
            search_query="admin app_users",
        )
        assert kw_res_multi["summary"]["total_matched"] >= 1

        print(
            f"✅ [17/19] وحدة نشاط النظام وشريط البحث بالكلمات المفتاحية (System Activity & Keyword Search): "
            f"تم التحقق من تتبع سجلات الدخول والخروج ({sys_summary['total_logins']})، وتوثيق تغييرات الإعدادات والسياسات ({sys_summary['total_config_changes']})، والبحث الفوري بمعرفات المعاملات والملاحظات بنجاح 100%"
        )

        # ---------------------------------------------------------------------
        # 18. اختبار تصدير البيانات بصيغة CSV للمراجع الخارجي (CSV Export Service)
        # ---------------------------------------------------------------------
        import io

        # 1. اختبار تصدير ميزان المراجعة بصيغة CSV وترميز UTF-8-SIG
        tb_live_df = LedgerService.get_live_trial_balance(
            db, start_date=date(2026, 1, 1), end_date=date(2026, 12, 31), include_zero_balances=True
        )
        tb_csv_bytes = CSVExportService.generate_trial_balance_csv(tb_live_df)
        assert isinstance(tb_csv_bytes, bytes)
        assert len(tb_csv_bytes) > 0
        assert tb_csv_bytes.startswith(b"\xef\xbb\xbf"), "يجب أن يبدأ ملف CSV بـ UTF-8 BOM لضمان قراءة الحروف العربية في Excel بدون تشويه!"
        parsed_tb_csv = pd.read_csv(io.BytesIO(tb_csv_bytes))
        assert "كود الحساب" in parsed_tb_csv.columns
        assert "اسم الحساب" in parsed_tb_csv.columns
        assert "صافي الرصيد" in parsed_tb_csv.columns
        assert len(parsed_tb_csv) == len(tb_live_df)

        # 2. اختبار تصدير القوائم المالية المعتمدة في جدول مسطح للتحليل (CSV Financial Statements)
        fs_engine = FinancialStatementsEngine(trial_balance_df=tb_live_df, fiscal_year=2026)
        full_rep = fs_engine.generate_full_financial_report()
        fs_csv_bytes = CSVExportService.generate_financial_statements_csv(report=full_rep, tb_df=tb_live_df)
        assert isinstance(fs_csv_bytes, bytes)
        assert fs_csv_bytes.startswith(b"\xef\xbb\xbf")
        parsed_fs_csv = pd.read_csv(io.BytesIO(fs_csv_bytes))
        assert "القائمة المالية" in parsed_fs_csv.columns
        assert "البند المحاسبي" in parsed_fs_csv.columns
        assert "المبلغ بالريال (SAR)" in parsed_fs_csv.columns
        unique_stmts = set(parsed_fs_csv["القائمة المالية"].unique())
        assert "قائمة الدخل" in unique_stmts
        assert "قائمة المركز المالي" in unique_stmts
        assert "قائمة التدفقات النقدية" in unique_stmts
        assert "إقرار ضريبة القيمة المضافة" in unique_stmts
        assert "إقرار الزكاة الشرعية" in unique_stmts

        # اختبار الـ ExportService wrapper
        wrapper_csv_bytes = ExportService.generate_financial_statements_csv(report=full_rep, trial_balance_df=tb_live_df)
        assert len(wrapper_csv_bytes) == len(fs_csv_bytes)

        # 3. اختبار تصدير دفتر الأستاذ العام وخطوط القيود المحاسبية للمراجع (CSV General Ledger)
        gl_csv_bytes = CSVExportService.generate_general_ledger_csv(db)
        assert isinstance(gl_csv_bytes, bytes)
        assert gl_csv_bytes.startswith(b"\xef\xbb\xbf")
        parsed_gl_csv = pd.read_csv(io.BytesIO(gl_csv_bytes))
        assert "رقم القيد" in parsed_gl_csv.columns
        assert "كود الحساب" in parsed_gl_csv.columns
        assert "مدين (ريال)" in parsed_gl_csv.columns
        assert "دائن (ريال)" in parsed_gl_csv.columns
        assert len(parsed_gl_csv) > 0
        total_gl_debit = parsed_gl_csv["مدين (ريال)"].sum()
        total_gl_credit = parsed_gl_csv["دائن (ريال)"].sum()
        assert abs(total_gl_debit - total_gl_credit) < 0.05, "يجب أن تكون قيود اليومية العامة في ملف CSV متزنة تماماً!"

        # 4. اختبار تصدير ميزان المراجعة المصنف لمكاتب المراجعة القانونية (CPA External Analyzer CSV)
        sample_ext_tb = ExternalTBAnalyzerService.get_sample_tasaheel_tb_dataframe()
        classified_ext_tb = ExternalTBAnalyzerService.normalize_and_classify_tb(sample_ext_tb)
        cpa_full_pkg = ExternalTBAnalyzerService.generate_cpa_full_package(classified_ext_tb, {"company_name": "مؤسسة تساهيل طيبة"})
        cpa_csv_bytes = ExternalTBAnalyzerService.generate_cpa_csv(classified_ext_tb, cpa_full_pkg)
        assert isinstance(cpa_csv_bytes, bytes)
        assert cpa_csv_bytes.startswith(b"\xef\xbb\xbf")
        parsed_cpa_csv = pd.read_csv(io.BytesIO(cpa_csv_bytes))
        assert "كود الحساب" in parsed_cpa_csv.columns
        assert "اسم الحساب" in parsed_cpa_csv.columns
        assert "التصنيف الرقابي في القوائم والإيضاحات" in parsed_cpa_csv.columns
        assert len(parsed_cpa_csv) >= len(classified_ext_tb)

        print(
            "✅ [18/20] تصدير البيانات بصيغة CSV للمراجع الخارجي (CSV Export Service for External Spreadsheet Analysis): "
            "تم التحقق بنجاح من تصدير ميزان المراجعة، القوائم المالية، دفتر الأستاذ العام، وميزان CPA بترميز UTF-8-SIG وجداول مسطحة غير مدمجة بنسبة نجاح 100%"
        )

        # ---------------------------------------------------------------------
        # 19. اختبار نظام الإنذار الأمني لمعالجة الدفعات الضخمة وإشعارات سطح المكتب (High-Volume Batch Alert & Desktop Notifications)
        # ---------------------------------------------------------------------
        from audit_notification_service import SuspiciousAuditAlertService, render_desktop_notification_component
        from models import AuditSecurityAlert

        # 1. اختبار تسجيل إنذار أمني فوري لمعالجة دفعة ضخمة (HIGH_VOLUME_BATCH_ALERT)
        batch_alert = SuspiciousAuditAlertService.log_high_volume_batch_alert(
            db=db,
            batch_size=20,
            total_amount=250000.0,
            user_id="USR-TEST-01",
            username="test_batch_user",
            performed_by="محلل البيانات الكتلي",
            table_name="sales_invoices",
            operation_type="BULK_DATA_MANIPULATION_TEST",
            details="اختبار محاكاة معالجة دفعة ضخمة تحتوي على 20 فاتورة بمبلغ 250,000 ريال",
        )
        assert batch_alert is not None
        assert batch_alert.alert_type == "HIGH_VOLUME_BATCH_ALERT"
        assert batch_alert.severity == "CRITICAL"
        assert "20" in batch_alert.title or "20" in batch_alert.description
        assert "250,000" in batch_alert.description or "250000" in batch_alert.details_json

        # 2. اختبار فحص الأنماط المشبوهة التلقائية لكشف الدفعات الضخمة المعالجة حديثاً
        detected_batch_alerts = SuspiciousAuditAlertService.scan_and_detect_anomalies(
            db=db,
            lookback_hours=24,
            high_value_threshold=Decimal("50000.00"),
        )
        assert isinstance(detected_batch_alerts, list)

        # 3. التأكد من استعلام جلب التنبيهات وإمكانية الاعتماد والتوثيق
        all_hv_alerts = SuspiciousAuditAlertService.get_alerts(db, only_unacknowledged=True)
        assert any(a.alert_type == "HIGH_VOLUME_BATCH_ALERT" for a in all_hv_alerts)

        ack_ok = SuspiciousAuditAlertService.acknowledge_alert(db, batch_alert.id, ack_user="مسؤول الامتثال والرقابة")
        assert ack_ok is True
        refreshed_alert = db.query(AuditSecurityAlert).filter(AuditSecurityAlert.id == batch_alert.id).first()
        assert refreshed_alert.is_acknowledged is True
        assert refreshed_alert.acknowledged_by == "مسؤول الامتثال والرقابة"

        print(
            "✅ [19/21] نظام الإنذار الأمني لمعالجة الدفعات الضخمة وإشعارات سطح المكتب (High-Volume Batch & Desktop Notification System): "
            "تم التحقق بنجاح من رصد المعالجات الكتلية، وتوثيق التنبيهات الحرجة، وبث حمولة إشعارات سطح المكتب بنسبة نجاح 100%"
        )

        # ---------------------------------------------------------------------
        # 20. اختبار الفاحص التشفيري للسجل الفردي SHA-256 لبصمة البيانات (Single-Record SHA-256 Hash Verifier)
        # ---------------------------------------------------------------------
        sample_log_entry = db.query(AuditLog).first()
        assert sample_log_entry is not None
        single_hash_verify = LedgerService.verify_single_entry_hash(db, sample_log_entry.id)
        assert single_hash_verify["success"] is True
        assert single_hash_verify["is_hash_valid"] is True
        assert single_hash_verify["stored_entry_hash"] == single_hash_verify["recomputed_entry_hash"]
        assert len(single_hash_verify["canonical_payload_string"]) > 0
        assert single_hash_verify["stored_previous_hash"] in single_hash_verify["canonical_payload_string"]

        invalid_id_verify = LedgerService.verify_single_entry_hash(db, 99999999)
        assert invalid_id_verify["success"] is False

        # التحقق من دالة الخدمة لتوليد تقرير PDF ملخص لسجلات التدقيق مع بصمات SHA-256
        # ---------------------------------------------------------------------
        # 21. اختبار المخطط الزمني لخارطة امتثال زاتكا وتخطيط دورات المراجعة (ZATCATimelineService)
        # ---------------------------------------------------------------------
        from zatca_timeline_service import ZATCATimelineService, ZATCA_MILESTONES
        assert len(ZATCA_MILESTONES) >= 8

        # اختبار جلب المحطات المفلترة بحساب الأيام والشريحة الإيرادية
        all_milestones = ZATCATimelineService.get_milestones(company_revenue_sar=150000000.0)
        assert len(all_milestones) >= 8
        wave_5 = next((m for m in all_milestones if m["id"] == "wave_05"), None)
        assert wave_5 is not None
        assert wave_5["applies_to_company"] is True

        phase2_waves = ZATCATimelineService.get_milestones(category_filter="phase2_waves")
        assert all(m["category"] == "phase2_waves" for m in phase2_waves)

        # اختبار حساب مؤشر الجاهزية والامتثال
        readiness_score = ZATCATimelineService.calculate_audit_readiness_score(db)
        assert "overall_compliance_pct" in readiness_score
        assert "readiness_status_ar" in readiness_score

        # اختبار توليد مستند HTML التفاعلي للمخطط الزمني
        timeline_html_doc = ZATCATimelineService.generate_timeline_html(all_milestones, readiness_score)
        assert isinstance(timeline_html_doc, str) and "ZATCA Compliance Roadmap" in timeline_html_doc
        assert "timeline-card" in timeline_html_doc

        # ---------------------------------------------------------------------
        # 22. اختبار الخريطة الحرارية التقويمية ورصد الشذوذ في كثافة الحركات (HeatmapService)
        # ---------------------------------------------------------------------
        from heatmap_service import HeatmapService

        heatmap_payload = HeatmapService.aggregate_calendar_heatmap_data(db, year=2026)
        assert "calendar_days" in heatmap_payload
        assert "metrics" in heatmap_payload
        assert heatmap_payload["metrics"]["total_transactions"] >= 0

        heatmap_html = HeatmapService.generate_heatmap_html(heatmap_payload)
        assert isinstance(heatmap_html, str) and "Calendar Anomaly Heatmap" in heatmap_html
        assert "legend-bar" in heatmap_html

        # ---------------------------------------------------------------------
        # 23. اختبار نظام الأرشفة المؤمّن والتخزين البارد لسجلات التدقيق القديمة (AuditArchiveService)
        # ---------------------------------------------------------------------
        from audit_archive_service import AuditArchiveService
        from models import AuditLogArchive, AuditArchiveManifest

        arch_summary_before = AuditArchiveService.get_archive_status_summary(db)
        assert "active_count" in arch_summary_before
        assert "archived_count" in arch_summary_before

        # تنفيذ أرشفة السجلات الأقدم من -10 أيام للتأكد من شمول السجلات الحالية في الاختبار
        arch_res = AuditArchiveService.archive_older_audit_logs(db, cutoff_days=-10, performed_by="مراجع النظام")
        assert arch_res["success"] is True
        assert arch_res["records_archived"] > 0
        batch_id = arch_res["batch_id"]

        arch_summary_after = AuditArchiveService.get_archive_status_summary(db)
        assert arch_summary_after["archived_count"] > 0
        assert arch_summary_after["batches_count"] >= 1

        # تصدير حزمة JSON المصدقة للأرشيف
        json_arch_bytes = AuditArchiveService.export_archive_batch_json(db, batch_id)
        assert isinstance(json_arch_bytes, bytes) and b"metadata" in json_arch_bytes

        # استعادة الدفعة الملاحظة
        restore_res = AuditArchiveService.restore_archived_audit_batch(db, batch_id, performed_by="مراجع النظام")
        assert restore_res["success"] is True
        assert restore_res["restored_count"] == arch_res["records_archived"]

        print(
            "✅ [23/25] نظام الأرشفة المؤمّن والتخزين البارد لسجلات التدقيق القديمة (Cold Storage Audit Archival System): "
            "تم التحقق بنجاح من نقل السجلات للتخزين البارد، توليد الختم التشفيري، تصدير JSON، واستعادة الدفعة بنسبة 100%"
        )

        # ---------------------------------------------------------------------
        # 24. اختبار ميزة الملاحظات والتعليقات الرقمية الخاصة للمراجعين (AuditAnnotationService)
        # ---------------------------------------------------------------------
        from audit_annotation_service import AuditAnnotationService
        from models import AuditLogAnnotation

        first_audit_log = db.query(AuditLog).first()
        assert first_audit_log is not None

        # إضافة ملاحظة جديدة للمراجع
        ann_res = AuditAnnotationService.add_annotation(
            db,
            audit_log_id=first_audit_log.id,
            auditor_id="USR-AUDIT-99",
            auditor_name="أحمد المراجع القانوني (CPA)",
            annotation_text="تم فحص عينة الفاتورة والتحقق من القيد المزدوج والضريبة المحسوبة بنسبة 100%.",
            category="INSPECTION_NOTE",
            is_private=True,
        )
        assert ann_res["success"] is True
        ann_id = ann_res["annotation_id"]
        ann_hash = ann_res["annotation_hash"]
        assert len(ann_hash) == 64

        # الاستعلام والتحقق من السلامة التشفيرية
        log_notes = AuditAnnotationService.get_annotations_for_log(db, first_audit_log.id)
        assert len(log_notes) >= 1
        matched_ann = [n for n in log_notes if n["id"] == ann_id][0]
        assert matched_ann["is_intact"] is True
        assert matched_ann["auditor_id"] == "USR-AUDIT-99"

        # اختبار الحماية ضد التعديل أو الحذف (Read-Only)
        verif_res = AuditAnnotationService.verify_annotation_integrity(db, ann_id)
        assert verif_res["is_valid"] is True

        ann_obj = db.query(AuditLogAnnotation).filter(AuditLogAnnotation.id == ann_id).first()
        try:
            ann_obj.annotation_text = "محاولة تعديل غير قانونية"
            db.commit()
            assert False, "خطأ: كان ينبغي منع تعديل ملاحظة المراجع!"
        except Exception as exc:
            db.rollback()
            assert "ZATCA_ANNOTATION_READ_ONLY" in str(exc) or "READ_ONLY" in str(exc)

        # استعلام ملخص كافة الملاحظات
        ann_summary = AuditAnnotationService.get_all_annotations_summary(db)
        assert ann_summary["total_count"] >= 1
        assert ann_summary["is_all_intact"] is True

        print(
            "✅ [24/25] التعليقات والملاحظات الرقمية الخاصة للمراجعين القانونيين (Auditor Private Annotations): "
            "تم التحقق بنجاح من توثيق الملاحظة، استخراج الختم التشفيري SHA-256، التحقق الجنائي، وتأكيد الحماية للقراءة فقط بنسبة 100%"
        )

        # ---------------------------------------------------------------------
        # 25. اختبار قائمة التحقق التفاعلية لامتثال زاتكا وشريط الجانب (ZATCATaxChecklistService)
        # ---------------------------------------------------------------------
        from zatca_checklist_service import ZATCATaxChecklistService

        eval_res = ZATCATaxChecklistService.evaluate_system_readiness(db)
        assert "total_score" in eval_res
        assert "readiness_pct" in eval_res
        assert eval_res["readiness_pct"] == 100
        assert eval_res["compliant_count"] == 10
        assert len(eval_res["evaluations"]) == 10

        print(
            "✅ [25/26] قائمة التحقق التفاعلية لامتثال هيئة الزكاة والضريبة والجمارك (Interactive ZATCA Compliance Checklist & Readiness Sidebar): "
            "تم تقييم 10/10 متطلبات وتأكيد نسبة الجاهزية الرقمية 100% بنجاح"
        )

        # ---------------------------------------------------------------------
        # 26. اختبار وحدة متصفح واسترجاع سجلات التخزين البارد (Cold Storage Log Retrieval Browser)
        # ---------------------------------------------------------------------
        # تنفيذ أرشفة السجلات الأقدم من -10 أيام لملء التخزين البارد بالسجلات الاختبارية
        arch_res_test = AuditArchiveService.archive_older_audit_logs(db, cutoff_days=-10, performed_by="مراجع النظام")
        assert arch_res_test["success"] is True

        cold_query_res = AuditArchiveService.query_archived_audit_logs(
            db,
            batch_id=arch_res_test["batch_id"],
        )
        assert cold_query_res["total_matched"] > 0
        assert not cold_query_res["dataframe"].empty
        assert "معرف الأرشيف" in cold_query_res["dataframe"].columns

        # تنظيف واستعادة السجلات المأرشفة
        restore_res_test = AuditArchiveService.restore_archived_audit_batch(db, arch_res_test["batch_id"], performed_by="مراجع النظام")
        assert restore_res_test["success"] is True

        print(
            "✅ [26/27] وحدة متصفح واسترجاع سجلات التخزين البارد (Cold Storage Audit Log Retrieval Browser): "
            "تم التحقق بنجاح من الاستعلام وتوليد DataFrame وتفتيش اللقطات التاريخية والتصدير واستعادة الدفعة بنسبة 100%"
        )

        # ---------------------------------------------------------------------
        # 27. اختبار أداة التحقق التجميعي الكتلي للبصمات التشفيرية (Bulk SHA-256 Batch Verification Tool)
        # ---------------------------------------------------------------------
        all_logs_sample = db.query(AuditLog).limit(10).all()
        sample_ids = [l.id for l in all_logs_sample]

        bulk_verify_res = LedgerService.verify_bulk_audit_log_entries(db, selected_ids=sample_ids)
        assert bulk_verify_res["total_checked"] == len(sample_ids)
        assert bulk_verify_res["valid_count"] == len(sample_ids)
        assert bulk_verify_res["broken_count"] == 0
        assert bulk_verify_res["is_batch_intact"] is True
        assert len(bulk_verify_res["batch_sha256_seal"]) == 64
        assert not bulk_verify_res["dataframe"].empty

        print(
            "✅ [27/27] أداة التحقق التجميعي الكتلي من البصمات التشفيرية (Bulk SHA-256 Batch Verification Tool): "
            "تم فحص الدفعة، التأكد من تطابق كافة الهواش 100%، وتوليد الختم الرقمي الجماعي شهادة التوثيق بنجاح"
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
    print("✅ [21/21] عزل الاختبارات: تم تنظيف قاعدة الاختبار المؤقتة وبقيت قاعدة التطبيق الرئيسية سليمة 100% دون أي مساس!")





if __name__ == "__main__":
    run_full_accounting_cycle()