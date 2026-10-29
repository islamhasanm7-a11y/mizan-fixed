"""
MizanPro - Full Accounting, Inventory (WAC), Returns, Vouchers, Fixed Assets, Payroll, Aging, Bank Rec, Custom RBAC Permissions, CPA Analyzer & ZATCA Test
النظام المالي المتكامل - ميزان برو
ملف اختبار ومحاكاة الدورة الشاملة للنظام شاملة منظومة التخصيص الحر لصلاحيات المستخدمين (الإصدار المؤسسي المتكامل)
"""

from datetime import date
import pandas as pd
from database import SessionLocal, Base, engine
from seed_coa import init_database_and_seed
from ledger_service import LedgerService
from financial_engine import FinancialStatementsEngine
from export_service import ExcelExportService, PrintTemplateService
from tb_analyzer_service import ExternalTBAnalyzerService
from models import (
    PaymentMethod, InvoiceType, NoteType,
    VoucherType, VoucherPartyType, Product,
    UserRole, SYSTEM_MODULES, SYSTEM_ACTIONS, get_default_permissions_for_role
)


def run_full_accounting_cycle():
    Base.metadata.drop_all(bind=engine)
    init_database_and_seed()
    db = SessionLocal()
    print("\n" + "=" * 80)
    print("🚀 بدء محاكاة واختبار الدورة الشاملة لنظام MizanPro ERP & CPA Audit Suite")
    print("=" * 80)

    try:
        settings = LedgerService.get_company_settings(db)
        prod1 = db.query(Product).filter(Product.code == "PRD-001").first()
        prod2 = db.query(Product).filter(Product.code == "PRD-002").first()

        # 0. اختبار منظومة التخصيص الحر لصلاحيات المستخدمين وقوالب الأدوار
        custom_perms = get_default_permissions_for_role(UserRole.CUSTOM)
        custom_perms["mod_sales"] = True
        custom_perms["mod_treasury"] = True
        custom_perms["act_create_sales"] = True
        custom_perms["act_create_vouchers"] = True

        custom_user = LedgerService.create_or_update_user(
            db=db,
            username="branch_cashier",
            full_name_ar="خالد العتيبي - محاسب مبيعات وصندوق",
            role=UserRole.CUSTOM,
            pin_code="5555",
            job_title="محاسب فرع وصندوق",
            permissions_dict=custom_perms,
            max_discount_pct=12.0,
            is_active=True
        )
        assert custom_user.has_permission("act_create_sales") is True
        assert custom_user.has_permission("act_close_year") is False
        assert SYSTEM_MODULES["mod_sales"] in custom_user.get_allowed_menu_options()
        print(f"✅ منظومة التخصيص الحر للصلاحيات: المستخدم ({custom_user.username}) | الشاشات المتاحة={len(custom_user.get_allowed_menu_options())}")

        # 0.5 اختبار جلب حسابات الخزينة والبنوك الديناميكية وتحديث بيانات السجلات الرئيسية مع التوثيق الرقابي
        treasury_accs = LedgerService.get_treasury_and_bank_accounts(db)
        cash_accs = [a for a in treasury_accs if a.code.startswith("1101")]
        bank_accs = [a for a in treasury_accs if a.code.startswith("1102")]
        assert len(cash_accs) >= 1
        assert len(bank_accs) >= 2
        updated_cust = LedgerService.create_or_update_customer(
            db=db, name_ar="شركة الأمل التجارية", vat_number="300112233445563",
            credit_limit=180000.0, is_active=True, performed_by="خالد العتيبي (branch_cashier)"
        )
        assert updated_cust.credit_limit == 180000.0
        print(f"✅ حسابات النقدية والبنوك الديناميكية: صناديق={len(cash_accs)} | بنوك={len(bank_accs)}")

        # 1. المشتريات والمبيعات والمرتجعات متعددة الأصناف (إشعار دائن ومدين) والسندات
        pur_inv = LedgerService.create_purchase_invoice(
            db=db, supplier_name="شركة التوريدات الهندسية العالمية",
            supplier_invoice_number="SUP-2026-901", invoice_date=date(2026, 2, 1),
            payment_method=PaymentMethod.CREDIT,
            items_data=[
                {"product_id": prod1.id, "item_name": prod1.name_ar, "quantity": 10.0, "unit_price": 200.0, "discount": 0.0, "tax_rate": 0.15},
                {"product_id": prod2.id, "item_name": prod2.name_ar, "quantity": 5.0, "unit_price": 400.0, "discount": 0.0, "tax_rate": 0.15},
            ],
            performed_by="خالد العتيبي (branch_cashier)"
        )
        sales_inv = LedgerService.create_sales_invoice(
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
        dn_note = LedgerService.create_credit_debit_note(
            db=db, note_type=NoteType.DEBIT_NOTE, party_name="شركة التوريدات الهندسية العالمية",
            original_invoice_number=pur_inv.invoice_number, purchase_invoice_id=pur_inv.id,
            note_date=date(2026, 2, 10),
            payment_method=PaymentMethod.CREDIT, reason="مرتجع بضاعة للمورد متعدد الأصناف",
            items_data=[
                {"product_id": prod1.id, "item_name": prod1.name_ar, "quantity": 2.0, "unit_price": 200.0, "cost_price": prod1.cost_price, "tax_rate": 0.15},
                {"product_id": prod2.id, "item_name": prod2.name_ar, "quantity": 1.0, "unit_price": 400.0, "cost_price": prod2.cost_price, "tax_rate": 0.15},
            ],
            performed_by="خالد العتيبي (branch_cashier)"
        )
        print(f"✅ الفواتير والإشعارات الضريبية متعددة الأصناف: مبيعات={sales_inv.invoice_number} | مشتريات={pur_inv.invoice_number} | إشعار مدين={dn_note.note_number}")

        # 1.5 اختبار كشف حساب العميل/المورد المفلتر بالتاريخ مع الرصيد المرحل لما قبل الفترة
        stmt_filtered = LedgerService.get_party_statement(
            db=db, party_type="SUPPLIER", party_id=pur_inv.supplier_id,
            start_date=date(2026, 2, 1), end_date=date(2026, 2, 28)
        )
        assert "opening_balance" in stmt_filtered
        assert len(stmt_filtered["statement"]) >= 2
        print(f"✅ كشف حساب المورد المفلتر زمنياً: عدد السطور={len(stmt_filtered['statement'])} | الرصيد الافتتاحي={stmt_filtered['opening_balance']:,.2f} | الرصيد النهائي={stmt_filtered['net_balance']:,.2f}")

        # 2. اختبار محرك إهلاك الأصول الثابتة الآلي
        dep_je = LedgerService.run_period_depreciation(db=db, dep_date=date(2026, 2, 28), months=1, performed_by="المدير المالي")
        print(f"✅ قيد إهلاك الأصول الثابتة الآلي: {dep_je.entry_number} بمبلغ {dep_je.total_debit:,.2f} ريال")

        # 3. اختبار محرك مسير الرواتب ومكافأة نهاية الخدمة مع اختيار الحساب البنكي
        pr_run = LedgerService.process_monthly_payroll(
            db=db, period_month="2026-02", payment_date=date(2026, 2, 28),
            treasury_account_code="110201", performed_by="المدير المالي"
        )
        print(f"✅ مسير الرواتب الشهري: {pr_run.payroll_number} | صافي المنصرف={pr_run.net_paid_salaries:,.2f} | مخصص نهاية الخدمة={pr_run.total_eos_accrual:,.2f}")

        # 4. اختبار تقرير أعمار الديون والتسوية البنكية وربحية مراكز التكلفة المفلترة زمنياً
        aging_df = LedgerService.get_aging_report(db, party_type="CUSTOMER")
        rec_data = LedgerService.reconcile_bank_statement(db, bank_account_code="110201")
        cc_df = LedgerService.get_cost_centers_pnl(db, start_date=date(2026, 1, 1), end_date=date(2026, 12, 31))
        print(f"✅ تقرير أعمار الديون: {len(aging_df)} عميل | مذكرة التسوية البنكية: رصيد الدفاتر={rec_data['book_closing_balance']:,.2f} | مراكز التكلفة={len(cc_df)}")

        # 5. اختبار محلل ميزان المراجعة الخارجي (حالة التأسيس + حالة الميزان متعدد السنوات مع أرصدة أول المدة)
        sample_tb = ExternalTBAnalyzerService.get_sample_tasaheel_tb_dataframe()
        c_df = ExternalTBAnalyzerService.normalize_and_classify_tb(sample_tb)
        cpa_pkg = ExternalTBAnalyzerService.generate_cpa_full_package(c_df, {
            "company_name": "مؤسسة تساهيل طيبة التجارية",
            "include_auditor_report": True,
            "opinion_type": "GOING_CONCERN"
        })
        assert abs((cpa_pkg["cash_flow_statement"]["opening_cash"] + cpa_pkg["cash_flow_statement"]["net_cash_change"]) - cpa_pkg["cash_flow_statement"]["closing_cash"]) < 0.01

        # اختبار ميزان مراجعة متعدد السنوات ذي مركز مالي افتتاحي متوازن (IAS 7 Working Capital Deltas)
        multi_year_tb = pd.DataFrame([
            {"كود الحساب": "1101", "اسم الحساب": "النقدية والبنوك", "مدين أول المدة": 100000.0, "دائن أول المدة": 0.0, "حركة مدين": 80000.0, "حركة دائن": 30000.0, "مدين آخر المدة": 150000.0, "دائن آخر المدة": 0.0},
            {"كود الحساب": "1103", "اسم الحساب": "العملاء والمدينون", "مدين أول المدة": 40000.0, "دائن أول المدة": 0.0, "حركة مدين": 60000.0, "حركة دائن": 45000.0, "مدين آخر المدة": 55000.0, "دائن آخر المدة": 0.0},
            {"كود الحساب": "1201", "اسم الحساب": "الأصول الثابتة بالصافي", "مدين أول المدة": 60000.0, "دائن أول المدة": 0.0, "حركة مدين": 20000.0, "حركة دائن": 5000.0, "مدين آخر المدة": 75000.0, "دائن آخر المدة": 0.0},
            {"كود الحساب": "2101", "اسم الحساب": "الموردون والدائنون", "مدين أول المدة": 0.0, "دائن أول المدة": 30000.0, "حركة مدين": 10000.0, "حركة دائن": 25000.0, "مدين آخر المدة": 0.0, "دائن آخر المدة": 45000.0},
            {"كود الحساب": "3101", "اسم الحساب": "رأس المال", "مدين أول المدة": 0.0, "دائن أول المدة": 170000.0, "حركة مدين": 0.0, "حركة دائن": 0.0, "مدين آخر المدة": 0.0, "دائن آخر المدة": 170000.0},
            {"كود الحساب": "4101", "اسم الحساب": "إيرادات المبيعات", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 0.0, "حركة دائن": 100000.0, "مدين آخر المدة": 0.0, "دائن آخر المدة": 100000.0},
            {"كود الحساب": "5201", "اسم الحساب": "مصروفات عمومية وإدارية", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 30000.0, "حركة دائن": 0.0, "مدين آخر المدة": 30000.0, "دائن آخر المدة": 0.0},
            {"كود الحساب": "5207", "اسم الحساب": "مصروف إهلاك الأصول الثابتة", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 5000.0, "حركة دائن": 0.0, "مدين آخر المدة": 5000.0, "دائن آخر المدة": 0.0},
        ])
        my_cdf = ExternalTBAnalyzerService.normalize_and_classify_tb(multi_year_tb)
        my_pkg = ExternalTBAnalyzerService.generate_cpa_full_package(my_cdf)
        assert my_pkg["cash_flow_statement"]["opening_cash"] == 100000.0
        assert my_pkg["cash_flow_statement"]["closing_cash"] == 150000.0
        assert my_pkg["cash_flow_statement"]["wc_changes"]["trade_receivables"] == -15000.0  # -(55,000 - 40,000)
        assert my_pkg["cash_flow_statement"]["wc_changes"]["trade_payables"] == 15000.0      # +(45,000 - 30,000)
        assert abs((my_pkg["cash_flow_statement"]["opening_cash"] + my_pkg["cash_flow_statement"]["net_cash_change"]) - my_pkg["cash_flow_statement"]["closing_cash"]) < 0.01

        word_bytes = ExternalTBAnalyzerService.generate_cpa_word_doc(cpa_pkg)
        assert len(word_bytes) > 15000
        print(f"✅ تقرير مكتب المحاسبة المعتمد (شامل مطابقة IAS 7 متعددة السنوات + Word .doc): حجم الملف={len(word_bytes)} بايت")

        # 6. اختبار التقرير التنفيذي ذي الـ 15 صفحة Excel
        excel_bytes = ExcelExportService.generate_master_excel_report(db, fiscal_year=2026)
        assert len(excel_bytes.getvalue()) > 8000
        print("✅ تم توليد مصنف الإكسيل التنفيذي الشامل (15 صفحة) بنجاح تام!")

        # 7. اختبار خدمة التكامل السحابي مع Google Drive (OAuth 2.0 + Firebase Auth)
        from google_drive_service import GoogleDriveService, SCOPES
        fb_cfg = GoogleDriveService.load_firebase_config()
        assert fb_cfg.get("projectId") == "symmetric-physics-pl37k"
        assert len(SCOPES) == 13
        gdrive_html = GoogleDriveService.render_google_drive_workspace_html()
        assert "gsi-material-button" in gdrive_html
        assert "confirmModalBackdrop" in gdrive_html
        print(f"✅ خدمة التكامل السحابي مع Google Drive: المشروع ({fb_cfg.get('projectId')}) | النطاقات المفعلة={len(SCOPES)} نطاق")

    finally:
        db.close()
        # إعادة قاعدة البيانات لحالتها القياسية الافتراضية النظيفة للتطبيق
        Base.metadata.drop_all(bind=engine)
        init_database_and_seed()


if __name__ == "__main__":
    run_full_accounting_cycle()