"""
MizanPro - Full Accounting, Inventory (WAC), Returns, Vouchers, Fixed Assets, Payroll, Aging, Bank Rec, Custom RBAC Permissions, CPA Analyzer & ZATCA Test
النظام المالي المتكامل - ميزان برو
ملف اختبار ومحاكاة الدورة الشاملة للنظام شاملة منظومة التخصيص الحر لصلاحيات المستخدمين (الإصدار المؤسسي المتكامل)
"""

from datetime import date
from database import SessionLocal
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
    init_database_and_seed()
    db = SessionLocal()
    print("\n" + "=" * 80)
    print("🚀 بدء محاكاة واختبار الدورة الشاملة لنظام MizanPro ERP & CPA Audit Suite")
    print("=" * 80)

    try:
        settings = LedgerService.get_company_settings(db)
        prod1 = db.query(Product).filter(Product.code == "PRD-001").first()

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

        # 1. المشتريات والمبيعات والمرتجعات (إشعار دائن ومدين) والسندات
        pur_inv = LedgerService.create_purchase_invoice(
            db=db, supplier_name="شركة التوريدات الهندسية العالمية",
            supplier_invoice_number="SUP-2026-901", invoice_date=date(2026, 2, 1),
            payment_method=PaymentMethod.CREDIT,
            items_data=[{"product_id": prod1.id, "item_name": prod1.name_ar, "quantity": 10.0, "unit_price": 200.0, "discount": 0.0, "tax_rate": 0.15}]
        )
        sales_inv = LedgerService.create_sales_invoice(
            db=db, customer_name="شركة الأمل التجارية", customer_vat_number="300112233445563",
            invoice_date=date(2026, 2, 5), payment_method=PaymentMethod.CREDIT,
            invoice_type=InvoiceType.STANDARD,
            items_data=[{"product_id": prod1.id, "item_name": prod1.name_ar, "quantity": 5.0, "unit_price": 300.0, "cost_price": prod1.cost_price, "discount": 0.0, "tax_rate": 0.15}]
        )
        dn_note = LedgerService.create_credit_debit_note(
            db=db, note_type=NoteType.DEBIT_NOTE, party_name="شركة التوريدات الهندسية العالمية",
            original_invoice_number=pur_inv.invoice_number, purchase_invoice_id=pur_inv.id,
            payment_method=PaymentMethod.CREDIT, reason="مرتجع بضاعة للمورد",
            items_data=[{"product_id": prod1.id, "item_name": prod1.name_ar, "quantity": 2.0, "unit_price": 200.0, "cost_price": prod1.cost_price, "tax_rate": 0.15}]
        )
        print(f"✅ الفواتير والإشعارات الضريبية: مبيعات={sales_inv.invoice_number} | مشتريات={pur_inv.invoice_number} | إشعار مدين={dn_note.note_number}")

        # 2. اختبار محرك إهلاك الأصول الثابتة الآلي
        dep_je = LedgerService.run_period_depreciation(db=db, dep_date=date(2026, 2, 28), months=1)
        print(f"✅ قيد إهلاك الأصول الثابتة الآلي: {dep_je.entry_number} بمبلغ {dep_je.total_debit:,.2f} ريال")

        # 3. اختبار محرك مسير الرواتب ومكافأة نهاية الخدمة
        pr_run = LedgerService.process_monthly_payroll(db=db, period_month="2026-02", payment_date=date(2026, 2, 28))
        print(f"✅ مسير الرواتب الشهري: {pr_run.payroll_number} | صافي المنصرف={pr_run.net_paid_salaries:,.2f} | مخصص نهاية الخدمة={pr_run.total_eos_accrual:,.2f}")

        # 4. اختبار تقرير أعمار الديون والتسوية البنكية وربحية مراكز التكلفة
        aging_df = LedgerService.get_aging_report(db, party_type="CUSTOMER")
        rec_data = LedgerService.reconcile_bank_statement(db, bank_account_code="110201")
        cc_df = LedgerService.get_cost_centers_pnl(db)
        print(f"✅ تقرير أعمار الديون: {len(aging_df)} عميل | مذكرة التسوية البنكية: رصيد الدفاتر={rec_data['book_closing_balance']:,.2f} | مراكز التكلفة={len(cc_df)}")

        # 5. اختبار محلل ميزان المراجعة الخارجي وتقرير المراجع وتصدير ملف Word
        sample_tb = ExternalTBAnalyzerService.get_sample_tasaheel_tb_dataframe()
        c_df = ExternalTBAnalyzerService.normalize_and_classify_tb(sample_tb)
        cpa_pkg = ExternalTBAnalyzerService.generate_cpa_full_package(c_df, {
            "company_name": "مؤسسة تساهيل طيبة التجارية",
            "include_auditor_report": True,
            "opinion_type": "GOING_CONCERN"
        })
        word_bytes = ExternalTBAnalyzerService.generate_cpa_word_doc(cpa_pkg)
        assert len(word_bytes) > 15000
        print(f"✅ تقرير مكتب المحاسبة المعتمد (شامل تقرير المراجع المستقل + Word .doc): حجم الملف={len(word_bytes)} بايت")

        # 6. اختبار التقرير التنفيذي ذي الـ 15 صفحة Excel
        excel_bytes = ExcelExportService.generate_master_excel_report(db, fiscal_year=2026)
        assert len(excel_bytes.getvalue()) > 8000
        print("✅ تم توليد مصنف الإكسيل التنفيذي الشامل (15 صفحة) بنجاح تام!")

    finally:
        db.close()


if __name__ == "__main__":
    run_full_accounting_cycle()