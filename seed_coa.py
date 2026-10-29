"""
MizanPro - Standard Chart of Accounts, Safe Auto-Migration & Master Data Seeder
النظام المالي المتكامل - ميزان برو
ملف تهيئة وترقية قاعدة البيانات وزراعة شجرة الحسابات القياسية والأصول والموظفين والصلاحيات المخصصة
"""

import json
import os
from datetime import date
from typing import Optional
from sqlalchemy import text, inspect
from database import engine, Base, SessionLocal, ACTIVE_DB_PATH
from models import (
    Account, AccountType, AccountSubType, NaturalBalance,
    FiscalPeriod, CostCenter, CompanySettings, Customer,
    Supplier, Product, FixedAsset, Employee, AppUser, UserRole,
    CustomRoleTemplate, Warehouse, WarehouseStock, JournalEntry, JournalLine,
    InventoryTransaction, InventoryTxType, DocumentType, EntryStatus, AuditLog,
    get_default_permissions_for_role, hash_pin_code, verify_pin_code,
    generate_random_pin, LEGACY_COMPROMISED_PINS, PIN_HASH_PREFIX,
    AUDIT_GENESIS_HASH, compute_audit_entry_hash, resolve_audit_user_identity
)

BOOTSTRAP_PIN_FILE = "/tmp/mizanpro_initial_admin_pin.json"


def get_initial_admin_bootstrap_pin() -> Optional[str]:
    """استرجاع الرمز العشوائي المؤقت لمدير النظام عند التهيئة الأولى فقط (معزول لكل قاعدة بيانات)"""
    if not os.path.exists(BOOTSTRAP_PIN_FILE):
        return None
    try:
        with open(BOOTSTRAP_PIN_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        db_key = os.path.abspath(ACTIVE_DB_PATH)
        if isinstance(data, dict) and db_key in data:
            return data[db_key]
        return data.get("admin_bootstrap_pin")
    except Exception:
        return None


def _save_initial_admin_bootstrap_pin(pin_str: str) -> None:
    try:
        data = {}
        if os.path.exists(BOOTSTRAP_PIN_FILE):
            try:
                with open(BOOTSTRAP_PIN_FILE, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    if isinstance(loaded, dict):
                        data = loaded
            except Exception:
                data = {}
        db_key = os.path.abspath(ACTIVE_DB_PATH)
        data[db_key] = pin_str
        with open(BOOTSTRAP_PIN_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.chmod(BOOTSTRAP_PIN_FILE, 0o600)
    except Exception:
        pass


def clear_initial_admin_bootstrap_pin() -> None:
    """مسح الرمز التمهيدي المؤقت لقاعدة البيانات النشطة فور قيام المدير بتغيير رمزه عند أول دخول"""
    if not os.path.exists(BOOTSTRAP_PIN_FILE):
        return
    try:
        with open(BOOTSTRAP_PIN_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        db_key = os.path.abspath(ACTIVE_DB_PATH)
        if isinstance(data, dict):
            data.pop(db_key, None)
            data.pop("admin_bootstrap_pin", None)
            with open(BOOTSTRAP_PIN_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f)
    except Exception:
        pass


def _safe_auto_migrate():
    """
    ترقية الجداول الحالية في قاعدة البيانات بأمان (Auto-Migration)
    دون حذف أو المساس بأي قيود أو فواتير مسجلة مسبقاً، مع إضافة الفهارس المحاسبية.
    """
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    with engine.begin() as conn:
        if "customers" in existing_tables:
            cols = [c["name"] for c in inspector.get_columns("customers")]
            if "credit_limit" not in cols:
                conn.execute(text("ALTER TABLE customers ADD COLUMN credit_limit FLOAT NOT NULL DEFAULT 0.0"))

        if "products" in existing_tables:
            cols = [c["name"] for c in inspector.get_columns("products")]
            if "category" not in cols:
                conn.execute(text("ALTER TABLE products ADD COLUMN category VARCHAR(100) DEFAULT 'عام'"))
            if "stock_quantity" not in cols:
                conn.execute(text("ALTER TABLE products ADD COLUMN stock_quantity FLOAT NOT NULL DEFAULT 0.0"))
            if "reorder_level" not in cols:
                conn.execute(text("ALTER TABLE products ADD COLUMN reorder_level FLOAT NOT NULL DEFAULT 5.0"))

        if "audit_logs" in existing_tables:
            cols = [c["name"] for c in inspector.get_columns("audit_logs")]
            # إيقاف تريجرات منع التعديل مؤقتاً فقط أثناء الترقية المعمارية لملء البصمات التشفيرية للسجلات القديمة
            conn.execute(text("DROP TRIGGER IF EXISTS trg_audit_logs_readonly_update"))
            conn.execute(text("DROP TRIGGER IF EXISTS trg_audit_logs_readonly_delete"))
            if "performed_by" not in cols:
                conn.execute(text("ALTER TABLE audit_logs ADD COLUMN performed_by VARCHAR(150) DEFAULT 'مدير النظام (Admin)'"))
            if "user_id" not in cols:
                conn.execute(text("ALTER TABLE audit_logs ADD COLUMN user_id VARCHAR(64) NOT NULL DEFAULT 'USR-001'"))
            if "username" not in cols:
                conn.execute(text("ALTER TABLE audit_logs ADD COLUMN username VARCHAR(100) DEFAULT 'admin'"))
            if "reference_number" not in cols:
                conn.execute(text("ALTER TABLE audit_logs ADD COLUMN reference_number VARCHAR(100)"))
            if "financial_amount" not in cols:
                conn.execute(text("ALTER TABLE audit_logs ADD COLUMN financial_amount NUMERIC(18, 2) DEFAULT 0.00"))
            if "old_values_json" not in cols:
                conn.execute(text("ALTER TABLE audit_logs ADD COLUMN old_values_json TEXT"))
            if "new_values_json" not in cols:
                conn.execute(text("ALTER TABLE audit_logs ADD COLUMN new_values_json TEXT"))
            if "previous_hash" not in cols:
                conn.execute(text(f"ALTER TABLE audit_logs ADD COLUMN previous_hash VARCHAR(64) NOT NULL DEFAULT '{AUDIT_GENESIS_HASH}'"))
            if "entry_hash" not in cols:
                conn.execute(text("ALTER TABLE audit_logs ADD COLUMN entry_hash VARCHAR(64)"))

            # استكمال البصمة التشفيرية ومعرف المستخدم للسجلات التاريخية التي أنشئت قبل الترقية
            unhashed = conn.execute(
                text("SELECT id, timestamp, user_id, username, performed_by, table_name, record_id, action, reference_number, financial_amount, details, previous_hash, entry_hash FROM audit_logs ORDER BY id ASC")
            ).fetchall()
            running_prev = AUDIT_GENESIS_HASH
            for row in unhashed:
                r_id, r_ts, r_uid, r_uname, r_actor, r_tbl, r_rec, r_act, r_ref, r_amt, r_det, r_prev, r_ehash = row
                uid_val, uname_val, actor_val = resolve_audit_user_identity(conn, performed_by=r_actor, explicit_user_id=r_uid, explicit_username=r_uname)
                computed_h = compute_audit_entry_hash(
                    previous_hash=running_prev,
                    timestamp=r_ts,
                    user_id=uid_val,
                    username=uname_val,
                    performed_by=actor_val,
                    table_name=r_tbl,
                    record_id=r_rec,
                    action=r_act,
                    reference_number=r_ref,
                    financial_amount=r_amt or 0.0,
                    details=r_det,
                )
                if not r_ehash or not r_uid or r_prev != running_prev or r_ehash != computed_h:
                    conn.execute(
                        text("UPDATE audit_logs SET user_id = :uid, username = :uname, performed_by = :actor, previous_hash = :ph, entry_hash = :eh WHERE id = :id"),
                        {"uid": uid_val, "uname": uname_val, "actor": actor_val, "ph": running_prev, "eh": computed_h, "id": r_id}
                    )
                running_prev = computed_h

        if "sales_invoices" in existing_tables:
            cols = [c["name"] for c in inspector.get_columns("sales_invoices")]
            if "cost_center_id" not in cols:
                conn.execute(text("ALTER TABLE sales_invoices ADD COLUMN cost_center_id INTEGER"))

        if "purchase_invoices" in existing_tables:
            cols = [c["name"] for c in inspector.get_columns("purchase_invoices")]
            if "cost_center_id" not in cols:
                conn.execute(text("ALTER TABLE purchase_invoices ADD COLUMN cost_center_id INTEGER"))
            if "qr_code_base64" not in cols:
                conn.execute(text("ALTER TABLE purchase_invoices ADD COLUMN qr_code_base64 TEXT"))

        if "cash_vouchers" in existing_tables:
            cols = [c["name"] for c in inspector.get_columns("cash_vouchers")]
            if "cost_center_id" not in cols:
                conn.execute(text("ALTER TABLE cash_vouchers ADD COLUMN cost_center_id INTEGER"))

        if "journal_lines" in existing_tables:
            cols = [c["name"] for c in inspector.get_columns("journal_lines")]
            if "customer_id" not in cols:
                conn.execute(text("ALTER TABLE journal_lines ADD COLUMN customer_id INTEGER"))
            if "supplier_id" not in cols:
                conn.execute(text("ALTER TABLE journal_lines ADD COLUMN supplier_id INTEGER"))

        if "app_users" in existing_tables:
            cols = [c["name"] for c in inspector.get_columns("app_users")]
            if "job_title" not in cols:
                conn.execute(text("ALTER TABLE app_users ADD COLUMN job_title VARCHAR(150) DEFAULT 'مسؤول مالي'"))
            if "permissions_json" not in cols:
                conn.execute(text("ALTER TABLE app_users ADD COLUMN permissions_json TEXT"))
            if "max_discount_pct" not in cols:
                conn.execute(text("ALTER TABLE app_users ADD COLUMN max_discount_pct NUMERIC(18, 2) NOT NULL DEFAULT 100.0"))
            if "must_change_pin" not in cols:
                conn.execute(text("ALTER TABLE app_users ADD COLUMN must_change_pin BOOLEAN NOT NULL DEFAULT 1"))

        # تفعيل تريجرات الحماية الصارمة على مستوى قاعدة البيانات (SQLite Triggers) لمنع أي تعديل أو حذف في audit_logs
        if "audit_logs" in inspect(conn).get_table_names():
            conn.execute(text("""
                CREATE TRIGGER IF NOT EXISTS trg_audit_logs_readonly_update
                BEFORE UPDATE ON audit_logs
                BEGIN
                    SELECT RAISE(ABORT, 'ZATCA_AUDIT_LOG_READ_ONLY: Modification of audit_logs is strictly prohibited for ZATCA compliance.');
                END;
            """))
            conn.execute(text("""
                CREATE TRIGGER IF NOT EXISTS trg_audit_logs_readonly_delete
                BEFORE DELETE ON audit_logs
                BEGIN
                    SELECT RAISE(ABORT, 'ZATCA_AUDIT_LOG_READ_ONLY: Deletion of audit_logs is strictly prohibited for ZATCA compliance.');
                END;
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_logs_user_id ON audit_logs (user_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_logs_timestamp ON audit_logs (timestamp)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_logs_table_rec ON audit_logs (table_name, record_id)"))

        # إنشاء الفهارس الضرورية لتسريع الاستعلامات ومنع التكرار
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_journal_lines_entry_id ON journal_lines (entry_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_journal_lines_account_id ON journal_lines (account_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_journal_entries_date_status ON journal_entries (entry_date, status)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_inventory_tx_product_id ON inventory_transactions (product_id)"))
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_warehouse_stock_wh_prod ON warehouse_stocks (warehouse_id, product_id)"))


def _get_full_coa_structure():
    """مصفوفة شجرة الحسابات القياسية الكاملة (IFRS / SOCPA / ZATCA)"""
    return [
        # الأصول (ASSETS)
        {
            "code": "1", "name_ar": "الأصول", "name_en": "Assets",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 1, "is_leaf": False, "parent_code": None
        },
        {
            "code": "11", "name_ar": "الأصول المتداولة", "name_en": "Current Assets",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 2, "is_leaf": False, "parent_code": "1"
        },
        {
            "code": "1101", "name_ar": "النقد وما في حكمه", "name_en": "Cash and Cash Equivalents",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": False, "parent_code": "11"
        },
        {
            "code": "110101", "name_ar": "الصندوق الرئيسي / الخزينة", "name_en": "Main Cash Vault",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 4, "is_leaf": True, "parent_code": "1101"
        },
        {
            "code": "110102", "name_ar": "العهد النقدية المستديمة", "name_en": "Petty Cash Funds",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 4, "is_leaf": True, "parent_code": "1101"
        },
        {
            "code": "1102", "name_ar": "البنوك والحسابات الجارية", "name_en": "Banks and Current Accounts",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": False, "parent_code": "11"
        },
        {
            "code": "110201", "name_ar": "حساب مصرفي جاري - رئيسي", "name_en": "Main Operating Bank Account",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 4, "is_leaf": True, "parent_code": "1102"
        },
        {
            "code": "110202", "name_ar": "حساب مصرفي نقاط البيع (POS)", "name_en": "POS Settlement Account",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 4, "is_leaf": True, "parent_code": "1102"
        },
        {
            "code": "1103", "name_ar": "العملاء والمدينون التجاريون", "name_en": "Trade Receivables",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": False, "parent_code": "11"
        },
        {
            "code": "110301", "name_ar": "حسابات العملاء التجاريين", "name_en": "Trade Debtors",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 4, "is_leaf": True, "parent_code": "1103"
        },
        {
            "code": "110302", "name_ar": "أوراق القبض (الشيكات تحت التحصيل)", "name_en": "Notes Receivable",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 4, "is_leaf": True, "parent_code": "1103"
        },
        {
            "code": "110303", "name_ar": "مخصص الخسائر الائتمانية المتوقعة (ديون مشكوك فيها)", "name_en": "Allowance for Expected Credit Losses",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CONTRA_ASSET,
            "natural_balance": NaturalBalance.CREDIT, "level": 4, "is_leaf": True, "parent_code": "1103"
        },
        {
            "code": "1104", "name_ar": "المخزون السلعي", "name_en": "Inventory",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": False, "parent_code": "11"
        },
        {
            "code": "110401", "name_ar": "مخزون بضاعة بغرض البيع (قطع غيار/بضائع)", "name_en": "Merchandise Inventory for Sale",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 4, "is_leaf": True, "parent_code": "1104"
        },
        {
            "code": "110402", "name_ar": "بضاعة بالطريق واعتمادات مستندية", "name_en": "Goods in Transit & LCs",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 4, "is_leaf": True, "parent_code": "1104"
        },
        {
            "code": "1105", "name_ar": "أرصدة مدينة أخرى ومصروفات مدفوعة مقدماً", "name_en": "Prepayments & Other Receivables",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": False, "parent_code": "11"
        },
        {
            "code": "110501", "name_ar": "مصروفات مدفوعة مقدماً (إيجار/تأمين)", "name_en": "Prepaid Expenses",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 4, "is_leaf": True, "parent_code": "1105"
        },
        {
            "code": "110502", "name_ar": "تأمينات مستردة ولدى الغير", "name_en": "Refundable Deposits",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 4, "is_leaf": True, "parent_code": "1105"
        },
        {
            "code": "110503", "name_ar": "ضريبة القيمة المضافة - مدخلات مشتريات (مستردة)", "name_en": "Input VAT (Recoverable)",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 4, "is_leaf": True, "parent_code": "1105"
        },
        {
            "code": "12", "name_ar": "الأصول غير المتداولة", "name_en": "Non-Current Assets",
            "type": AccountType.ASSET, "sub_type": AccountSubType.NON_CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 2, "is_leaf": False, "parent_code": "1"
        },
        {
            "code": "1201", "name_ar": "الأصول الثابتة الملموسة (بالتكلفة)", "name_en": "Property, Plant & Equipment",
            "type": AccountType.ASSET, "sub_type": AccountSubType.NON_CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": False, "parent_code": "12"
        },
        {
            "code": "120101", "name_ar": "المباني والإنشاءات", "name_en": "Buildings & Improvements",
            "type": AccountType.ASSET, "sub_type": AccountSubType.NON_CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 4, "is_leaf": True, "parent_code": "1201"
        },
        {
            "code": "120102", "name_ar": "الآلات والمعدات والأجهزة", "name_en": "Machinery & Equipment",
            "type": AccountType.ASSET, "sub_type": AccountSubType.NON_CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 4, "is_leaf": True, "parent_code": "1201"
        },
        {
            "code": "120103", "name_ar": "السيارات ووسائل النقل", "name_en": "Vehicles & Transport",
            "type": AccountType.ASSET, "sub_type": AccountSubType.NON_CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 4, "is_leaf": True, "parent_code": "1201"
        },
        {
            "code": "120104", "name_ar": "الأثاث والتركيبات والتجهيزات", "name_en": "Furniture & Fixtures",
            "type": AccountType.ASSET, "sub_type": AccountSubType.NON_CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 4, "is_leaf": True, "parent_code": "1201"
        },
        {
            "code": "1202", "name_ar": "مجمع إهلاك الأصول الثابتة", "name_en": "Accumulated Depreciation",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CONTRA_ASSET,
            "natural_balance": NaturalBalance.CREDIT, "level": 3, "is_leaf": False, "parent_code": "12"
        },
        {
            "code": "120201", "name_ar": "مجمع إهلاك المباني والإنشاءات", "name_en": "Accum. Dep. - Buildings",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CONTRA_ASSET,
            "natural_balance": NaturalBalance.CREDIT, "level": 4, "is_leaf": True, "parent_code": "1202"
        },
        {
            "code": "120202", "name_ar": "مجمع إهلاك الآلات والمعدات", "name_en": "Accum. Dep. - Machinery",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CONTRA_ASSET,
            "natural_balance": NaturalBalance.CREDIT, "level": 4, "is_leaf": True, "parent_code": "1202"
        },
        {
            "code": "120203", "name_ar": "مجمع إهلاك السيارات ووسائل النقل", "name_en": "Accum. Dep. - Vehicles",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CONTRA_ASSET,
            "natural_balance": NaturalBalance.CREDIT, "level": 4, "is_leaf": True, "parent_code": "1202"
        },
        {
            "code": "120204", "name_ar": "مجمع إهلاك الأثاث والتركيبات", "name_en": "Accum. Dep. - Furniture",
            "type": AccountType.ASSET, "sub_type": AccountSubType.CONTRA_ASSET,
            "natural_balance": NaturalBalance.CREDIT, "level": 4, "is_leaf": True, "parent_code": "1202"
        },
        {
            "code": "1203", "name_ar": "الأصول غير الملموسة (برامج وتراخيص)", "name_en": "Intangible Assets & Software",
            "type": AccountType.ASSET, "sub_type": AccountSubType.NON_CURRENT_ASSET,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": True, "parent_code": "12"
        },

        # الالتزامات (LIABILITIES)
        {
            "code": "2", "name_ar": "الالتزامات", "name_en": "Liabilities",
            "type": AccountType.LIABILITY, "sub_type": AccountSubType.CURRENT_LIABILITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 1, "is_leaf": False, "parent_code": None
        },
        {
            "code": "21", "name_ar": "الالتزامات المتداولة", "name_en": "Current Liabilities",
            "type": AccountType.LIABILITY, "sub_type": AccountSubType.CURRENT_LIABILITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 2, "is_leaf": False, "parent_code": "2"
        },
        {
            "code": "2101", "name_ar": "الموردون والدائنون التجاريون", "name_en": "Trade Payables",
            "type": AccountType.LIABILITY, "sub_type": AccountSubType.CURRENT_LIABILITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 3, "is_leaf": False, "parent_code": "21"
        },
        {
            "code": "210101", "name_ar": "حسابات الموردين المحليين والدوليين", "name_en": "Trade Creditors",
            "type": AccountType.LIABILITY, "sub_type": AccountSubType.CURRENT_LIABILITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 4, "is_leaf": True, "parent_code": "2101"
        },
        {
            "code": "210102", "name_ar": "أوراق الدفع (شيكات وكمبيالات صادرة)", "name_en": "Notes Payable",
            "type": AccountType.LIABILITY, "sub_type": AccountSubType.CURRENT_LIABILITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 4, "is_leaf": True, "parent_code": "2101"
        },
        {
            "code": "2102", "name_ar": "أرصدة دائنة ومستحقات أخرى", "name_en": "Accruals & Other Payables",
            "type": AccountType.LIABILITY, "sub_type": AccountSubType.CURRENT_LIABILITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 3, "is_leaf": False, "parent_code": "21"
        },
        {
            "code": "210201", "name_ar": "مصروفات مستحقة غير مسددة", "name_en": "Accrued Expenses",
            "type": AccountType.LIABILITY, "sub_type": AccountSubType.CURRENT_LIABILITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 4, "is_leaf": True, "parent_code": "2102"
        },
        {
            "code": "210202", "name_ar": "رواتب ومستحقات موظفين مستحقة", "name_en": "Accrued Salaries",
            "type": AccountType.LIABILITY, "sub_type": AccountSubType.CURRENT_LIABILITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 4, "is_leaf": True, "parent_code": "2102"
        },
        {
            "code": "210203", "name_ar": "تأمينات اجتماعية / ضرائب كسب عمل مستحقة", "name_en": "Social Insurance & Payroll Taxes Payable",
            "type": AccountType.LIABILITY, "sub_type": AccountSubType.CURRENT_LIABILITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 4, "is_leaf": True, "parent_code": "2102"
        },
        {
            "code": "210204", "name_ar": "ضريبة القيمة المضافة - مخرجات مبيعات (مستحقة للهيئة)", "name_en": "Output VAT (Payable to Authority)",
            "type": AccountType.LIABILITY, "sub_type": AccountSubType.CURRENT_LIABILITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 4, "is_leaf": True, "parent_code": "2102"
        },
        {
            "code": "210205", "name_ar": "مخصص الزكاة الشرعية وضريبة الدخل المستحقة", "name_en": "Zakat & Income Tax Provision",
            "type": AccountType.LIABILITY, "sub_type": AccountSubType.CURRENT_LIABILITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 4, "is_leaf": True, "parent_code": "2102"
        },
        {
            "code": "22", "name_ar": "الالتزامات غير المتداولة", "name_en": "Non-Current Liabilities",
            "type": AccountType.LIABILITY, "sub_type": AccountSubType.NON_CURRENT_LIABILITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 2, "is_leaf": False, "parent_code": "2"
        },
        {
            "code": "2201", "name_ar": "قروض وتسهيلات تمويلية طويلة الأجل", "name_en": "Long-Term Loans & Financing",
            "type": AccountType.LIABILITY, "sub_type": AccountSubType.NON_CURRENT_LIABILITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 3, "is_leaf": True, "parent_code": "22"
        },
        {
            "code": "2202", "name_ar": "مخصص مكافأة نهاية الخدمة للموظفين", "name_en": "End of Service Benefits Provision",
            "type": AccountType.LIABILITY, "sub_type": AccountSubType.NON_CURRENT_LIABILITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 3, "is_leaf": True, "parent_code": "22"
        },

        # حقوق الملكية (EQUITY)
        {
            "code": "3", "name_ar": "حقوق الملكية", "name_en": "Equity",
            "type": AccountType.EQUITY, "sub_type": AccountSubType.EQUITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 1, "is_leaf": False, "parent_code": None
        },
        {
            "code": "31", "name_ar": "رأس المال والاحتياطيات والأرباح", "name_en": "Capital, Reserves & Retained Earnings",
            "type": AccountType.EQUITY, "sub_type": AccountSubType.EQUITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 2, "is_leaf": False, "parent_code": "3"
        },
        {
            "code": "3101", "name_ar": "رأس المال المدفوع", "name_en": "Paid-up Share Capital",
            "type": AccountType.EQUITY, "sub_type": AccountSubType.EQUITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 3, "is_leaf": True, "parent_code": "31"
        },
        {
            "code": "3102", "name_ar": "الاحتياطي النظامي / القانوني", "name_en": "Statutory / Legal Reserve",
            "type": AccountType.EQUITY, "sub_type": AccountSubType.EQUITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 3, "is_leaf": True, "parent_code": "31"
        },
        {
            "code": "3103", "name_ar": "الأرباح المبقاة (المرحلة)", "name_en": "Retained Earnings",
            "type": AccountType.EQUITY, "sub_type": AccountSubType.EQUITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 3, "is_leaf": True, "parent_code": "31"
        },
        {
            "code": "3104", "name_ar": "جاري الشركاء / جاري المالك", "name_en": "Partners' / Owner Current Account",
            "type": AccountType.EQUITY, "sub_type": AccountSubType.EQUITY,
            "natural_balance": NaturalBalance.CREDIT, "level": 3, "is_leaf": True, "parent_code": "31"
        },

        # الإيرادات (REVENUES)
        {
            "code": "4", "name_ar": "الإيرادات", "name_en": "Revenues",
            "type": AccountType.REVENUE, "sub_type": AccountSubType.OPERATING_REVENUE,
            "natural_balance": NaturalBalance.CREDIT, "level": 1, "is_leaf": False, "parent_code": None
        },
        {
            "code": "41", "name_ar": "إيرادات النشاط التشغيلي", "name_en": "Operating Revenues",
            "type": AccountType.REVENUE, "sub_type": AccountSubType.OPERATING_REVENUE,
            "natural_balance": NaturalBalance.CREDIT, "level": 2, "is_leaf": False, "parent_code": "4"
        },
        {
            "code": "4101", "name_ar": "إيرادات مبيعات البضائع والخدمات", "name_en": "Sales of Goods & Services",
            "type": AccountType.REVENUE, "sub_type": AccountSubType.OPERATING_REVENUE,
            "natural_balance": NaturalBalance.CREDIT, "level": 3, "is_leaf": True, "parent_code": "41"
        },
        {
            "code": "4102", "name_ar": "مردودات ومسموحات المبيعات", "name_en": "Sales Returns & Allowances",
            "type": AccountType.REVENUE, "sub_type": AccountSubType.OPERATING_REVENUE,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": True, "parent_code": "41"
        },
        {
            "code": "4103", "name_ar": "خصم مسموح به (خصم المبيعات)", "name_en": "Sales Discounts Allowed",
            "type": AccountType.REVENUE, "sub_type": AccountSubType.OPERATING_REVENUE,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": True, "parent_code": "41"
        },
        {
            "code": "4201", "name_ar": "إيرادات وأرباح أخرى متنوعة (غير تشغيلية)", "name_en": "Other Non-Operating Income",
            "type": AccountType.REVENUE, "sub_type": AccountSubType.OTHER_INCOME,
            "natural_balance": NaturalBalance.CREDIT, "level": 2, "is_leaf": True, "parent_code": "4"
        },

        # المصروفات (EXPENSES)
        {
            "code": "5", "name_ar": "المصروفات", "name_en": "Expenses",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.OPERATING_EXPENSE,
            "natural_balance": NaturalBalance.DEBIT, "level": 1, "is_leaf": False, "parent_code": None
        },
        {
            "code": "51", "name_ar": "تكلفة المبيعات والنشاط", "name_en": "Cost of Sales",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.COST_OF_SALES,
            "natural_balance": NaturalBalance.DEBIT, "level": 2, "is_leaf": False, "parent_code": "5"
        },
        {
            "code": "5101", "name_ar": "تكلفة البضاعة المباعة", "name_en": "Cost of Goods Sold (COGS)",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.COST_OF_SALES,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": True, "parent_code": "51"
        },
        {
            "code": "5102", "name_ar": "مصاريف شحن ونقل مشتريات وتخليص جمركي", "name_en": "Freight-in & Customs Clearance",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.COST_OF_SALES,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": True, "parent_code": "51"
        },
        {
            "code": "5103", "name_ar": "مردودات ومسموحات المشتريات", "name_en": "Purchase Returns & Allowances",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.COST_OF_SALES,
            "natural_balance": NaturalBalance.CREDIT, "level": 3, "is_leaf": True, "parent_code": "51"
        },
        {
            "code": "5104", "name_ar": "خصم مكتسب من الموردين", "name_en": "Purchase Discounts Received",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.COST_OF_SALES,
            "natural_balance": NaturalBalance.CREDIT, "level": 3, "is_leaf": True, "parent_code": "51"
        },
        {
            "code": "5105", "name_ar": "فروق وتسويات الجرد المخزني (عجز/فائض)", "name_en": "Inventory Shrinkage & Adjustments",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.COST_OF_SALES,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": True, "parent_code": "51"
        },
        {
            "code": "52", "name_ar": "المصاريف التشغيلية والعمومية والإدارية", "name_en": "General, Admin & Selling Expenses",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.OPERATING_EXPENSE,
            "natural_balance": NaturalBalance.DEBIT, "level": 2, "is_leaf": False, "parent_code": "5"
        },
        {
            "code": "5201", "name_ar": "الرواتب والأجور وبدلات الموظفين", "name_en": "Salaries, Wages & Benefits",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.OPERATING_EXPENSE,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": True, "parent_code": "52"
        },
        {
            "code": "5202", "name_ar": "إيجار المقرات والمعارض والمستودعات", "name_en": "Rent Expense",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.OPERATING_EXPENSE,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": True, "parent_code": "52"
        },
        {
            "code": "5203", "name_ar": "المنافع (كهرباء، مياه، اتصالات، إنترنت)", "name_en": "Utilities & Telecommunications",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.OPERATING_EXPENSE,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": True, "parent_code": "52"
        },
        {
            "code": "5204", "name_ar": "الصيانة العامة وقطع الغيار التشغيلية", "name_en": "Repairs & Maintenance",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.OPERATING_EXPENSE,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": True, "parent_code": "52"
        },
        {
            "code": "5205", "name_ar": "الدعاية والإعلان والتسويق", "name_en": "Advertising & Marketing",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.OPERATING_EXPENSE,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": True, "parent_code": "52"
        },
        {
            "code": "5206", "name_ar": "الرسوم الحكومية ورخص العمل والتأمينات والاشتراكات", "name_en": "Government Fees, Licenses & Subscriptions",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.OPERATING_EXPENSE,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": True, "parent_code": "52"
        },
        {
            "code": "5207", "name_ar": "مصروف إهلاك الأصول الثابتة للفترة", "name_en": "Depreciation Expense",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.OPERATING_EXPENSE,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": True, "parent_code": "52"
        },
        {
            "code": "5208", "name_ar": "مصروف مكافأة نهاية الخدمة للفترة", "name_en": "End of Service Expense",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.OPERATING_EXPENSE,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": True, "parent_code": "52"
        },
        {
            "code": "5209", "name_ar": "مصاريف عمومية وإدارية أخرى متنوعة", "name_en": "Other General & Administrative Expenses",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.OPERATING_EXPENSE,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": True, "parent_code": "52"
        },
        {
            "code": "53", "name_ar": "تكاليف التمويل ومصروف الزكاة والضريبة", "name_en": "Finance Costs, Zakat & Tax",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.FINANCIAL_EXPENSE,
            "natural_balance": NaturalBalance.DEBIT, "level": 2, "is_leaf": False, "parent_code": "5"
        },
        {
            "code": "5301", "name_ar": "العمولات والمصاريف البنكية وتكاليف التمويل", "name_en": "Bank Charges & Finance Costs",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.FINANCIAL_EXPENSE,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": True, "parent_code": "53"
        },
        {
            "code": "5302", "name_ar": "مصروف الزكاة الشرعية وضريبة الدخل للفترة", "name_en": "Zakat & Income Tax Expense for the Period",
            "type": AccountType.EXPENSE, "sub_type": AccountSubType.ZAKAT_TAX_EXPENSE,
            "natural_balance": NaturalBalance.DEBIT, "level": 3, "is_leaf": True, "parent_code": "53"
        },
    ]


def init_database_and_seed(seed_demo_data: bool = True):
    """إنشاء وترقية الجداول وزراعة دليل الحسابات والإعدادات والأصول والموظفين والمستخدمين وقوالب الصلاحيات"""
    Base.metadata.create_all(bind=engine)
    _safe_auto_migrate()
    db = SessionLocal()

    try:
        # 1. إعدادات المنشأة الافتراضية
        settings = db.query(CompanySettings).first()
        if not settings:
            settings = CompanySettings(
                company_name_ar="شركة ميزان برو التجارية",
                company_name_en="MizanPro Trading Co.",
                vat_number="300000000000003",
                cr_number="1010889922",
                address_ar="المملكة العربية السعودية - الرياض - حي العليا",
                phone="+966 11 234 5678",
                email="finance@mizanpro.sa",
                currency="ريال",
                default_vat_rate=0.15,
                fiscal_year=2026
            )
            db.add(settings)
            db.commit()

        # 2. المستخدمون الافتراضيون والصلاحيات القابلة للتخصيص الحر (مع توليد رمز عشوائي آمن وإلزام تغييره عند أول دخول)
        if db.query(AppUser).count() == 0:
            admin_random_pin = generate_random_pin(6)
            _save_initial_admin_bootstrap_pin(admin_random_pin)
            default_users = [
                AppUser(
                    username="admin", full_name_ar="المدير المالي / مدير النظام",
                    job_title="المدير المالي التنفيذي", role=UserRole.ADMIN,
                    pin_code=hash_pin_code(admin_random_pin),
                    must_change_pin=True,
                    permissions_json=json.dumps(get_default_permissions_for_role(UserRole.ADMIN), ensure_ascii=False),
                    max_discount_pct=100.0
                ),
                AppUser(
                    username="cpa_auditor", full_name_ar="المراجع القانوني المعتمد (CPA)",
                    job_title="مراجع حسابات قانوني", role=UserRole.AUDITOR,
                    pin_code=hash_pin_code(generate_random_pin(6)),
                    must_change_pin=True,
                    permissions_json=json.dumps(get_default_permissions_for_role(UserRole.AUDITOR), ensure_ascii=False),
                    max_discount_pct=0.0
                ),
                AppUser(
                    username="accountant", full_name_ar="المحاسب العام",
                    job_title="محاسب مالي أول", role=UserRole.ACCOUNTANT,
                    pin_code=hash_pin_code(generate_random_pin(6)),
                    must_change_pin=True,
                    permissions_json=json.dumps(get_default_permissions_for_role(UserRole.ACCOUNTANT), ensure_ascii=False),
                    max_discount_pct=25.0
                ),
                AppUser(
                    username="sales", full_name_ar="مسؤول المبيعات والمستودع",
                    job_title="مسؤول مبيعات ومخازن", role=UserRole.SALES,
                    pin_code=hash_pin_code(generate_random_pin(6)),
                    must_change_pin=True,
                    permissions_json=json.dumps(get_default_permissions_for_role(UserRole.SALES), ensure_ascii=False),
                    max_discount_pct=10.0
                ),
            ]
            db.add_all(default_users)
            db.commit()
        else:
            # مراجعة أمنية شاملة: تدوير أي رموز دخول افتراضية أو مكشوفة في قاعدة البيانات وإلزام تغييرها عند أول دخول
            for u in db.query(AppUser).all():
                if not u.permissions_json:
                    u.permissions_json = json.dumps(get_default_permissions_for_role(u.role), ensure_ascii=False)
                elif u.role == UserRole.ADMIN:
                    try:
                        p_dict = json.loads(u.permissions_json)
                        p_dict["act_cloud_backup"] = True
                        u.permissions_json = json.dumps(p_dict, ensure_ascii=False)
                    except Exception:
                        u.permissions_json = json.dumps(get_default_permissions_for_role(UserRole.ADMIN), ensure_ascii=False)
                if not u.job_title:
                    u.job_title = "مسؤول مالي"

                has_compromised_pin = (
                    not u.pin_code
                    or u.pin_code == "REDACTED_IN_BACKUP"
                    or any(verify_pin_code(bad_p, u.pin_code) for bad_p in LEGACY_COMPROMISED_PINS)
                )
                if has_compromised_pin:
                    rotated_pin = generate_random_pin(6)
                    u.pin_code = hash_pin_code(rotated_pin)
                    u.must_change_pin = True
                    if u.username == "admin":
                        _save_initial_admin_bootstrap_pin(rotated_pin)
                    db.add(AuditLog(
                        table_name="app_users",
                        record_id=u.id or 1,
                        action="ROTATE_COMPROMISED_PIN",
                        performed_by="System Security Guard",
                        details=f"Rotated legacy/exposed PIN for user '{u.username}' and enforced must_change_pin=True."
                    ))
                elif not str(u.pin_code).startswith(PIN_HASH_PREFIX):
                    u.pin_code = hash_pin_code(u.pin_code)

                if u.username == "admin" and u.must_change_pin and not get_initial_admin_bootstrap_pin():
                    rotated_pin = generate_random_pin(6)
                    u.pin_code = hash_pin_code(rotated_pin)
                    _save_initial_admin_bootstrap_pin(rotated_pin)
            db.commit()

        # 2.ب زراعة قوالب الأدوار الوظيفية المخصصة الافتراضية
        if db.query(CustomRoleTemplate).count() == 0:
            cashier_perms = get_default_permissions_for_role(UserRole.CUSTOM)
            cashier_perms["mod_treasury"] = True
            cashier_perms["mod_sales"] = True
            cashier_perms["act_create_vouchers"] = True
            cashier_perms["act_create_sales"] = True

            hr_perms = get_default_permissions_for_role(UserRole.CUSTOM)
            hr_perms["mod_assets_hr"] = True
            hr_perms["act_manage_payroll"] = True
            hr_perms["act_manage_assets"] = True

            store_perms = get_default_permissions_for_role(UserRole.CUSTOM)
            store_perms["mod_inventory"] = True
            store_perms["mod_purchases"] = True
            store_perms["act_manage_inventory"] = True
            store_perms["act_inventory_adjust"] = True
            store_perms["act_create_purchases"] = True

            db.add_all([
                CustomRoleTemplate(
                    template_name="أمين صندوق ومبيعات معرض",
                    description="صلاحية إصدار فواتير المبيعات وسندات القبض والصرف فقط دون الدخول للقيود أو الإعدادات",
                    permissions_json=json.dumps(cashier_perms, ensure_ascii=False)
                ),
                CustomRoleTemplate(
                    template_name="محاسب رواتب وأصول ثابتة",
                    description="صلاحية إدارة الموظفين ومسير الرواتب وسجل الأصول الثابتة والإهلاك",
                    permissions_json=json.dumps(hr_perms, ensure_ascii=False)
                ),
                CustomRoleTemplate(
                    template_name="أمين مستودع ومشتريات",
                    description="صلاحية إدارة الأصناف، كارت الصنف، الجرد المخزني، وفواتير المشتريات فقط",
                    permissions_json=json.dumps(store_perms, ensure_ascii=False)
                ),
            ])
            db.commit()

        # 3. السنة المالية الافتراضية من إعدادات المنشأة
        current_year = int(settings.fiscal_year or date.today().year)
        period = db.query(FiscalPeriod).filter(FiscalPeriod.year == current_year).first()
        if not period:
            start_d = date(current_year, 1, 1)
            end_d = date(current_year, 12, 31)
            period = FiscalPeriod(
                year=current_year,
                start_date=start_d,
                end_date=end_d,
                is_closed=False,
                total_days=(end_d - start_d).days + 1
            )
            db.add(period)
            db.commit()

        # 4. مراكز التكلفة والمشاريع الافتراضية
        if db.query(CostCenter).count() == 0:
            cc_admin = CostCenter(code="CC-01", name_ar="الإدارة العامة والمقر الرئيسي", name_en="General Administration", is_leaf=True)
            cc_main = CostCenter(code="CC-02", name_ar="معرض المبيعات الرئيسي - الرياض", name_en="Main Sales Showroom", is_leaf=True)
            cc_proj = CostCenter(code="CC-03", name_ar="مشروع التوريدات والمقاولات الشمالي", name_en="Northern Contracting Project", is_leaf=True)
            db.add_all([cc_admin, cc_main, cc_proj])
            db.commit()

        # 5. زراعة أو استكمال شجرة الحسابات القياسية
        coa_structure = _get_full_coa_structure()
        existing_accounts = {acc.code: acc.id for acc in db.query(Account).all()}

        for item in coa_structure:
            if item["code"] not in existing_accounts:
                parent_id = existing_accounts.get(item["parent_code"])
                account = Account(
                    code=item["code"],
                    name_ar=item["name_ar"],
                    name_en=item["name_en"],
                    type=item["type"],
                    sub_type=item["sub_type"],
                    natural_balance=item["natural_balance"],
                    level=item["level"],
                    is_leaf=item["is_leaf"],
                    parent_id=parent_id
                )
                db.add(account)
                db.flush()
                existing_accounts[item["code"]] = account.id
        db.commit()

        # 6. زراعة المستودع الرئيسي الافتراضي والبيانات التجريبية الاختيارية
        if db.query(Warehouse).count() == 0:
            wh1 = Warehouse(code="WH-01", name_ar="المستودع المركزي الرئيسي - الرياض", location="الرياض - الصناعية", manager_name="سلمان الدوسري")
            wh2 = Warehouse(code="WH-02", name_ar="مستودع معرض المبيعات الفرعي - جدة", location="جدة - طريق الميناء", manager_name="فهد العتيبي")
            wh3 = Warehouse(code="WH-03", name_ar="مستودع مشروع التوريدات الشمالي - تبوك", location="تبوك", manager_name="أحمد الشناوي")
            db.add_all([wh1, wh2, wh3])
            db.commit()

        if not seed_demo_data:
            return

        ar_acc = db.query(Account).filter(Account.code == "110301").first()
        ap_acc = db.query(Account).filter(Account.code == "210101").first()

        if db.query(Customer).count() == 0:
            db.add_all([
                Customer(code="CUST-001", name_ar="عميل نقدي عام (مبيعات معرض)", vat_number="", address="الرياض", credit_limit=0.0, account_id=ar_acc.id if ar_acc else None),
                Customer(code="CUST-002", name_ar="شركة الأمل التجارية", vat_number="300112233445563", cr_number="1010223344", phone="0501234567", address="الرياض - المنطقة الصناعية", credit_limit=250000.0, account_id=ar_acc.id if ar_acc else None),
                Customer(code="CUST-003", name_ar="مؤسسة الرائد للنقليات والصيانة", vat_number="300998877665543", cr_number="1010556677", phone="0559876543", address="جدة - طريق الميناء", credit_limit=150000.0, account_id=ar_acc.id if ar_acc else None),
            ])
            db.commit()

        if db.query(Supplier).count() == 0:
            db.add_all([
                Supplier(code="SUPP-001", name_ar="شركة التوريدات الهندسية العالمية", vat_number="300445566778893", cr_number="1010778899", phone="0114455667", address="الرياض - الصناعية الثانية", account_id=ap_acc.id if ap_acc else None),
                Supplier(code="SUPP-002", name_ar="مصنع الخليج لزيوت المحركات والفلاتر", vat_number="300776655443323", cr_number="2050112233", phone="0138899001", address="الدمام - المدينة الصناعية", account_id=ap_acc.id if ap_acc else None),
            ])
            db.commit()

        if db.query(Product).count() == 0:
            db.add_all([
                Product(code="PRD-001", barcode="628100000101", name_ar="طقم فحمات فرامل أمامية سيراميك", category="قطع غيار فرامل", unit="طقم", stock_quantity=40.0, reorder_level=10.0, cost_price=180.0, sale_price=280.0, tax_rate=0.15, is_service=False),
                Product(code="PRD-002", barcode="628100000102", name_ar="زيت محرك تخليقي بالكامل 5W-30 (كرتون 12 عبوة)", category="زيوت وشحوم", unit="كرتون", stock_quantity=25.0, reorder_level=8.0, cost_price=240.0, sale_price=360.0, tax_rate=0.15, is_service=False),
                Product(code="PRD-003", barcode="628100000103", name_ar="بطارية سيارة إلكترونية 80 أمبير", category="بطاريات وكهرباء", unit="حبة", stock_quantity=15.0, reorder_level=5.0, cost_price=310.0, sale_price=450.0, tax_rate=0.15, is_service=False),
                Product(code="SRV-001", barcode="628100000999", name_ar="خدمة فحص وبرمجة كمبيوتر شامل", category="خدمات صيانة", unit="خدمة", stock_quantity=0.0, reorder_level=0.0, cost_price=0.0, sale_price=200.0, tax_rate=0.15, is_service=True),
            ])
            db.commit()

        # 6.ب توزيع الأرصدة الابتدائية للأصناف التجريبية على المستودعات
        if db.query(WarehouseStock).count() == 0:
            whs = db.query(Warehouse).order_by(Warehouse.id).all()
            if whs:
                for p_item in db.query(Product).filter(Product.is_service == False).all():
                    for idx_w, w_obj in enumerate(whs):
                        db.add(WarehouseStock(warehouse_id=w_obj.id, product_id=p_item.id, quantity=p_item.stock_quantity if idx_w == 0 else 0.0))
                db.commit()

        # 7. زراعة سجل الأصول الثابتة الافتراضي
        if db.query(FixedAsset).count() == 0:
            db.add_all([
                FixedAsset(
                    asset_code="AST-001", name_ar="أجهزة ومعدات فحص هيدروليكية للمعرض",
                    category="الآلات والمعدات والأجهزة", purchase_date=date(2026, 1, 15),
                    purchase_cost=50000.0, salvage_value=0.0, useful_life_years=10.0,
                    depreciation_rate=0.10, accumulated_depreciation=5000.0, net_book_value=45000.0,
                    asset_account_code="120102", accum_dep_account_code="120202", dep_expense_account_code="5207"
                ),
                FixedAsset(
                    asset_code="AST-002", name_ar="سيارة نقل بضائع وتوزيع (إيسوزو ديزل)",
                    category="السيارات ووسائل النقل", purchase_date=date(2026, 1, 1),
                    purchase_cost=120000.0, salvage_value=0.0, useful_life_years=5.0,
                    depreciation_rate=0.20, accumulated_depreciation=0.0, net_book_value=120000.0,
                    asset_account_code="120103", accum_dep_account_code="120203", dep_expense_account_code="5207"
                ),
            ])
            db.commit()

        # 8. زراعة سجل الموظفين الافتراضي
        if db.query(Employee).count() == 0:
            db.add_all([
                Employee(
                    emp_code="EMP-001", name_ar="فهد بن عبد العزيز العتيبي", job_title="مدير المبيعات والفروع",
                    nationality="سعودي", is_saudi=True, join_date=date(2022, 1, 1),
                    basic_salary=9000.0, housing_allowance=2250.0, transport_allowance=750.0, other_allowance=500.0
                ),
                Employee(
                    emp_code="EMP-002", name_ar="أحمد محمود الشناوي", job_title="محاسب مالي أول",
                    nationality="مصري", is_saudi=False, join_date=date(2023, 6, 1),
                    basic_salary=7000.0, housing_allowance=1750.0, transport_allowance=750.0, other_allowance=0.0
                ),
                Employee(
                    emp_code="EMP-003", name_ar="سلمان بن محمد الدوسري", job_title="أمين مستودع ومشتريات",
                    nationality="سعودي", is_saudi=True, join_date=date(2024, 3, 1),
                    basic_salary=6000.0, housing_allowance=1500.0, transport_allowance=500.0, other_allowance=0.0
                ),
            ])
            db.commit()

        # 9. ترقية وتدقيق كافة رموز QR في المستندات المسجلة لتتوافق مع المرحلة الثانية (ZATCA Phase 2 Tags 1-9)
        from zatca_phase2_validator import ZATCAPhase2Validator
        ZATCAPhase2Validator.audit_all_database_documents(db, auto_upgrade_phase2=True)

    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


if __name__ == "__main__":
    init_database_and_seed()