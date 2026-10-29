"""
MizanPro - Enterprise Accounting, Inventory, Treasury, Fixed Assets, Payroll, Audit & Compliance Data Models
النظام المالي المتكامل - ميزان برو
ملف نماذج الجداول المحاسبية والمخزنية والسندات والأصول الثابتة والرواتب والصلاحيات الحرة ودورات المبيعات والمشتريات
"""

from datetime import datetime, date, timezone
import enum
import hashlib
import hmac
import json
import secrets
from typing import Dict, Any, List, Optional
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, Date, DateTime,
    ForeignKey, Enum as SQLEnum, Text
)
from sqlalchemy.orm import relationship
from database import Base


def utc_now() -> datetime:
    """إرجاع التوقيت العالمي الحالي بصيغة متوافقة مع كافة إصدارات Python"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# =============================================================================
# 0. دوال التشفير والتجزئة الآمنة لرموز الدخول (PIN Hashing - PBKDF2-HMAC-SHA256)
# =============================================================================

PIN_HASH_PREFIX = "pbkdf2_sha256$"


def hash_pin_code(plain_pin: str, salt: Optional[str] = None) -> str:
    """تجزئة رمز الدخول السري (PIN) بخوارزمية PBKDF2-HMAC-SHA256 مع Salt عشوائي"""
    raw = str(plain_pin or "").strip()
    if raw.startswith(PIN_HASH_PREFIX):
        return raw
    salt_str = salt or secrets.token_hex(8)
    dk = hashlib.pbkdf2_hmac("sha256", raw.encode("utf-8"), salt_str.encode("utf-8"), 100_000)
    return f"{PIN_HASH_PREFIX}{salt_str}${dk.hex()}"


def verify_pin_code(plain_pin: str, stored_pin: str) -> bool:
    """التحقق الآمن من تطابق رمز الدخول السري مع القيمة المخزنة (يدعم التجزئة والترقية الآمنة)"""
    candidate = str(plain_pin or "").strip()
    stored = str(stored_pin or "").strip()
    if not candidate or not stored:
        return False
    if stored.startswith(PIN_HASH_PREFIX):
        parts = stored.split("$")
        if len(parts) != 3:
            return False
        salt_str = parts[1]
        expected = hash_pin_code(candidate, salt=salt_str)
        return hmac.compare_digest(expected, stored)
    return hmac.compare_digest(candidate, stored)


# =============================================================================
# 1. التبويبات والثوابت المحاسبية والمخزنية والضريبية والإدارية (Enums)
# =============================================================================

class AccountType(str, enum.Enum):
    """النوع الرئيسي للحساب في القوائم المالية"""
    ASSET = "ASSET"              # أصول
    LIABILITY = "LIABILITY"      # التزامات
    EQUITY = "EQUITY"            # حقوق ملكية
    REVENUE = "REVENUE"          # إيرادات
    EXPENSE = "EXPENSE"          # مصروفات


class AccountSubType(str, enum.Enum):
    """التبويب الفرعي المحاسبي لعرض القوائم والزكاة"""
    CURRENT_ASSET = "CURRENT_ASSET"                  # أصول متداولة
    NON_CURRENT_ASSET = "NON_CURRENT_ASSET"          # أصول غير متداولة
    CONTRA_ASSET = "CONTRA_ASSET"                    # مجمعات إهلاك ومخصصات مدينة (تخصم من الأصول)

    CURRENT_LIABILITY = "CURRENT_LIABILITY"          # التزامات متداولة
    NON_CURRENT_LIABILITY = "NON_CURRENT_LIABILITY"  # التزامات غير متداولة (طويلة الأجل)

    EQUITY = "EQUITY"                                # حقوق الملكية

    OPERATING_REVENUE = "OPERATING_REVENUE"          # إيرادات النشاط التشغيلي
    OTHER_INCOME = "OTHER_INCOME"                    # إيرادات وأرباح أخرى

    COST_OF_SALES = "COST_OF_SALES"                  # تكلفة المبيعات
    OPERATING_EXPENSE = "OPERATING_EXPENSE"          # مصاريف عمومية وإدارية وتسويقية
    FINANCIAL_EXPENSE = "FINANCIAL_EXPENSE"          # تكاليف تمويلية
    OTHER_EXPENSE = "OTHER_EXPENSE"                  # مصاريف أخرى
    ZAKAT_TAX_EXPENSE = "ZAKAT_TAX_EXPENSE"          # مخصص زكاة وضريبة الدخل


class NaturalBalance(str, enum.Enum):
    """طبيعة الحساب الأصلية"""
    DEBIT = "DEBIT"    # مدين بطبيعته
    CREDIT = "CREDIT"  # دائن بطبيعته


class DocumentType(str, enum.Enum):
    """نوع المستند المنشئ للقيد"""
    JOURNAL_VOUCHER = "JOURNAL_VOUCHER"          # قيد تسوية / يومية عامة
    OPENING_BALANCE = "OPENING_BALANCE"          # قيد أرصدة افتتاحية
    SALES_INVOICE = "SALES_INVOICE"              # فاتورة مبيعات ضريبية
    PURCHASE_INVOICE = "PURCHASE_INVOICE"        # فاتورة مشتريات
    SALES_RETURN = "SALES_RETURN"                # إشعار دائن / مرتجع مبيعات
    PURCHASE_RETURN = "PURCHASE_RETURN"          # إشعار مدين / مرتجع مشتريات
    PAYMENT_VOUCHER = "PAYMENT_VOUCHER"          # سند صرف / مدفوعات
    RECEIPT_VOUCHER = "RECEIPT_VOUCHER"          # سند قبض / مقبوضات
    INVENTORY_ADJUSTMENT = "INVENTORY_ADJUSTMENT"# تسوية جردية للمخزون
    DEPRECIATION_RUN = "DEPRECIATION_RUN"        # قيد إهلاك الأصول الثابتة
    PAYROLL_RUN = "PAYROLL_RUN"                  # مسير رواتب وأجور
    CLOSING_ENTRY = "CLOSING_ENTRY"              # قيد إقفال الفترة


class EntryStatus(str, enum.Enum):
    """حالة القيد المحاسبي"""
    DRAFT = "DRAFT"        # مسودة (غير مرحل)
    POSTED = "POSTED"      # مرحل لدفتر الأستاذ
    REVERSED = "REVERSED"  # معكوس / ملغي بقيد تسوية


class PaymentMethod(str, enum.Enum):
    """طريقة السداد للفواتير والسندات"""
    CASH = "CASH"          # نقداً (الصندوق الرئيسي)
    BANK = "BANK"          # تحويل بنكي / نقاط بيع (POS)
    CREDIT = "CREDIT"      # بالأجل (على الحساب)


class InvoiceType(str, enum.Enum):
    """نوع الفاتورة الضريبية وفق متطلبات ZATCA"""
    SIMPLIFIED = "SIMPLIFIED"    # فاتورة ضريبية مبسطة (B2C للأفراد)
    STANDARD = "STANDARD"        # فاتورة ضريبية قياسية (B2B للشركات مع الرقم الضريبي)


class VoucherType(str, enum.Enum):
    """نوع سند الخزينة / البنك"""
    RECEIPT = "RECEIPT"    # سند قبض (مقبوضات)
    PAYMENT = "PAYMENT"    # سند صرف (مدفوعات)


class VoucherPartyType(str, enum.Enum):
    """نوع الطرف المقابل في سند القبض أو الصرف"""
    CUSTOMER = "CUSTOMER"  # عميل تجاري
    SUPPLIER = "SUPPLIER"  # مورد تجاري
    EXPENSE = "EXPENSE"    # مصروف تشغيلي مباشر
    OTHER = "OTHER"        # حساب أستاذ عام آخر


class NoteType(str, enum.Enum):
    """نوع الإشعار الضريبي (المرتجعات والتسويات)"""
    CREDIT_NOTE = "CREDIT_NOTE"  # إشعار دائن (مرتجع مبيعات)
    DEBIT_NOTE = "DEBIT_NOTE"    # إشعار مدين (مرتجع مشتريات)


class InventoryTxType(str, enum.Enum):
    """نوع حركة المخزون"""
    PURCHASE_IN = "PURCHASE_IN"              # وارد مشتريات
    SALE_OUT = "SALE_OUT"                    # منصرف مبيعات
    SALES_RETURN_IN = "SALES_RETURN_IN"      # وارد مرتجع مبيعات
    PURCHASE_RETURN_OUT = "PURCHASE_RETURN_OUT" # منصرف مرتجع مشتريات
    ADJUSTMENT = "ADJUSTMENT"                # تسوية جردية (فائض / عجز)


class UserRole(str, enum.Enum):
    """أدوار وصلاحيات المستخدمين في النظام (قابلة للتخصيص الحر)"""
    ADMIN = "ADMIN"              # مدير النظام / المدير المالي (كامل الصلاحيات)
    ACCOUNTANT = "ACCOUNTANT"    # محاسب عام (القيود، السندات، الفواتير، التقارير)
    AUDITOR = "AUDITOR"          # مراجع قانوني CPA (القوائم، الإيضاحات، محلل الميزان، التدقيق)
    SALES = "SALES"              # مسؤول مبيعات ومخازن (المبيعات، المشتريات، المخزون)
    CUSTOM = "CUSTOM"            # تخصيص حر للصلاحيات (مصفوفة شاشات وعمليات مخصصة)


# =============================================================================
# 1.ب مصفوفة الصلاحيات الحرة للشاشات والعمليات (Granular Free Permissions Matrix)
# =============================================================================

SYSTEM_MODULES: Dict[str, str] = {
    "mod_dashboard": "📊 لوحة التحكم والمؤشرات",
    "mod_cpa": "📑 محلل ميزان المراجعة الخارجي والإيضاحات المعتمدة (CPA)",
    "mod_assets_hr": "🏗️ الأصول الثابتة، الرواتب، ومراكز التكلفة",
    "mod_control": "🛡️ الرقابة المالية: أعمار الديون، البنوك، وإقفال السنة",
    "mod_inventory": "📦 المخزون والعملاء والموردون",
    "mod_sales": "🧾 المبيعات وإشعارات الدائن",
    "mod_purchases": "📥 المشتريات وإشعارات المدين",
    "mod_treasury": "💸 سندات القبض والصرف (الخزينة)",
    "mod_journal": "✍️ القيود اليومية ودفتر اليومية",
    "mod_ledger": "📖 كشف الحساب وميزان المراجعة",
    "mod_statements": "🏛️ القوائم المالية والزكاة والضريبة",
    "mod_settings": "🌳 شجرة الحسابات، الإعدادات، وصلاحيات المستخدمين",
}

MODULE_LABEL_TO_KEY: Dict[str, str] = {v: k for k, v in SYSTEM_MODULES.items()}

SYSTEM_ACTIONS: Dict[str, str] = {
    "act_create_sales": "إصدار فواتير المبيعات وإشعارات الدائن (مرتجع مبيعات)",
    "act_create_purchases": "تسجيل فواتير المشتريات وإشعارات المدين (مرتجع مشتريات)",
    "act_create_vouchers": "إصدار سندات القبض والصرف النقدية والبنكية",
    "act_create_journal": "تسجيل القيود اليومية العامة (مسودة أو ترحيل) والتسويات البنكية",
    "act_approve_journal": "اعتماد وترحيل القيود المسودة (Maker-Checker Approval)",
    "act_reverse_journal": "عكس / إلغاء القيود المحاسبية المرحلة في دفتر اليومية",
    "act_manage_inventory": "إضافة وتحديث بطاقات الأصناف والعملاء والموردين",
    "act_inventory_adjust": "اعتماد التسويات الجردية للمخزون (عجز / فائض)",
    "act_manage_assets": "إضافة الأصول الثابتة وتشغيل وترحيل قيد الإهلاك الدوري",
    "act_manage_payroll": "إدارة سجل الموظفين واعتماد وصرف مسير الرواتب الشهري",
    "act_manage_coa": "إضافة حسابات فرعية في شجرة الحسابات وإدارة مراكز التكلفة",
    "act_cpa_profiles": "حفظ وتعديل قوالب التوجيه المحاسبي في محلل الميزان (CPA)",
    "act_export_reports": "تصدير التقارير المالية (Excel / Word / PDF) والنسخ الاحتياطي",
    "act_close_year": "إقفال السنة المالية وقفل الفترات المحاسبية",
    "act_reset_db": "تصفير الحركات التجريبية لقاعدة البيانات (إجراء حساس)",
    "act_manage_settings": "تعديل إعدادات المنشأة والبيانات الضريبية",
    "act_manage_users": "إدارة المستخدمين وتخصيص الصلاحيات الحرة (RBAC / Custom)",
}

ALL_PERMISSION_KEYS: List[str] = list(SYSTEM_MODULES.keys()) + list(SYSTEM_ACTIONS.keys())


def get_default_permissions_for_role(role: Any) -> Dict[str, bool]:
    """إرجاع مصفوفة الصلاحيات الافتراضية لأي دور وظيفي لتكون نقطة انطلاق قابلة للتخصيص الحر"""
    role_str = role.value if hasattr(role, "value") else str(role)

    if role_str == UserRole.ADMIN.value:
        return {k: True for k in ALL_PERMISSION_KEYS}

    base = {k: False for k in ALL_PERMISSION_KEYS}

    if role_str == UserRole.ACCOUNTANT.value:
        for k in [
            "mod_dashboard", "mod_assets_hr", "mod_control", "mod_inventory",
            "mod_sales", "mod_purchases", "mod_treasury", "mod_journal",
            "mod_ledger", "mod_statements", "mod_settings",
            "act_create_sales", "act_create_purchases", "act_create_vouchers",
            "act_create_journal", "act_approve_journal", "act_reverse_journal", "act_manage_inventory",
            "act_inventory_adjust", "act_manage_assets", "act_manage_payroll",
            "act_manage_coa", "act_export_reports"
        ]:
            base[k] = True
        return base

    if role_str == UserRole.AUDITOR.value:
        for k in [
            "mod_dashboard", "mod_cpa", "mod_assets_hr", "mod_control",
            "mod_ledger", "mod_statements", "mod_settings",
            "act_cpa_profiles", "act_export_reports"
        ]:
            base[k] = True
        return base

    if role_str == UserRole.SALES.value:
        for k in [
            "mod_dashboard", "mod_inventory", "mod_sales", "mod_purchases", "mod_treasury",
            "act_create_sales", "act_create_purchases", "act_create_vouchers",
            "act_manage_inventory"
        ]:
            base[k] = True
        return base

    # دور CUSTOM (مخصص حر) يبدأ بلوحة التحكم وكشف الحساب كحد أدنى قابل للتعديل
    base["mod_dashboard"] = True
    base["mod_ledger"] = True
    return base


# =============================================================================
# 2. جدول إعدادات المنشأة والمستخدمين وقوالب الصلاحيات والتوجيه
# =============================================================================

class CompanySettings(Base):
    """جدول إعدادات المنشأة والبيانات الضريبية الموحدة"""
    __tablename__ = "company_settings"

    id = Column(Integer, primary_key=True, index=True)
    company_name_ar = Column(String(255), nullable=False, default="شركة ميزان برو التجارية")
    company_name_en = Column(String(255), nullable=True, default="MizanPro Trading Co.")
    vat_number = Column(String(15), nullable=False, default="300000000000003")
    cr_number = Column(String(50), nullable=True, default="1010889922")
    address_ar = Column(String(255), nullable=True, default="المملكة العربية السعودية - الرياض")
    phone = Column(String(50), nullable=True, default="+966 11 000 0000")
    email = Column(String(100), nullable=True, default="finance@mizanpro.sa")
    currency = Column(String(20), nullable=False, default="ريال")
    default_vat_rate = Column(Float, nullable=False, default=0.15)
    fiscal_year = Column(Integer, nullable=False, default=2026)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class AppUser(Base):
    """جدول المستخدمين والصلاحيات الرقابية المخصصة"""
    __tablename__ = "app_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    full_name_ar = Column(String(255), nullable=False)
    job_title = Column(String(150), nullable=True, default="مسؤول مالي")
    role = Column(SQLEnum(UserRole), default=UserRole.ADMIN, nullable=False)
    pin_code = Column(String(255), default=lambda: hash_pin_code("1234"), nullable=False)
    permissions_json = Column(Text, nullable=True)  # JSON dict of custom permissions {perm_key: bool}
    max_discount_pct = Column(Float, default=100.0, nullable=False)  # سقف نسبة الخصم المسموح بها للمستخدم (%)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    def verify_pin(self, entered_pin: str) -> bool:
        """التحقق المشفر من رمز الدخول السري للمستخدم"""
        return verify_pin_code(entered_pin, self.pin_code)

    def get_permissions(self) -> Dict[str, bool]:
        """استرجاع مصفوفة الصلاحيات الفعلية للمستخدم مع دمج التخصيص الحر"""
        defaults = get_default_permissions_for_role(self.role)
        if self.permissions_json:
            try:
                custom = json.loads(self.permissions_json)
                if isinstance(custom, dict):
                    for k in ALL_PERMISSION_KEYS:
                        if k in custom:
                            defaults[k] = bool(custom[k])
            except Exception:
                pass
        return defaults

    def has_permission(self, perm_key: str) -> bool:
        """التحقق مما إذا كان المستخدم يمتلك صلاحية شاشة أو عملية محددة"""
        if not self.is_active:
            return False
        perms = self.get_permissions()
        return bool(perms.get(perm_key, False))

    def get_allowed_menu_options(self) -> List[str]:
        """إرجاع قائمة الشاشات المسموح للمستخدم رؤيتها والدخول إليها في القائمة الجانبية"""
        perms = self.get_permissions()
        allowed = [label for mod_key, label in SYSTEM_MODULES.items() if perms.get(mod_key, False)]
        return allowed or [SYSTEM_MODULES["mod_dashboard"]]


class CustomRoleTemplate(Base):
    """جدول قوالب الأدوار الوظيفية المخصصة لإعادة استخدامها وتطبيقها على المستخدمين بضغطة زر"""
    __tablename__ = "custom_role_templates"

    id = Column(Integer, primary_key=True, index=True)
    template_name = Column(String(150), unique=True, index=True, nullable=False)
    description = Column(String(255), nullable=True)
    permissions_json = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class TBMappingProfile(Base):
    """جدول حفظ قوالب التوجيه المحاسبي لموازين المراجعة الخارجية (CPA Mapping Profiles)"""
    __tablename__ = "tb_mapping_profiles"

    id = Column(Integer, primary_key=True, index=True)
    profile_name = Column(String(150), unique=True, index=True, nullable=False)
    client_name = Column(String(255), nullable=True)
    mapping_json = Column(Text, nullable=False)  # JSON dict: {account_name_or_code: cpa_category_label}
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


# =============================================================================
# 3. جداول الهيكل المالي والمحاسبي (General Ledger Tables)
# =============================================================================

class FiscalPeriod(Base):
    """جدول الفترات المالية والسنوات المالية"""
    __tablename__ = "fiscal_periods"

    id = Column(Integer, primary_key=True, index=True)
    year = Column(Integer, nullable=False)
    start_date = Column(Date, nullable=False)
    end_date = Column(Date, nullable=False)
    is_closed = Column(Boolean, default=False, nullable=False)
    total_days = Column(Integer, nullable=False, default=365)

    entries = relationship("JournalEntry", back_populates="period")


class CostCenter(Base):
    """جدول مراكز التكلفة والمشاريع والفروع"""
    __tablename__ = "cost_centers"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(50), unique=True, index=True, nullable=False)
    name_ar = Column(String(255), nullable=False)
    name_en = Column(String(255), nullable=True)
    parent_id = Column(Integer, ForeignKey("cost_centers.id"), nullable=True)
    is_leaf = Column(Boolean, default=True, nullable=False)

    parent = relationship("CostCenter", remote_side=[id], backref="children")
    journal_lines = relationship("JournalLine", back_populates="cost_center")


class Account(Base):
    """جدول دليل الحسابات الشجري الموحد"""
    __tablename__ = "accounts"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(50), unique=True, index=True, nullable=False)
    name_ar = Column(String(255), nullable=False)
    name_en = Column(String(255), nullable=True)

    type = Column(SQLEnum(AccountType), nullable=False)
    sub_type = Column(SQLEnum(AccountSubType), nullable=False)
    natural_balance = Column(SQLEnum(NaturalBalance), nullable=False)

    parent_id = Column(Integer, ForeignKey("accounts.id"), nullable=True)
    level = Column(Integer, default=1, nullable=False)
    is_leaf = Column(Boolean, default=True, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    description = Column(String(500), nullable=True)

    parent = relationship("Account", remote_side=[id], backref="children")
    journal_lines = relationship("JournalLine", back_populates="account")


class JournalEntry(Base):
    """جدول رأس القيد اليومي (General Journal Header)"""
    __tablename__ = "journal_entries"

    id = Column(Integer, primary_key=True, index=True)
    entry_number = Column(String(50), unique=True, index=True, nullable=False)
    entry_date = Column(Date, default=date.today, nullable=False)
    period_id = Column(Integer, ForeignKey("fiscal_periods.id"), nullable=True)

    doc_type = Column(SQLEnum(DocumentType), default=DocumentType.JOURNAL_VOUCHER, nullable=False)
    reference = Column(String(100), nullable=True)
    description = Column(String(500), nullable=False)
    status = Column(SQLEnum(EntryStatus), default=EntryStatus.POSTED, nullable=False)

    total_debit = Column(Float, default=0.0, nullable=False)
    total_credit = Column(Float, default=0.0, nullable=False)

    is_reversal = Column(Boolean, default=False, nullable=False)
    reversed_entry_id = Column(Integer, ForeignKey("journal_entries.id"), nullable=True)

    created_at = Column(DateTime, default=utc_now, nullable=False)
    posted_at = Column(DateTime, default=utc_now, nullable=False)

    period = relationship("FiscalPeriod", back_populates="entries")
    lines = relationship("JournalLine", back_populates="entry", cascade="all, delete-orphan")


class JournalLine(Base):
    """جدول أسطر القيد المحاسبي (General Journal Lines)"""
    __tablename__ = "journal_lines"

    id = Column(Integer, primary_key=True, index=True)
    entry_id = Column(Integer, ForeignKey("journal_entries.id"), nullable=False, index=True)
    line_number = Column(Integer, default=1, nullable=False)

    account_id = Column(Integer, ForeignKey("accounts.id"), nullable=False, index=True)
    cost_center_id = Column(Integer, ForeignKey("cost_centers.id"), nullable=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    supplier_id = Column(Integer, ForeignKey("suppliers.id"), nullable=True)

    debit = Column(Float, default=0.0, nullable=False)
    credit = Column(Float, default=0.0, nullable=False)
    description = Column(String(255), nullable=True)

    entry = relationship("JournalEntry", back_populates="lines")
    account = relationship("Account", back_populates="journal_lines")
    cost_center = relationship("CostCenter", back_populates="journal_lines")


class AuditLog(Base):
    """جدول سجل الرقابة والتدقيق (Immutable Audit Trail)"""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    table_name = Column(String(50), nullable=False)
    record_id = Column(Integer, nullable=False)
    action = Column(String(50), nullable=False)
    performed_by = Column(String(100), default="مدير النظام (Admin)", nullable=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False)
    details = Column(Text, nullable=True)


# =============================================================================
# 4. جداول العملاء والموردين والأصناف وحركة المخزون (Master Data & Inventory)
# =============================================================================

class Customer(Base):
    """جدول العملاء التجاريين والأفراد"""
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(50), unique=True, index=True, nullable=False)
    name_ar = Column(String(255), nullable=False)
    name_en = Column(String(255), nullable=True)
    vat_number = Column(String(15), nullable=True)
    cr_number = Column(String(50), nullable=True)
    phone = Column(String(50), nullable=True)
    email = Column(String(100), nullable=True)
    address = Column(String(255), nullable=True)
    credit_limit = Column(Float, default=0.0, nullable=False)

    account_id = Column(Integer, ForeignKey("accounts.id"), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    invoices = relationship("SalesInvoice", back_populates="customer")


class Supplier(Base):
    """جدول الموردين التجاريين"""
    __tablename__ = "suppliers"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(50), unique=True, index=True, nullable=False)
    name_ar = Column(String(255), nullable=False)
    name_en = Column(String(255), nullable=True)
    vat_number = Column(String(15), nullable=True)
    cr_number = Column(String(50), nullable=True)
    phone = Column(String(50), nullable=True)
    email = Column(String(100), nullable=True)
    address = Column(String(255), nullable=True)

    account_id = Column(Integer, ForeignKey("accounts.id"), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)


class Product(Base):
    """جدول الأصناف والخدمات المخزنية مع التقييم بالمتوسط المرجح"""
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(50), unique=True, index=True, nullable=False)
    barcode = Column(String(100), unique=True, nullable=True)
    name_ar = Column(String(255), nullable=False)
    name_en = Column(String(255), nullable=True)
    category = Column(String(100), default="عام", nullable=True)
    unit = Column(String(50), default="حبة", nullable=False)

    stock_quantity = Column(Float, default=0.0, nullable=False)
    reorder_level = Column(Float, default=5.0, nullable=False)
    cost_price = Column(Float, default=0.0, nullable=False)
    sale_price = Column(Float, default=0.0, nullable=False)
    tax_rate = Column(Float, default=0.15, nullable=False)

    is_service = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    invoice_items = relationship("SalesInvoiceItem", back_populates="product")
    inventory_transactions = relationship("InventoryTransaction", back_populates="product")


class InventoryTransaction(Base):
    """جدول سجل حركات المخزون التفصيلي (كارت الصنف)"""
    __tablename__ = "inventory_transactions"

    id = Column(Integer, primary_key=True, index=True)
    tx_date = Column(Date, default=date.today, nullable=False)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=False, index=True)
    tx_type = Column(SQLEnum(InventoryTxType), nullable=False)
    reference_number = Column(String(50), nullable=False)

    quantity_in = Column(Float, default=0.0, nullable=False)
    quantity_out = Column(Float, default=0.0, nullable=False)
    balance_after = Column(Float, default=0.0, nullable=False)

    unit_cost = Column(Float, default=0.0, nullable=False)
    total_cost = Column(Float, default=0.0, nullable=False)

    journal_entry_id = Column(Integer, ForeignKey("journal_entries.id"), nullable=True)
    notes = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    product = relationship("Product", back_populates="inventory_transactions")
    journal_entry = relationship("JournalEntry")


# =============================================================================
# 5. جداول دورة المبيعات والمشتريات (Sales & Purchase Invoices)
# =============================================================================

class SalesInvoice(Base):
    """جدول فواتير المبيعات الضريبية (ZATCA E-Invoicing)"""
    __tablename__ = "sales_invoices"

    id = Column(Integer, primary_key=True, index=True)
    invoice_number = Column(String(50), unique=True, index=True, nullable=False)
    invoice_date = Column(Date, default=date.today, nullable=False)
    due_date = Column(Date, nullable=True)

    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    customer_name = Column(String(255), nullable=False)
    customer_vat_number = Column(String(15), nullable=True)
    cost_center_id = Column(Integer, ForeignKey("cost_centers.id"), nullable=True)

    payment_method = Column(SQLEnum(PaymentMethod), default=PaymentMethod.CASH, nullable=False)
    invoice_type = Column(SQLEnum(InvoiceType), default=InvoiceType.SIMPLIFIED, nullable=False)

    subtotal = Column(Float, default=0.0, nullable=False)
    discount_amount = Column(Float, default=0.0, nullable=False)
    taxable_amount = Column(Float, default=0.0, nullable=False)
    vat_amount = Column(Float, default=0.0, nullable=False)
    grand_total = Column(Float, default=0.0, nullable=False)
    total_cost = Column(Float, default=0.0, nullable=False)

    journal_entry_id = Column(Integer, ForeignKey("journal_entries.id"), nullable=True)
    cogs_entry_id = Column(Integer, ForeignKey("journal_entries.id"), nullable=True)

    qr_code_base64 = Column(Text, nullable=True)
    notes = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    customer = relationship("Customer", back_populates="invoices")
    cost_center = relationship("CostCenter")
    items = relationship("SalesInvoiceItem", back_populates="invoice", cascade="all, delete-orphan")
    journal_entry = relationship("JournalEntry", foreign_keys=[journal_entry_id])
    cogs_entry = relationship("JournalEntry", foreign_keys=[cogs_entry_id])


class SalesInvoiceItem(Base):
    """جدول بنود وأسطر فاتورة المبيعات"""
    __tablename__ = "sales_invoice_items"

    id = Column(Integer, primary_key=True, index=True)
    invoice_id = Column(Integer, ForeignKey("sales_invoices.id"), nullable=False)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=True)

    item_name = Column(String(255), nullable=False)
    quantity = Column(Float, default=1.0, nullable=False)
    unit_price = Column(Float, default=0.0, nullable=False)
    cost_price = Column(Float, default=0.0, nullable=False)
    discount = Column(Float, default=0.0, nullable=False)

    taxable_amount = Column(Float, default=0.0, nullable=False)
    tax_rate = Column(Float, default=0.15, nullable=False)
    tax_amount = Column(Float, default=0.0, nullable=False)
    total_with_tax = Column(Float, default=0.0, nullable=False)

    invoice = relationship("SalesInvoice", back_populates="items")
    product = relationship("Product", back_populates="invoice_items")


class PurchaseInvoice(Base):
    """جدول فواتير المشتريات وسندات الاستلام المخزني"""
    __tablename__ = "purchase_invoices"

    id = Column(Integer, primary_key=True, index=True)
    invoice_number = Column(String(50), unique=True, index=True, nullable=False)
    supplier_invoice_number = Column(String(100), nullable=True)
    invoice_date = Column(Date, default=date.today, nullable=False)
    due_date = Column(Date, nullable=True)

    supplier_id = Column(Integer, ForeignKey("suppliers.id"), nullable=True)
    supplier_name = Column(String(255), nullable=False)
    supplier_vat_number = Column(String(15), nullable=True)
    cost_center_id = Column(Integer, ForeignKey("cost_centers.id"), nullable=True)

    payment_method = Column(SQLEnum(PaymentMethod), default=PaymentMethod.CREDIT, nullable=False)

    subtotal = Column(Float, default=0.0, nullable=False)
    discount_amount = Column(Float, default=0.0, nullable=False)
    taxable_amount = Column(Float, default=0.0, nullable=False)
    vat_amount = Column(Float, default=0.0, nullable=False)
    grand_total = Column(Float, default=0.0, nullable=False)

    journal_entry_id = Column(Integer, ForeignKey("journal_entries.id"), nullable=True)
    notes = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    supplier = relationship("Supplier", backref="purchase_invoices")
    cost_center = relationship("CostCenter")
    items = relationship("PurchaseInvoiceItem", back_populates="invoice", cascade="all, delete-orphan")
    journal_entry = relationship("JournalEntry", foreign_keys=[journal_entry_id])


class PurchaseInvoiceItem(Base):
    """جدول بنود وأسطر فاتورة المشتريات"""
    __tablename__ = "purchase_invoice_items"

    id = Column(Integer, primary_key=True, index=True)
    invoice_id = Column(Integer, ForeignKey("purchase_invoices.id"), nullable=False)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=True)

    item_name = Column(String(255), nullable=False)
    quantity = Column(Float, default=1.0, nullable=False)
    unit_price = Column(Float, default=0.0, nullable=False)
    discount = Column(Float, default=0.0, nullable=False)

    taxable_amount = Column(Float, default=0.0, nullable=False)
    tax_rate = Column(Float, default=0.15, nullable=False)
    tax_amount = Column(Float, default=0.0, nullable=False)
    total_with_tax = Column(Float, default=0.0, nullable=False)

    invoice = relationship("PurchaseInvoice", back_populates="items")
    product = relationship("Product")


# =============================================================================
# 6. جداول إشعارات الدائن والمدين وسندات القبض والصرف
# =============================================================================

class CreditDebitNote(Base):
    """جدول إشعارات الدائن (مرتجعات المبيعات) وإشعارات المدين (مرتجعات المشتريات)"""
    __tablename__ = "credit_debit_notes"

    id = Column(Integer, primary_key=True, index=True)
    note_number = Column(String(50), unique=True, index=True, nullable=False)
    note_type = Column(SQLEnum(NoteType), nullable=False)
    note_date = Column(Date, default=date.today, nullable=False)

    original_invoice_number = Column(String(50), nullable=True)
    sales_invoice_id = Column(Integer, ForeignKey("sales_invoices.id"), nullable=True)
    purchase_invoice_id = Column(Integer, ForeignKey("purchase_invoices.id"), nullable=True)

    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    supplier_id = Column(Integer, ForeignKey("suppliers.id"), nullable=True)
    party_name = Column(String(255), nullable=False)
    party_vat_number = Column(String(15), nullable=True)

    payment_method = Column(SQLEnum(PaymentMethod), default=PaymentMethod.CREDIT, nullable=False)
    reason = Column(String(255), nullable=False, default="مرتجع بضاعة طبقاً للاتفاق")

    subtotal = Column(Float, default=0.0, nullable=False)
    taxable_amount = Column(Float, default=0.0, nullable=False)
    vat_amount = Column(Float, default=0.0, nullable=False)
    grand_total = Column(Float, default=0.0, nullable=False)
    total_cost_reversal = Column(Float, default=0.0, nullable=False)

    journal_entry_id = Column(Integer, ForeignKey("journal_entries.id"), nullable=True)
    cogs_entry_id = Column(Integer, ForeignKey("journal_entries.id"), nullable=True)
    qr_code_base64 = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    items = relationship("CreditDebitNoteItem", back_populates="note", cascade="all, delete-orphan")
    journal_entry = relationship("JournalEntry", foreign_keys=[journal_entry_id])
    cogs_entry = relationship("JournalEntry", foreign_keys=[cogs_entry_id])


class CreditDebitNoteItem(Base):
    """جدول بنود إشعار الدائن أو المدين"""
    __tablename__ = "credit_debit_note_items"

    id = Column(Integer, primary_key=True, index=True)
    note_id = Column(Integer, ForeignKey("credit_debit_notes.id"), nullable=False)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=True)

    item_name = Column(String(255), nullable=False)
    quantity = Column(Float, default=1.0, nullable=False)
    unit_price = Column(Float, default=0.0, nullable=False)
    cost_price = Column(Float, default=0.0, nullable=False)

    taxable_amount = Column(Float, default=0.0, nullable=False)
    tax_rate = Column(Float, default=0.15, nullable=False)
    tax_amount = Column(Float, default=0.0, nullable=False)
    total_with_tax = Column(Float, default=0.0, nullable=False)

    note = relationship("CreditDebitNote", back_populates="items")
    product = relationship("Product")


class CashVoucher(Base):
    """جدول سندات القبض وسندات الصرف النقدية والبنكية"""
    __tablename__ = "cash_vouchers"

    id = Column(Integer, primary_key=True, index=True)
    voucher_number = Column(String(50), unique=True, index=True, nullable=False)
    voucher_type = Column(SQLEnum(VoucherType), nullable=False)
    voucher_date = Column(Date, default=date.today, nullable=False)

    payment_method = Column(SQLEnum(PaymentMethod), default=PaymentMethod.CASH, nullable=False)
    party_type = Column(SQLEnum(VoucherPartyType), default=VoucherPartyType.CUSTOMER, nullable=False)

    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    supplier_id = Column(Integer, ForeignKey("suppliers.id"), nullable=True)
    cost_center_id = Column(Integer, ForeignKey("cost_centers.id"), nullable=True)
    target_account_code = Column(String(50), nullable=False)
    party_name = Column(String(255), nullable=False)

    amount_before_vat = Column(Float, default=0.0, nullable=False)
    vat_amount = Column(Float, default=0.0, nullable=False)
    total_amount = Column(Float, default=0.0, nullable=False)

    reference_number = Column(String(100), nullable=True)
    description = Column(String(500), nullable=False)
    journal_entry_id = Column(Integer, ForeignKey("journal_entries.id"), nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    customer = relationship("Customer")
    supplier = relationship("Supplier")
    cost_center = relationship("CostCenter")
    journal_entry = relationship("JournalEntry")


# =============================================================================
# 7. جداول سجل الأصول الثابتة والموظفين ومسير الرواتب (Fixed Assets & Payroll)
# =============================================================================

class FixedAsset(Base):
    """جدول سجل الأصول الثابتة الملموسة واحتساب الإهلاك التلقائي (IAS 16)"""
    __tablename__ = "fixed_assets"

    id = Column(Integer, primary_key=True, index=True)
    asset_code = Column(String(50), unique=True, index=True, nullable=False)
    name_ar = Column(String(255), nullable=False)
    category = Column(String(100), nullable=False, default="السيارات ووسائل النقل")
    purchase_date = Column(Date, default=date.today, nullable=False)

    purchase_cost = Column(Float, default=0.0, nullable=False)
    salvage_value = Column(Float, default=0.0, nullable=False)
    useful_life_years = Column(Float, default=5.0, nullable=False)
    depreciation_rate = Column(Float, default=0.20, nullable=False)

    accumulated_depreciation = Column(Float, default=0.0, nullable=False)
    net_book_value = Column(Float, default=0.0, nullable=False)

    asset_account_code = Column(String(50), default="120103", nullable=False)
    accum_dep_account_code = Column(String(50), default="120203", nullable=False)
    dep_expense_account_code = Column(String(50), default="5207", nullable=False)
    cost_center_id = Column(Integer, ForeignKey("cost_centers.id"), nullable=True)
    last_depreciation_date = Column(Date, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    cost_center = relationship("CostCenter")


class Employee(Base):
    """جدول سجل الموظفين والرواتب ومكافأة نهاية الخدمة (نظام العمل السعودي)"""
    __tablename__ = "employees"

    id = Column(Integer, primary_key=True, index=True)
    emp_code = Column(String(50), unique=True, index=True, nullable=False)
    name_ar = Column(String(255), nullable=False)
    job_title = Column(String(150), nullable=True, default="محاسب")
    nationality = Column(String(100), nullable=False, default="سعودي")
    is_saudi = Column(Boolean, default=True, nullable=False)
    join_date = Column(Date, default=date(2024, 1, 1), nullable=False)

    basic_salary = Column(Float, default=0.0, nullable=False)
    housing_allowance = Column(Float, default=0.0, nullable=False)
    transport_allowance = Column(Float, default=0.0, nullable=False)
    other_allowance = Column(Float, default=0.0, nullable=False)

    cost_center_id = Column(Integer, ForeignKey("cost_centers.id"), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    cost_center = relationship("CostCenter")


class PayrollRun(Base):
    """جدول مسيرات الرواتب الشهرية المرحلة"""
    __tablename__ = "payroll_runs"

    id = Column(Integer, primary_key=True, index=True)
    payroll_number = Column(String(50), unique=True, index=True, nullable=False)
    period_month = Column(String(20), nullable=False)
    payment_date = Column(Date, default=date.today, nullable=False)
    payment_method = Column(SQLEnum(PaymentMethod), default=PaymentMethod.BANK, nullable=False)

    employees_count = Column(Integer, default=0, nullable=False)
    total_gross_salaries = Column(Float, default=0.0, nullable=False)
    total_gosi_employee = Column(Float, default=0.0, nullable=False)
    total_gosi_employer = Column(Float, default=0.0, nullable=False)
    total_eos_accrual = Column(Float, default=0.0, nullable=False)
    net_paid_salaries = Column(Float, default=0.0, nullable=False)

    journal_entry_id = Column(Integer, ForeignKey("journal_entries.id"), nullable=True)
    notes = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    journal_entry = relationship("JournalEntry")


class Warehouse(Base):
    """جدول المستودعات والفروع المخزنية المتعددة"""
    __tablename__ = "warehouses"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(50), unique=True, index=True, nullable=False)
    name_ar = Column(String(255), nullable=False)
    location = Column(String(255), nullable=True, default="الرياض")
    manager_name = Column(String(150), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)


class WarehouseStock(Base):
    """جدول أرصدة الأصناف تفصيلياً داخل كل مستودع فرعي"""
    __tablename__ = "warehouse_stocks"

    id = Column(Integer, primary_key=True, index=True)
    warehouse_id = Column(Integer, ForeignKey("warehouses.id"), nullable=False)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=False)
    quantity = Column(Float, default=0.0, nullable=False)

    warehouse = relationship("Warehouse")
    product = relationship("Product")
