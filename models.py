"""
MizanPro - Enterprise Accounting, Inventory, Treasury, Fixed Assets, Payroll, Audit & Compliance Data Models
النظام المالي المتكامل - ميزان برو
ملف نماذج الجداول المحاسبية والمخزنية والسندات والأصول الثابتة والرواتب والصلاحيات الحرة ودورات المبيعات والمشتريات
"""

from datetime import datetime, date, timezone
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation
import enum
import hashlib
import hmac
import json
import secrets
import re
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy import (
    Column, Integer, String, Numeric, Boolean, Date, DateTime,
    ForeignKey, Enum as SQLEnum, Text, TypeDecorator, event, inspect as sa_inspect, text
)
from sqlalchemy.orm import relationship, Session
from database import Base


class AuditLogReadOnlyError(PermissionError):
    """خطأ أمني ورقابي يُرفع عند محاولة تعديل أو حذف أي سجل من سجل التدقيق الإلزامي للقراءة فقط (ZATCA Read-Only Audit Log)"""
    pass


AUDIT_GENESIS_HASH = "0" * 64



def utc_now() -> datetime:
    """إرجاع التوقيت العالمي الحالي بصيغة متوافقة مع كافة إصدارات Python"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# =============================================================================
# 0.أ محرك الدقة العشرية وقواعد التقريب المحاسبي والضريبي (ZATCA Decimal Engine)
# =============================================================================

MONEY_QUANTIZER = Decimal("0.01")
RATE_QUANTIZER = Decimal("0.0001")
ROUNDING_MODE = ROUND_HALF_UP


def to_decimal(val: Any, default: str = "0.00") -> Decimal:
    """تحويل آمن لأي قيمة رقمية أو نصية إلى Decimal دون أخطاء الفاصلة العائمة الثنائية"""
    if val is None or val == "":
        return Decimal(default)
    if isinstance(val, Decimal):
        return val
    if isinstance(val, (int,)):
        return Decimal(val)
    if isinstance(val, float):
        return Decimal(f"{val:.6f}")
    try:
        return Decimal(str(val).strip().replace(",", ""))
    except (InvalidOperation, ValueError):
        return Decimal(default)


def quantize_money(val: Any) -> Decimal:
    """تقريب المبالغ المالية إلى هللتين (0.01) وفق قاعدة التقريب التجاري والضريبي (ROUND_HALF_UP)"""
    return to_decimal(val).quantize(MONEY_QUANTIZER, rounding=ROUNDING_MODE)


def round_money(val: Any) -> float:
    """إرجاع المبلغ المالي مقرباً بدقة Decimal (ROUND_HALF_UP) كقيمة رقمية متوافقة مع الجداول والرسوم"""
    return float(quantize_money(val))


def quantize_rate(val: Any) -> Decimal:
    """تقريب النسب والكميات وتكاليف الوحدة إلى 4 منازل عشرية (0.0001)"""
    return to_decimal(val).quantize(RATE_QUANTIZER, rounding=ROUNDING_MODE)


def round_rate(val: Any) -> float:
    return float(quantize_rate(val))


def calculate_line_and_tax_amounts(
    quantity: Any,
    unit_price: Any,
    discount: Any = "0.00",
    tax_rate: Any = "0.15"
) -> Dict[str, Decimal]:
    """
    القاعدة الرسمية لاحتساب وتقريب سطور الفواتير والإشعارات الضريبية (ZATCA E-Invoicing Rounding Rules):
    1. إجمالي السطر قبل الخصم = تقريب(الكمية × سعر الوحدة، 0.01، ROUND_HALF_UP)
    2. الصافي الخاضع للضريبة = تقريب(إجمالي السطر - الخصم، 0.01، ROUND_HALF_UP)
    3. ضريبة القيمة المضافة للسطر = تقريب(الصافي الخاضع للضريبة × نسبة الضريبة، 0.01، ROUND_HALF_UP)
    4. إجمالي السطر شامل الضريبة = الصافي الخاضع للضريبة + ضريبة السطر
    """
    qty_d = quantize_rate(quantity)
    price_d = quantize_rate(unit_price)
    disc_d = quantize_money(discount)
    rate_d = quantize_rate(tax_rate)

    gross_d = quantize_money(qty_d * price_d)
    if disc_d > gross_d:
        disc_d = gross_d
    taxable_d = quantize_money(gross_d - disc_d)
    vat_d = quantize_money(taxable_d * rate_d)
    total_d = quantize_money(taxable_d + vat_d)

    return {
        "quantity": qty_d,
        "unit_price": price_d,
        "discount": disc_d,
        "tax_rate": rate_d,
        "gross_amount": gross_d,
        "taxable_amount": taxable_d,
        "tax_amount": vat_d,
        "total_with_tax": total_d,
    }


class MoneyAmount(TypeDecorator):
    """نوع عمود محاسبي عشري دقيق (Numeric 18,2) يحفظ المبالغ بعد تقريبها بـ ROUND_HALF_UP ويمنع أخطاء Float"""
    impl = Numeric(18, 2)
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> Optional[Decimal]:
        if value is None:
            return Decimal("0.00")
        return quantize_money(value)

    def process_result_value(self, value: Any, dialect: Any) -> float:
        if value is None:
            return 0.0
        return float(quantize_money(value))


class RateAmount(TypeDecorator):
    """نوع عمود عشري للكميات والنسب وتكلفة الوحدة بالمتوسط المرجح (Numeric 18,4)"""
    impl = Numeric(18, 4)
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> Optional[Decimal]:
        if value is None:
            return Decimal("0.0000")
        return quantize_rate(value)

    def process_result_value(self, value: Any, dialect: Any) -> float:
        if value is None:
            return 0.0
        return float(quantize_rate(value))


# =============================================================================
# 0.ب دوال التشفير والتجزئة الآمنة لرموز الدخول (PIN Hashing - PBKDF2-HMAC-SHA256)
# =============================================================================

PIN_HASH_PREFIX = "pbkdf2_sha256$"
LEGACY_COMPROMISED_PINS = {"1234", "1111", "2222", "3333", "5555", "0000", "123456", "654321"}


def generate_random_pin(length: int = 6) -> str:
    """توليد رمز دخول سري عشوائي آمن криптоغرافياً (CSPRNG) غير متوقع"""
    rng = secrets.SystemRandom()
    while True:
        pin = "".join(str(rng.randrange(0, 10)) for _ in range(max(6, length)))
        if pin not in LEGACY_COMPROMISED_PINS and len(set(pin)) >= 3:
            return pin


def is_compromised_or_weak_pin(plain_pin: str) -> bool:
    """فحص ما إذا كان الرمز السري من الرموز الافتراضية المكشوفة سابقاً أو ضعيفاً"""
    cand = str(plain_pin or "").strip()
    if len(cand) < 6 or cand in LEGACY_COMPROMISED_PINS:
        return True
    if len(set(cand)) == 1:
        return True
    return False


def hash_pin_code(plain_pin: str, salt: Optional[str] = None) -> str:
    """تجزئة رمز الدخول السري (PIN) بخوارزمية PBKDF2-HMAC-SHA256 مع Salt عشوائي"""
    raw = str(plain_pin or "").strip()
    if raw.startswith(PIN_HASH_PREFIX):
        return raw
    salt_str = salt or secrets.token_hex(8)
    dk = hashlib.pbkdf2_hmac("sha256", raw.encode("utf-8"), salt_str.encode("utf-8"), 100_000)
    return f"{PIN_HASH_PREFIX}{salt_str}${dk.hex()}"


def verify_pin_code(plain_pin: str, stored_pin: str) -> bool:
    """التحقق الآمن من تطابق رمز الدخول السري مع القيمة المخزنة (يرفض النسخ المطهرة أو الفارغة)"""
    candidate = str(plain_pin or "").strip()
    stored = str(stored_pin or "").strip()
    if not candidate or not stored or stored == "REDACTED_IN_BACKUP":
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
    "mod_audit_log": "🔍 سجل التدقيق الرقابي للقراءة فقط (ZATCA Audit Log)",
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
    "act_export_reports": "تصدير التقارير المالية (Excel / Word / PDF)",
    "act_view_audit_logs": "الاطلاع على سجل التدقيق الرقابي للقراءة فقط وفلترته وتصديره (ZATCA Audit Log)",
    "act_cloud_backup": "الوصول لمركز Google Drive السحابي وتصدير/استعادة النسخ الاحتياطية",
    "act_close_year": "إقفال السنة المالية وقفل الفترات المحاسبية",
    "act_reset_db": "تصفير الحركات التجريبية لقاعدة البيانات (إجراء حساس)",
    "act_manage_settings": "تعديل إعدادات المنشأة والبيانات الضريبية",
    "act_manage_users": "إدارة المستخدمين وتخصيص الصلاحيات الحرة (RBAC / Custom)",
}

ALL_PERMISSION_KEYS: List[str] = list(SYSTEM_MODULES.keys()) + list(SYSTEM_ACTIONS.keys())


# تصنيف أنواع المعاملات المالية في سجل التدقيق الرقابي وفق متطلبات الشفافية لهيئة الزكاة والضريبة والجمارك (ZATCA)
AUDIT_TRANSACTION_TYPES: Dict[str, Dict[str, Any]] = {
    "SALES_INVOICES": {
        "label_ar": "🧾 فواتير المبيعات الضريبية (Sales Invoices)",
        "tables": {"sales_invoices"},
        "action_keywords": ("SALES_INVOICE",),
    },
    "PURCHASE_INVOICES": {
        "label_ar": "📥 فواتير المشتريات الضريبية (Purchase Invoices)",
        "tables": {"purchase_invoices"},
        "action_keywords": ("PURCHASE_INVOICE",),
    },
    "CREDIT_DEBIT_NOTES": {
        "label_ar": "🔄 الإشعارات الدائنة والمدينة والمرتجعات (Credit & Debit Notes)",
        "tables": {"credit_debit_notes"},
        "action_keywords": ("CREDIT_NOTE", "DEBIT_NOTE", "CREDIT_DEBIT_NOTE"),
    },
    "CASH_BANK_VOUCHERS": {
        "label_ar": "💸 سندات القبض والصرف والخزينة (Cash & Bank Vouchers)",
        "tables": {"cash_vouchers"},
        "action_keywords": ("VOUCHER", "CASH_VOUCHER"),
    },
    "JOURNAL_ENTRIES": {
        "label_ar": "✍️ قيود اليومية العامة والتسويات وعكس القيود (Journal Entries)",
        "tables": {"journal_entries"},
        "action_keywords": ("JOURNAL", "APPROVE_DRAFT", "REVERSE_JOURNAL", "BANK_RECONCILIATION"),
    },
    "INVENTORY_WAREHOUSES": {
        "label_ar": "📦 المخزون والتسويات الجردية والمستودعات (Inventory & Warehouses)",
        "tables": {"inventory_transactions", "products", "warehouse_stocks", "warehouses"},
        "action_keywords": ("INVENTORY", "WAREHOUSE", "PRODUCT"),
    },
    "FIXED_ASSETS_PAYROLL": {
        "label_ar": "🏗️ الأصول الثابتة والإهلاك ومسيرات الرواتب (Assets & Payroll)",
        "tables": {"fixed_assets", "payroll_runs", "employees"},
        "action_keywords": ("ASSET", "DEPRECIATION", "PAYROLL", "EMPLOYEE"),
    },
    "PARTIES_ACCOUNTS": {
        "label_ar": "👥 العملاء والموردون وشجرة الحسابات (Parties & COA)",
        "tables": {"customers", "suppliers", "accounts", "cost_centers"},
        "action_keywords": ("CUSTOMER", "SUPPLIER", "ACCOUNT", "COST_CENTER"),
    },
    "FISCAL_CLOSING": {
        "label_ar": "🔒 إقفال الفترات والسنوات المالية (Fiscal Period Closing)",
        "tables": {"fiscal_periods"},
        "action_keywords": ("CLOSE_FISCAL", "FISCAL_PERIOD"),
    },
    "SECURITY_SETTINGS": {
        "label_ar": "⚙️ إعدادات المنشأة والأمن وصلاحيات المستخدمين (Settings & Security)",
        "tables": {"company_settings", "app_users", "custom_role_templates"},
        "action_keywords": ("USER", "LOGIN", "PIN", "SETTINGS", "ROLE_TEMPLATE", "RESET"),
    },
}


def classify_audit_transaction_type(table_name: Optional[str], action: Optional[str]) -> str:
    """تصنيف سجل التدقيق الرقابي إلى نوع معاملة مالية معياري لغايات الفلترة والتقارير الرقابية"""
    tbl = (table_name or "").strip().lower()
    act = (action or "").strip().upper()

    for tx_key, meta in AUDIT_TRANSACTION_TYPES.items():
        if tbl in meta["tables"]:
            return tx_key
    for tx_key, meta in AUDIT_TRANSACTION_TYPES.items():
        if any(kw in act for kw in meta["action_keywords"]):
            return tx_key
    return "SECURITY_SETTINGS"


def get_audit_transaction_type_label(tx_type_key: str) -> str:
    """إرجاع المسمى العربي الواضح لنوع المعاملة المالية في سجل التدقيق"""
    meta = AUDIT_TRANSACTION_TYPES.get((tx_type_key or "").strip().upper())
    if meta:
        return meta["label_ar"]
    return "📋 معاملات أخرى (Other Transactions)"


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
            "mod_ledger", "mod_statements", "mod_audit_log", "mod_settings",
            "act_cpa_profiles", "act_export_reports", "act_view_audit_logs"
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
    default_vat_rate = Column(RateAmount(), nullable=False, default=Decimal("0.1500"))
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
    pin_code = Column(String(255), default=lambda: hash_pin_code(generate_random_pin(6)), nullable=False)
    must_change_pin = Column(Boolean, default=True, nullable=False)
    permissions_json = Column(Text, nullable=True)  # JSON dict of custom permissions {perm_key: bool}
    max_discount_pct = Column(MoneyAmount(), default=Decimal("100.00"), nullable=False)  # سقف نسبة الخصم المسموح بها للمستخدم (%)
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

    total_debit = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    total_credit = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)

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

    debit = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    credit = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    description = Column(String(255), nullable=True)

    entry = relationship("JournalEntry", back_populates="lines")
    account = relationship("Account", back_populates="journal_lines")
    cost_center = relationship("CostCenter", back_populates="journal_lines")


class AuditLog(Base):
    """
    جدول سجل الرقابة والتدقيق الإلزامي للقراءة فقط (ZATCA Read-Only / Append-Only Immutable Audit Trail)
    يوثق كل عملية إنشاء أو تعديل أو عكس للمعاملات المالية مع الطابع الزمني الدقيق ومعرف المستخدم وبصمة التشفير المتسلسلة.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    table_name = Column(String(50), nullable=False, index=True)
    record_id = Column(Integer, nullable=False, index=True)
    action = Column(String(50), nullable=False, index=True)
    user_id = Column(String(64), default="USR-001", nullable=False, index=True)
    username = Column(String(100), default="admin", nullable=True, index=True)
    performed_by = Column(String(150), default="مدير النظام (Admin)", nullable=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)
    reference_number = Column(String(100), nullable=True, index=True)
    financial_amount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=True)
    old_values_json = Column(Text, nullable=True)
    new_values_json = Column(Text, nullable=True)
    details = Column(Text, nullable=True)
    previous_hash = Column(String(64), default=AUDIT_GENESIS_HASH, nullable=False)
    entry_hash = Column(String(64), nullable=True, index=True)



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
    credit_limit = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)

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

    stock_quantity = Column(RateAmount(), default=Decimal("0.0000"), nullable=False)
    reorder_level = Column(RateAmount(), default=Decimal("5.0000"), nullable=False)
    cost_price = Column(RateAmount(), default=Decimal("0.0000"), nullable=False)
    sale_price = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    tax_rate = Column(RateAmount(), default=Decimal("0.1500"), nullable=False)

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

    quantity_in = Column(RateAmount(), default=Decimal("0.0000"), nullable=False)
    quantity_out = Column(RateAmount(), default=Decimal("0.0000"), nullable=False)
    balance_after = Column(RateAmount(), default=Decimal("0.0000"), nullable=False)

    unit_cost = Column(RateAmount(), default=Decimal("0.0000"), nullable=False)
    total_cost = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)

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

    subtotal = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    discount_amount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    taxable_amount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    vat_amount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    grand_total = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    total_cost = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)

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
    quantity = Column(RateAmount(), default=Decimal("1.0000"), nullable=False)
    unit_price = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    cost_price = Column(RateAmount(), default=Decimal("0.0000"), nullable=False)
    discount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)

    taxable_amount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    tax_rate = Column(RateAmount(), default=Decimal("0.1500"), nullable=False)
    tax_amount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    total_with_tax = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)

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

    subtotal = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    discount_amount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    taxable_amount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    vat_amount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    grand_total = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)

    journal_entry_id = Column(Integer, ForeignKey("journal_entries.id"), nullable=True)
    qr_code_base64 = Column(Text, nullable=True)
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
    quantity = Column(RateAmount(), default=Decimal("1.0000"), nullable=False)
    unit_price = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    discount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)

    taxable_amount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    tax_rate = Column(RateAmount(), default=Decimal("0.1500"), nullable=False)
    tax_amount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    total_with_tax = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)

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

    subtotal = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    taxable_amount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    vat_amount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    grand_total = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    total_cost_reversal = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)

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
    quantity = Column(RateAmount(), default=Decimal("1.0000"), nullable=False)
    unit_price = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    cost_price = Column(RateAmount(), default=Decimal("0.0000"), nullable=False)

    taxable_amount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    tax_rate = Column(RateAmount(), default=Decimal("0.1500"), nullable=False)
    tax_amount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    total_with_tax = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)

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

    amount_before_vat = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    vat_amount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    total_amount = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)

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

    purchase_cost = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    salvage_value = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    useful_life_years = Column(RateAmount(), default=Decimal("5.0000"), nullable=False)
    depreciation_rate = Column(RateAmount(), default=Decimal("0.2000"), nullable=False)

    accumulated_depreciation = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    net_book_value = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)

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

    basic_salary = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    housing_allowance = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    transport_allowance = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    other_allowance = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)

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
    total_gross_salaries = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    total_gosi_employee = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    total_gosi_employer = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    total_eos_accrual = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)
    net_paid_salaries = Column(MoneyAmount(), default=Decimal("0.00"), nullable=False)

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
    quantity = Column(RateAmount(), default=Decimal("0.0000"), nullable=False)

    warehouse = relationship("Warehouse")
    product = relationship("Product")


# =============================================================================
# 7. محرك الحماية الصارمة لسجل التدقيق للقراءة فقط (ZATCA Read-Only Audit Engine)
# =============================================================================

def compute_audit_entry_hash(
    previous_hash: Optional[str],
    timestamp: Optional[datetime],
    user_id: Optional[str],
    username: Optional[str],
    performed_by: Optional[str],
    table_name: Optional[str],
    record_id: Optional[int],
    action: Optional[str],
    reference_number: Optional[str] = None,
    financial_amount: Any = 0.0,
    details: Optional[str] = None,
) -> str:
    """حساب البصمة التشفيرية المتسلسلة (SHA-256 Chain Hash) لسجل التدقيق لمنع أي تلاعب أو تعديل لاحق"""
    prev_h = (previous_hash or AUDIT_GENESIS_HASH).strip()
    if isinstance(timestamp, datetime):
        ts_str = timestamp.strftime("%Y-%m-%dT%H:%M:%S")
    else:
        ts_str = str(timestamp or "").strip().replace(" ", "T")[:19]
    uid_str = str(user_id or "USR-001").strip()
    uname_str = str(username or "admin").strip()
    actor_str = str(performed_by or "").strip()
    tbl_str = str(table_name or "").strip()
    rec_str = str(record_id if record_id is not None else 0)
    act_str = str(action or "").strip()
    ref_str = str(reference_number or "").strip()
    amt_str = f"{quantize_money(financial_amount):.2f}"
    det_str = str(details or "").strip()

    canonical_payload = (
        f"{prev_h}|{ts_str}|{uid_str}|{uname_str}|{actor_str}|"
        f"{tbl_str}|{rec_str}|{act_str}|{ref_str}|{amt_str}|{det_str}"
    )
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


def resolve_audit_user_identity(
    conn_or_session: Any,
    performed_by: Optional[str] = None,
    explicit_user_id: Optional[str] = None,
    explicit_username: Optional[str] = None,
) -> Tuple[str, str, str]:
    """
    استخلاص وتوحيد معرف المستخدم (User ID) واسم الدخول (Username) والاسم الكامل (Performed By)
    لكل حركة مالية مسجلة في سجل التدقيق الرقابي لضمان المساءلة التامة وفق متطلبات ZATCA.
    """
    info_dict = getattr(conn_or_session, "info", {}) or {}
    raw_actor = (
        performed_by
        or info_dict.get("audit_performed_by")
        or info_dict.get("performed_by")
        or "مدير النظام (Admin)"
    ).strip()
    uid = (
        explicit_user_id
        or info_dict.get("audit_user_id")
        or info_dict.get("user_id")
        or ""
    ).strip()
    uname = (
        explicit_username
        or info_dict.get("audit_username")
        or info_dict.get("username")
        or ""
    ).strip()

    # استخراج اسم المستخدم إذا كان مكتوباً بصيغة "الاسم الكامل (username)"
    paren_match = re.search(r"\(([^()]+)\)", raw_actor)
    candidate_uname = paren_match.group(1).strip().lower() if paren_match else raw_actor.lower()
    clean_name_part = re.sub(r"\s*\([^()]+\)\s*", "", raw_actor).strip()

    if conn_or_session is not None and (not uid or uid == "USR-001" or not uname):
        try:
            rows = conn_or_session.execute(
                text("SELECT id, username, full_name_ar FROM app_users")
            ).fetchall()
            matched_row = None
            for r_id, r_uname, r_fname in rows:
                r_uname_l = (r_uname or "").strip().lower()
                r_fname_s = (r_fname or "").strip()
                if uname and r_uname_l == uname.lower():
                    matched_row = (r_id, r_uname, r_fname_s)
                    break
                if candidate_uname and r_uname_l == candidate_uname:
                    matched_row = (r_id, r_uname, r_fname_s)
                    break
                if clean_name_part and (r_fname_s == clean_name_part or clean_name_part in r_fname_s or r_fname_s in clean_name_part):
                    matched_row = (r_id, r_uname, r_fname_s)
                    break
            if matched_row:
                if not explicit_user_id and not info_dict.get("audit_user_id"):
                    uid = f"USR-{int(matched_row[0]):03d}"
                uname = matched_row[1]
                if not raw_actor:
                    raw_actor = f"{matched_row[2]} ({matched_row[1]})"
        except Exception:
            pass

    if not uid:
        uid = "USR-001"
        uname = uname or "admin"
    if not uname:
        uname = candidate_uname if (candidate_uname and candidate_uname.isascii()) else "admin"

    return uid, uname, raw_actor


@event.listens_for(AuditLog, "before_insert")
def _audit_log_before_insert(mapper, connection, target: AuditLog):
    """توليد الطابع الزمني ومعرف المستخدم والبصمة التشفيرية المتسلسلة تلقائياً عند إدراج أي سجل تدقيق"""
    if target.timestamp is None:
        target.timestamp = utc_now()

    uid, uname, actor = resolve_audit_user_identity(
        connection,
        performed_by=target.performed_by,
        explicit_user_id=target.user_id if target.user_id != "USR-001" else None,
        explicit_username=target.username if target.username != "admin" else None,
    )
    target.user_id = uid
    target.username = uname
    target.performed_by = actor

    if target.financial_amount is None:
        target.financial_amount = Decimal("0.00")
    else:
        target.financial_amount = quantize_money(target.financial_amount)

    # جلب آخر بصمة تشفيرية في جدول audit_logs لبناء سلسلة التشفير غير القابلة للتلاعب (مع دعم الإدراج المتعدد في نفس الدفعة)
    db_last_hash = AUDIT_GENESIS_HASH
    try:
        last_row = connection.execute(
            text("SELECT entry_hash FROM audit_logs WHERE entry_hash IS NOT NULL AND entry_hash != '' ORDER BY id DESC LIMIT 1")
        ).fetchone()
        if last_row and last_row[0]:
            db_last_hash = str(last_row[0])
    except Exception:
        db_last_hash = AUDIT_GENESIS_HASH

    if (
        connection.info.get("_pending_audit_db_base") == db_last_hash
        and connection.info.get("_pending_audit_hash")
    ):
        prev_hash = str(connection.info["_pending_audit_hash"])
    else:
        prev_hash = db_last_hash
        connection.info["_pending_audit_db_base"] = db_last_hash

    target.previous_hash = prev_hash
    target.entry_hash = compute_audit_entry_hash(
        previous_hash=target.previous_hash,
        timestamp=target.timestamp,
        user_id=target.user_id,
        username=target.username,
        performed_by=target.performed_by,
        table_name=target.table_name,
        record_id=target.record_id,
        action=target.action,
        reference_number=target.reference_number,
        financial_amount=target.financial_amount,
        details=target.details,
    )
    connection.info["_pending_audit_hash"] = target.entry_hash



@event.listens_for(AuditLog, "before_update")
def _prevent_audit_log_update(mapper, connection, target: AuditLog):
    """منع تعديل أي سجل تدقيق على مستوى ORM نهائياً (Read-Only Compliance)"""
    raise AuditLogReadOnlyError(
        "ZATCA_AUDIT_LOG_READ_ONLY: سجل التدقيق الرقابي للقراءة والإضافة فقط (Read-Only) ويُمنع تعديل أي سجل رقابي مسجل."
    )


@event.listens_for(AuditLog, "before_delete")
def _prevent_audit_log_delete(mapper, connection, target: AuditLog):
    """منع حذف أي سجل تدقيق على مستوى ORM نهائياً (Read-Only Compliance)"""
    raise AuditLogReadOnlyError(
        "ZATCA_AUDIT_LOG_READ_ONLY: سجل التدقيق الرقابي للقراءة والإضافة فقط (Read-Only) ويُمنع حذف أي سجل رقابي مسجل."
    )


def _serialize_audit_val(val: Any) -> Any:
    if val is None:
        return None
    if isinstance(val, (datetime, date)):
        return val.isoformat()
    if isinstance(val, Decimal):
        return float(quantize_money(val))
    if isinstance(val, enum.Enum):
        return val.value
    if isinstance(val, (int, float, bool, str)):
        return val
    return str(val)


def _extract_model_ref_and_amount(obj: Any) -> Tuple[Optional[str], Decimal]:
    ref = (
        getattr(obj, "entry_number", None)
        or getattr(obj, "invoice_number", None)
        or getattr(obj, "note_number", None)
        or getattr(obj, "voucher_number", None)
        or getattr(obj, "payroll_number", None)
        or getattr(obj, "reference_number", None)
        or getattr(obj, "asset_code", None)
        or getattr(obj, "code", None)
        or (f"FY-{obj.year}" if hasattr(obj, "year") else None)
    )
    amt_raw = (
        getattr(obj, "grand_total", None)
        if getattr(obj, "grand_total", None) is not None else
        getattr(obj, "total_debit", None)
        if getattr(obj, "total_debit", None) is not None else
        getattr(obj, "total_amount", None)
        if getattr(obj, "total_amount", None) is not None else
        getattr(obj, "total_cost", None)
        if getattr(obj, "total_cost", None) is not None else
        getattr(obj, "net_paid_salaries", None)
        if getattr(obj, "net_paid_salaries", None) is not None else
        getattr(obj, "purchase_cost", None)
        if getattr(obj, "purchase_cost", None) is not None else
        Decimal("0.00")
    )
    return (str(ref) if ref else None), quantize_money(amt_raw)


_TRACKED_FINANCIAL_MODELS = (
    JournalEntry,
    SalesInvoice,
    PurchaseInvoice,
    CreditDebitNote,
    CashVoucher,
    InventoryTransaction,
    PayrollRun,
    FixedAsset,
    FiscalPeriod,
)


@event.listens_for(Session, "before_flush")
def _capture_financial_modifications_before_flush(session: Session, flush_context, instances):
    """
    اعتراض وتوثيق أي تعديل أو حذف على الجداول والمعاملات المالية تلقائياً في سجل التدقيق (AuditLog)
    مع حفظ القيم السابقة واللاحقة (Before/After Snapshot) والطابع الزمني ومعرف المستخدم.
    """
    if session.info.get("_suppress_auto_audit"):
        return

    # منع أي محاولة لحذف أو تعديل كائن AuditLog داخل الجلسة
    for obj in list(session.deleted):
        if isinstance(obj, AuditLog):
            raise AuditLogReadOnlyError(
                "ZATCA_AUDIT_LOG_READ_ONLY: سجل التدقيق الرقابي للقراءة والإضافة فقط (Read-Only) ويُمنع حذف أي سجل رقابي."
            )
    for obj in list(session.dirty):
        if isinstance(obj, AuditLog) and session.is_modified(obj, include_collections=False):
            raise AuditLogReadOnlyError(
                "ZATCA_AUDIT_LOG_READ_ONLY: سجل التدقيق الرقابي للقراءة والإضافة فقط (Read-Only) ويُمنع تعديل أي سجل رقابي."
            )

    queued_audit_keys = {
        (a.table_name, a.record_id, a.action)
        for a in session.new
        if isinstance(a, AuditLog)
    }
    queued_table_rec = {
        (a.table_name, a.record_id)
        for a in session.new
        if isinstance(a, AuditLog)
    }

    default_actor = session.info.get("audit_performed_by") or session.info.get("performed_by") or "مدير النظام (Admin)"
    default_uid = session.info.get("audit_user_id") or session.info.get("user_id") or "USR-001"
    default_uname = session.info.get("audit_username") or session.info.get("username") or "admin"

    # رصد كافة التعديلات على السجلات المالية القائمة (Dirty Financial Objects)
    for obj in list(session.dirty):
        if not isinstance(obj, _TRACKED_FINANCIAL_MODELS):
            continue
        if not session.is_modified(obj, include_collections=False):
            continue

        insp = sa_inspect(obj)
        tbl_name = obj.__tablename__
        rec_id = getattr(obj, "id", None) or 0

        db_current_row: Optional[Dict[str, Any]] = None
        if rec_id:
            try:
                row_res = session.connection().execute(
                    text(f"SELECT * FROM {tbl_name} WHERE id = :rid"),
                    {"rid": int(rec_id)},
                ).mappings().first()
                if row_res:
                    db_current_row = dict(row_res)
            except Exception:
                db_current_row = None

        old_vals: Dict[str, Any] = {}
        new_vals: Dict[str, Any] = {}
        for attr in insp.mapper.column_attrs:
            col_key = attr.key
            hist = getattr(insp.attrs, col_key).history
            if hist.has_changes():
                if hist.deleted:
                    old_v = hist.deleted[0]
                elif db_current_row is not None and col_key in db_current_row:
                    old_v = db_current_row[col_key]
                else:
                    old_v = None
                new_v = hist.added[0] if hist.added else getattr(obj, col_key, None)
                if _serialize_audit_val(old_v) != _serialize_audit_val(new_v):
                    old_vals[col_key] = _serialize_audit_val(old_v)
                    new_vals[col_key] = _serialize_audit_val(new_v)

        if not new_vals:
            continue

        # إذا كان هناك سجل AuditLog مضاف يدوياً في نفس الدفعة لنفس السجل، نثريه بالقيم السابقة واللاحقة والمرجع والمبلغ
        matching_manual = [
            a for a in session.new
            if isinstance(a, AuditLog) and a.table_name == tbl_name and a.record_id == rec_id
        ]
        ref_no, fin_amt = _extract_model_ref_and_amount(obj)
        if matching_manual:
            for m_log in matching_manual:
                if not m_log.old_values_json:
                    m_log.old_values_json = json.dumps(old_vals, ensure_ascii=False)
                if not m_log.new_values_json:
                    m_log.new_values_json = json.dumps(new_vals, ensure_ascii=False)
                if not m_log.reference_number and ref_no:
                    m_log.reference_number = ref_no
                if (m_log.financial_amount is None or quantize_money(m_log.financial_amount) == Decimal("0.00")) and fin_amt > Decimal("0.00"):
                    m_log.financial_amount = fin_amt
            continue

        action_code = f"MODIFY_{tbl_name.upper()}"
        if (tbl_name, rec_id, action_code) in queued_audit_keys or (tbl_name, rec_id) in queued_table_rec:
            continue

        changed_fields_str = ", ".join(f"{k}: {old_vals.get(k)} -> {new_vals.get(k)}" for k in new_vals.keys())
        session.add(AuditLog(
            table_name=tbl_name,
            record_id=rec_id,
            action=action_code,
            user_id=default_uid,
            username=default_uname,
            performed_by=default_actor,
            timestamp=utc_now(),
            reference_number=ref_no,
            financial_amount=fin_amt,
            old_values_json=json.dumps(old_vals, ensure_ascii=False),
            new_values_json=json.dumps(new_vals, ensure_ascii=False),
            details=f"Modified {tbl_name} (ID={rec_id}, Ref={ref_no or '-'}): {changed_fields_str}",
        ))
        queued_audit_keys.add((tbl_name, rec_id, action_code))

