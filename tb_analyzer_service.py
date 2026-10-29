import html
"""
MizanPro - External Trial Balance Analyzer & Certified CPA Financial Statements + Auditor Report + Comparative Year + Word/Excel/PDF Exporter
النظام المالي المتكامل - ميزان برو
محرك تحليل أي ميزان مراجعة خارجي (Excel / CSV) وإصدار تقرير المراجع المستقل والقوائم المالية المقارنة والإيضاحات الـ 18 المعتمدة
مع دعم حفظ قوالب التوجيه (Mapping Profiles) والتصدير إلى Word (.doc) و Excel (.xlsx) و HTML/PDF
"""

import io
import json
import re
from typing import Dict, Any, List, Optional, Tuple
import pandas as pd
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from sqlalchemy.orm import Session
from models import TBMappingProfile


# =============================================================================
# 1. التصنيفات القياسية للإيضاحات والقوائم المالية المعتمدة (CPA Note Mapping)
# =============================================================================

CPA_CATEGORIES = {
    "PPE_COST": "4-أصول ثابتة: عقارات وآلات ومعدات (بالتكلفة)",
    "PPE_ACCUM_DEP": "4-مجمع إهلاك العقارات والآلات والمعدات",
    "INTANGIBLES": "4-أصول غير ملموسة وبرمجيات",
    "CASH_AND_BANKS": "5-النقدية وما في حكمها (صناديق وبنوك)",
    "TRADE_RECEIVABLES": "6-ذمم مدينة تجارية (العملاء)",
    "ALLOWANCE_DOUBTFUL": "6-مخصص ديون مشكوك في تحصيلها",
    "OTHER_RECEIVABLES": "7-أرصدة مدينة أخرى (مدفوعات مقدمة وضريبة مدخلات)",
    "INVENTORY": "8-المخزون السلعي (مخزون بضاعة)",
    "TRADE_PAYABLES": "9-ذمم دائنة تجارية (الموردون)",
    "OTHER_PAYABLES": "10-أرصدة دائنة أخرى ومصروفات مستحقة",
    "ZAKAT_PROVISION": "11-مخصص الزكاة الشرعية المستحقة",
    "RELATED_PARTIES_CREDIT": "12-مستحق إلى أطراف ذات علاقة (جاري الشركاء/تمويل)",
    "LONG_TERM_LIABILITIES": "12-التزامات غير متداولة (قروض ومخصص نهاية الخدمة)",
    "CAPITAL": "حقوق الملكية: رأس المال",
    "STATUTORY_RESERVE": "حقوق الملكية: احتياطي نظامي",
    "RETAINED_EARNINGS": "حقوق الملكية: أرباح مبقاة / (خسائر متراكمة) أول المدة",
    "REVENUE_SALES": "13-الإيرادات: إيرادات المبيعات والنشاط",
    "REVENUE_OTHER": "13-الإيرادات: إيرادات أخرى متنوعة",
    "SALES_RETURNS": "13-الإيرادات: مردودات ومسموحات المبيعات والخصم المسموح به",
    "COST_OF_REVENUE": "14-تكلفة الإيرادات (تكلفة المبيعات / المشتريات)",
    "DEPRECIATION_EXP": "4-مصروف استهلاك العقارات والآلات والمعدات",
    "GA_EXPENSES": "15-المصاريف الإدارية والعمومية والتشغيلية",
    "ZAKAT_EXPENSE": "11-مصروف الزكاة الشرعية المسجل للفترة",
}

NATURAL_DEBIT_CATEGORIES = {
    "PPE_COST", "INTANGIBLES", "CASH_AND_BANKS", "TRADE_RECEIVABLES",
    "OTHER_RECEIVABLES", "INVENTORY", "SALES_RETURNS", "COST_OF_REVENUE",
    "DEPRECIATION_EXP", "GA_EXPENSES", "ZAKAT_EXPENSE"
}

AUDIT_OPINION_TYPES = {
    "UNQUALIFIED": "رأي غير متحفظ (تقرير نظيف - Unqualified Opinion)",
    "GOING_CONCERN": "رأي غير متحفظ مع فقرة عدم التأكد الجوهري المتعلق بالاستمرارية (Going Concern)",
    "EMPHASIS_OF_MATTER": "رأي غير متحفظ مع فقرة لفت انتباه (Emphasis of Matter)",
    "QUALIFIED": "رأي متحفظ (Qualified Opinion)",
}


class ExternalTBAnalyzerService:
    """محرك قراءة وتصنيف أي ميزان مراجعة خارجي وتوليد تقرير المراجع والقوائم المقارنة والإيضاحات الـ 18"""

    @staticmethod
    def get_sample_tasaheel_tb_dataframe() -> pd.DataFrame:
        """
        توليد ميزان مراجعة مطابق تماماً لأرقام القوائم المالية المرفقة
        (مؤسسة تساهيل طيبة التجارية - من 30 مارس 2025 حتى 19 مارس 2026)
        مع دعم أعمدة سنة المقارنة (اختياري)
        """
        rows = [
            {"كود الحساب": "120103", "اسم الحساب": "السيارات (العقارات والآلات والمعدات)", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 731381.0, "حركة دائن": 0.0, "مدين آخر المدة": 731381.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "120203", "اسم الحساب": "مجمع استهلاك السيارات", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 0.0, "حركة دائن": 121897.0, "مدين آخر المدة": 0.0, "دائن آخر المدة": 121897.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "110101", "اسم الحساب": "نقد بالصندوق", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 23456.0, "حركة دائن": 0.0, "مدين آخر المدة": 23456.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "110201", "اسم الحساب": "بنوك", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 39436.0, "حركة دائن": 0.0, "مدين آخر المدة": 39436.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "110301", "اسم الحساب": "عملاء تجاريون", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 266744.0, "حركة دائن": 0.0, "مدين آخر المدة": 266744.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "110501", "اسم الحساب": "موردين دفعات مقدمة", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 83533.0, "حركة دائن": 0.0, "مدين آخر المدة": 83533.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "110503", "اسم الحساب": "الهيئة العامة للزكاة والدخل - ضريبة القيمة المضافة", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 72638.0, "حركة دائن": 0.0, "مدين آخر المدة": 72638.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "110401", "اسم الحساب": "مخزون بضاعة", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 414372.0, "حركة دائن": 0.0, "مدين آخر المدة": 414372.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "210101", "اسم الحساب": "موردين", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 0.0, "حركة دائن": 1351309.0, "مدين آخر المدة": 0.0, "دائن آخر المدة": 1351309.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "210201", "اسم الحساب": "دائنون متنوعون", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 0.0, "حركة دائن": 47909.0, "مدين آخر المدة": 0.0, "دائن آخر المدة": 47909.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "210301", "اسم الحساب": "مستحق إلى أطراف ذات علاقة - نائف حمدان سالم بن عصاي", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 0.0, "حركة دائن": 2430648.0, "مدين آخر المدة": 0.0, "دائن آخر المدة": 2430648.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "3101", "اسم الحساب": "رأس المال", "مدين أول المدة": 0.0, "دائن أول المدة": 260000.0, "حركة مدين": 0.0, "حركة دائن": 0.0, "مدين آخر المدة": 0.0, "دائن آخر المدة": 260000.0, "مدين مقارنة": 0.0, "دائن مقارنة": 260000.0},
            {"كود الحساب": "4101", "اسم الحساب": "إيرادات المبيعات", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 0.0, "حركة دائن": 5155251.0, "مدين آخر المدة": 0.0, "دائن آخر المدة": 5155251.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "4201", "اسم الحساب": "إيرادات أخرى", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 0.0, "حركة دائن": 2299.0, "مدين آخر المدة": 0.0, "دائن آخر المدة": 2299.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "4102", "اسم الحساب": "مردودات المبيعات", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 308002.0, "حركة دائن": 0.0, "مدين آخر المدة": 308002.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "5101", "اسم الحساب": "تكلفة الإيرادات (صافي المشتريات وتكلفة المبيعات)", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 4847474.0, "حركة دائن": 0.0, "مدين آخر المدة": 4847474.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "5207", "اسم الحساب": "استهلاك العقارات وآلات ومعدات", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 121897.0, "حركة دائن": 0.0, "مدين آخر المدة": 121897.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520101", "اسم الحساب": "أجور ورواتب", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 923312.0, "حركة دائن": 0.0, "مدين آخر المدة": 923312.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520102", "اسم الحساب": "إيجارات", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 126800.0, "حركة دائن": 0.0, "مدين آخر المدة": 126800.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520103", "اسم الحساب": "كهرباء ومياه", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 15663.0, "حركة دائن": 0.0, "مدين آخر المدة": 15663.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520104", "اسم الحساب": "هاتف وإنترنت", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 5789.0, "حركة دائن": 0.0, "مدين آخر المدة": 5789.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520105", "اسم الحساب": "مصاريف حكومية", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 16363.0, "حركة دائن": 0.0, "مدين آخر المدة": 16363.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520106", "اسم الحساب": "رسوم نقاط بيع وتحويل", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 39304.0, "حركة دائن": 0.0, "مدين آخر المدة": 39304.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520107", "اسم الحساب": "حوافز وبدلات", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 11700.0, "حركة دائن": 0.0, "مدين آخر المدة": 11700.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520108", "اسم الحساب": "تجديد إقامات وتعديل المهن", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 21277.0, "حركة دائن": 0.0, "مدين آخر المدة": 21277.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520109", "اسم الحساب": "ضيافة ونظافة", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 3750.0, "حركة دائن": 0.0, "مدين آخر المدة": 3750.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520110", "اسم الحساب": "وقود وزيوت", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 312222.0, "حركة دائن": 0.0, "مدين آخر المدة": 312222.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520111", "اسم الحساب": "صيانة وقطع غيار", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 224485.0, "حركة دائن": 0.0, "مدين آخر المدة": 224485.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520112", "اسم الحساب": "شحن ونقل", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 291724.0, "حركة دائن": 0.0, "مدين آخر المدة": 291724.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520113", "اسم الحساب": "قرطاسية ومستلزمات مكتبية", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 11299.0, "حركة دائن": 0.0, "مدين آخر المدة": 11299.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520114", "اسم الحساب": "تأمينات اجتماعية", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 42335.0, "حركة دائن": 0.0, "مدين آخر المدة": 42335.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520115", "اسم الحساب": "تأمين طبي", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 34368.0, "حركة دائن": 0.0, "مدين آخر المدة": 34368.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520116", "اسم الحساب": "دعاية وإعلان", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 4000.0, "حركة دائن": 0.0, "مدين آخر المدة": 4000.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520117", "اسم الحساب": "عمولات المناديب", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 292981.0, "حركة دائن": 0.0, "مدين آخر المدة": 292981.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
            {"كود الحساب": "520118", "اسم الحساب": "مصاريف أخرى", "مدين أول المدة": 0.0, "دائن أول المدة": 0.0, "حركة مدين": 83008.0, "حركة دائن": 0.0, "مدين آخر المدة": 83008.0, "دائن آخر المدة": 0.0, "مدين مقارنة": 0.0, "دائن مقارنة": 0.0},
        ]
        return pd.DataFrame(rows)

    # =========================================================================
    # 2. حفظ واستدعاء قوالب التوجيه المحاسبي (Mapping Profiles CRUD)
    # =========================================================================
    @classmethod
    def save_mapping_profile(cls, db: Session, profile_name: str, client_name: str, classified_df: pd.DataFrame) -> TBMappingProfile:
        if not profile_name.strip():
            raise ValueError("اسم القالب مطلوب.")
        mapping_dict = {}
        for _, r in classified_df.iterrows():
            key_name = str(r["اسم الحساب"]).strip()
            mapping_dict[key_name] = str(r["التصنيف في القوائم والإيضاحات"])

        prof = db.query(TBMappingProfile).filter(TBMappingProfile.profile_name == profile_name.strip()).first()
        if prof:
            prof.client_name = client_name
            prof.mapping_json = json.dumps(mapping_dict, ensure_ascii=False)
        else:
            prof = TBMappingProfile(
                profile_name=profile_name.strip(),
                client_name=client_name,
                mapping_json=json.dumps(mapping_dict, ensure_ascii=False)
            )
            db.add(prof)
        db.commit()
        db.refresh(prof)
        return prof

    @classmethod
    def apply_mapping_profile(cls, db: Session, profile_name: str, classified_df: pd.DataFrame) -> pd.DataFrame:
        prof = db.query(TBMappingProfile).filter(TBMappingProfile.profile_name == profile_name).first()
        if not prof:
            return classified_df
        mapping_dict = json.loads(prof.mapping_json)
        df = classified_df.copy()
        for idx, r in df.iterrows():
            acc_name = str(r["اسم الحساب"]).strip()
            if acc_name in mapping_dict:
                df.at[idx, "التصنيف في القوائم والإيضاحات"] = mapping_dict[acc_name]
        return df

    # =========================================================================
    # 3. قراءة وتنظيف وتصنيف أي ملف ميزان مراجعة مرفوع
    # =========================================================================
    @classmethod
    def parse_uploaded_trial_balance(cls, uploaded_file) -> pd.DataFrame:
        filename = getattr(uploaded_file, "name", "tb.xlsx").lower()
        if filename.endswith(".csv"):
            raw_df = pd.read_csv(uploaded_file)
        else:
            raw_df = pd.read_excel(uploaded_file)

        return cls.normalize_and_classify_tb(raw_df)

    @classmethod
    def normalize_and_classify_tb(cls, raw_df: pd.DataFrame) -> pd.DataFrame:
        df = raw_df.dropna(how="all").copy()
        if df.empty:
            raise ValueError("ملف ميزان المراجعة المرفوع فارغ.")

        for idx in range(min(10, len(df))):
            row_vals = " ".join(str(v) for v in df.iloc[idx].values if pd.notna(v))
            if any(k in row_vals for k in ["اسم الحساب", "الحساب", "البيان", "Account Name", "مدين", "Debit"]):
                if idx > 0 and not any(k in " ".join(str(c) for c in df.columns) for k in ["اسم الحساب", "الحساب", "Account", "مدين", "Debit"]):
                    df.columns = [str(v).strip() for v in df.iloc[idx].values]
                    df = df.iloc[idx + 1:].reset_index(drop=True)
                break

        cols_map = {str(c).strip(): c for c in df.columns}

        def find_col(keywords: List[str], exclude: List[str] = None) -> Optional[str]:
            exclude = exclude or []
            for k in keywords:
                for col_clean, orig_col in cols_map.items():
                    low = col_clean.lower()
                    if k.lower() in low and not any(ex.lower() in low for ex in exclude):
                        return orig_col
            return None

        col_code = find_col(["كود", "رقم الحساب", "رمز", "code", "account no", "acc_code"])
        col_name = find_col(["اسم الحساب", "بيان", "الحساب", "account name", "name", "description"], exclude=["كود", "رقم", "code", "type", "نوع"])
        if not col_name:
            for c in df.columns:
                if df[c].dtype == object and c != col_code:
                    col_name = c
                    break

        col_op_d = find_col(["مدين أول", "افتتاحي مدين", "opening debit", "op debit"])
        col_op_c = find_col(["دائن أول", "افتتاحي دائن", "opening credit", "op credit"])
        col_p_d = find_col(["حركة مدين", "مدين الفترة", "period debit", "movement debit"])
        col_p_c = find_col(["حركة دائن", "دائن الفترة", "period credit", "movement credit"])
        col_cl_d = find_col(["مدين آخر", "ختامي مدين", "رصيد مدين", "closing debit", "مدين", "debit"], exclude=["أول", "افتتاحي", "حركة", "مقارن", "opening", "period", "comp", "prior"])
        col_cl_c = find_col(["دائن آخر", "ختامي دائن", "رصيد دائن", "closing credit", "دائن", "credit"], exclude=["أول", "افتتاحي", "حركة", "مقارن", "opening", "period", "comp", "prior"])
        col_comp_d = find_col(["مدين مقارن", "مدين سابق", "comp debit", "prior debit"])
        col_comp_c = find_col(["دائن مقارن", "دائن سابق", "comp credit", "prior credit"])
        col_net = find_col(["صافي", "الرصيد", "net balance", "balance"], exclude=["مدين", "دائن", "debit", "credit", "طبيعة"])

        def to_num(val) -> float:
            if pd.isna(val):
                return 0.0
            if isinstance(val, (int, float)):
                return float(val)
            s = str(val).strip().replace(",", "").replace("ريال", "").replace("SAR", "")
            is_neg = ("(" in s and ")" in s) or s.startswith("-") or s.endswith("-")
            s = re.sub(r"[^\d.]", "", s)
            try:
                num = float(s) if s else 0.0
                return -num if is_neg else num
            except ValueError:
                return 0.0

        normalized_rows = []
        for idx, row in df.iterrows():
            acc_name = str(row[col_name]).strip() if col_name and pd.notna(row[col_name]) else ""
            if not acc_name or acc_name.lower() in ("nan", "none", ""):
                continue
            if any(tot_w in acc_name for tot_w in ["الإجمالي", "الاجمالي", "المجموع", "مجموع", "total", "إجمالي ميزان"]):
                if len(acc_name) < 30:
                    continue

            acc_code = str(row[col_code]).strip() if col_code and pd.notna(row[col_code]) else f"{idx + 1:04d}"
            acc_code = acc_code.replace(".0", "")

            op_d = to_num(row[col_op_d]) if col_op_d else 0.0
            op_c = to_num(row[col_op_c]) if col_op_c else 0.0
            p_d = to_num(row[col_p_d]) if col_p_d else 0.0
            p_c = to_num(row[col_p_c]) if col_p_c else 0.0
            cl_d = to_num(row[col_cl_d]) if col_cl_d else 0.0
            cl_c = to_num(row[col_cl_c]) if col_cl_c else 0.0
            comp_d = to_num(row[col_comp_d]) if col_comp_d else op_d
            comp_c = to_num(row[col_comp_c]) if col_comp_c else op_c

            if cl_d == 0.0 and cl_c == 0.0:
                if op_d != 0 or op_c != 0 or p_d != 0 or p_c != 0:
                    net_val = (op_d - op_c) + (p_d - p_c)
                    cl_d = net_val if net_val > 0 else 0.0
                    cl_c = abs(net_val) if net_val < 0 else 0.0
                elif col_net:
                    net_val = to_num(row[col_net])
                    cl_d = net_val if net_val > 0 else 0.0
                    cl_c = abs(net_val) if net_val < 0 else 0.0

            if cl_d == 0.0 and cl_c == 0.0 and op_d == 0.0 and op_c == 0.0 and p_d == 0.0 and p_c == 0.0:
                continue

            cat_key = cls.classify_account(acc_code, acc_name, cl_d, cl_c)

            normalized_rows.append({
                "كود الحساب": acc_code,
                "اسم الحساب": acc_name,
                "مدين أول المدة": round(op_d, 2),
                "دائن أول المدة": round(op_c, 2),
                "حركة مدين": round(p_d, 2),
                "حركة دائن": round(p_c, 2),
                "مدين آخر المدة": round(cl_d, 2),
                "دائن آخر المدة": round(cl_c, 2),
                "مدين مقارنة": round(comp_d, 2),
                "دائن مقارنة": round(comp_c, 2),
                "التصنيف في القوائم والإيضاحات": CPA_CATEGORIES[cat_key],
                "_cat_key": cat_key
            })

        return pd.DataFrame(normalized_rows)

    @classmethod
    def classify_account(cls, code: str, name: str, debit: float, credit: float) -> str:
        n = name.strip().lower()
        c = str(code).strip()

        if any(w in n for w in ["مجمع إهلاك", "مجمع اهلاك", "مجمع استهلاك", "accumulated dep", "accum. dep"]):
            return "PPE_ACCUM_DEP"
        if any(w in n for w in ["مصروف إهلاك", "مصروف اهلاك", "استهلاك العقارات", "إستهلاك العقارات", "قسط إهلاك", "depreciation exp"]):
            return "DEPRECIATION_EXP"
        if any(w in n for w in ["مشروع تحت التنفيذ", "عقارات", "مباني", "أراضي", "اراضي", "آلات", "الات", "معدات", "سيارات", "وسائل نقل", "أثاث", "اثاث", "تجهيزات", "أصول ثابتة", "اصول ثابتة"]):
            if any(w in n for w in ["صيانة", "وقود", "إيجار", "ايجار", "استئجار"]):
                return "GA_EXPENSES"
            return "PPE_COST"
        if any(w in n for w in ["غير ملموسة", "برمجيات", "تراخيص برامج", "شهرة", "intangible"]):
            return "INTANGIBLES"

        if any(w in n for w in ["صندوق", "خزينة", "نقد", "بنك", "بنوك", "مصرف", "عهدة", "عهد نقدية", "cash", "bank", "pos", "نقاط البيع"]) and not any(w in n for w in ["رسوم", "عمولات", "مصاريف"]):
            return "CASH_AND_BANKS"

        if any(w in n for w in ["مخصص ديون", "خسائر ائتمانية", "مشكوك فيها", "allowance for"]):
            return "ALLOWANCE_DOUBTFUL"

        if any(w in n for w in ["عملاء", "عميل", "ذمم مدينة", "مدينون تجاريون", "أوراق قبض", "اوراق قبض", "trade receiv", "debtors"]):
            return "TRADE_RECEIVABLES"

        if any(w in n for w in ["مخزون", "بضاعة", "قطع غيار", "inventory", "stock"]) and not any(w in n for w in ["تكلفة", "مبيعات", "صيانة", "فروق"]):
            return "INVENTORY"

        if any(w in n for w in ["دفعات مقدمة", "مدفوعة مقدما", "مدفوعة مقدماً", "تأمينات مستردة", "ضريبة القيمة المضافة - مدخلات", "ضريبة مدخلات", "الهيئة العامة للزكاة والدخل - ضريبة", "أرصدة مدينة", "ارصدة مدينة", "سلف"]):
            if credit > debit and "مخرجات" in n:
                return "OTHER_PAYABLES"
            return "OTHER_RECEIVABLES"

        if any(w in n for w in ["أطراف ذات علاقة", "اطراف ذات علاقة", "جاري الشركاء", "جاري المالك", "جاري شريك", "تمويل شريك", "related part", "partners"]):
            return "RELATED_PARTIES_CREDIT"

        if any(w in n for w in ["مخصص الزكاة", "مخصص زكاة", "زكاة مستحقة", "zakat provision"]):
            return "ZAKAT_PROVISION"
        if any(w in n for w in ["مصروف الزكاة", "مصروف زكاة", "الزكاة الشرعية للفترة", "zakat exp"]):
            return "ZAKAT_EXPENSE"

        if any(w in n for w in ["قروض طويلة", "تسهيلات طويلة", "مخصص مكافأة نهاية الخدمة", "مخصص نهاية الخدمة", "end of service", "long-term loan"]):
            return "LONG_TERM_LIABILITIES"

        if any(w in n for w in ["موردين", "موردون", "ذمم دائنة", "ذمم تجارية دائنة", "أوراق دفع", "اوراق دفع", "trade payable", "creditors"]):
            return "TRADE_PAYABLES"

        if any(w in n for w in ["دائنون", "أرصدة دائنة", "ارصدة دائنة", "مصروفات مستحقة", "رواتب مستحقة", "ضريبة مخرجات", "مستحقة للهيئة", "accrued", "other payable"]):
            return "OTHER_PAYABLES"

        if any(w in n for w in ["رأس المال", "راس المال", "capital"]):
            return "CAPITAL"
        if any(w in n for w in ["احتياطي", "إحتياطي", "reserve"]):
            return "STATUTORY_RESERVE"
        if any(w in n for w in ["أرباح مبقاة", "ارباح مبقاة", "أرباح مرحلة", "خسائر متراكمة", "خسائر مبقاة", "retained earning"]):
            return "RETAINED_EARNINGS"

        if any(w in n for w in ["مردودات مبيعات", "مردودات المبيعات", "مسموحات المبيعات", "خصم مسموح", "sales return", "sales discount"]):
            return "SALES_RETURNS"
        if any(w in n for w in ["إيرادات أخرى", "ايرادات اخرى", "أرباح أخرى", "other income"]):
            return "REVENUE_OTHER"
        if any(w in n for w in ["مبيعات", "إيراد", "ايراد", "revenue", "sales"]) and not any(w in n for w in ["تكلفة"]):
            return "REVENUE_SALES"

        if any(w in n for w in ["تكلفة الإيرادات", "تكلفة الايرادات", "تكلفة المبيعات", "تكلفة البضاعة المباعة", "مشتريات", "مردودات مشتريات", "خصم مكتسب", "cost of sales", "cogs", "purchases"]):
            return "COST_OF_REVENUE"

        if c.startswith("1101") or c.startswith("1102"):
            return "CASH_AND_BANKS"
        if c.startswith("1103"):
            return "TRADE_RECEIVABLES"
        if c.startswith("1104"):
            return "INVENTORY"
        if c.startswith("1105"):
            return "OTHER_RECEIVABLES"
        if c.startswith("1202"):
            return "PPE_ACCUM_DEP"
        if c.startswith("12"):
            return "PPE_COST"
        if c.startswith("2101"):
            return "TRADE_PAYABLES"
        if c.startswith("2102"):
            return "OTHER_PAYABLES"
        if c.startswith("22"):
            return "LONG_TERM_LIABILITIES"
        if c.startswith("3101"):
            return "CAPITAL"
        if c.startswith("3102"):
            return "STATUTORY_RESERVE"
        if c.startswith("3103"):
            return "RETAINED_EARNINGS"
        if c.startswith("3104"):
            return "RELATED_PARTIES_CREDIT"
        if c.startswith("4102") or c.startswith("4103"):
            return "SALES_RETURNS"
        if c.startswith("42"):
            return "REVENUE_OTHER"
        if c.startswith("4"):
            return "REVENUE_SALES"
        if c.startswith("51"):
            return "COST_OF_REVENUE"
        if c.startswith("5207"):
            return "DEPRECIATION_EXP"
        if c.startswith("5"):
            return "GA_EXPENSES"

        return "GA_EXPENSES" if debit >= credit else "OTHER_PAYABLES"

    # =========================================================================
    # 4. توليد القوائم المالية الخمس + سنة المقارنة + تقرير المراجع + الـ 18 إيضاحاً
    # =========================================================================
    @classmethod
    def generate_cpa_full_package(
        cls,
        classified_df: pd.DataFrame,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        metadata = metadata or {}
        label_to_key = {v: k for k, v in CPA_CATEGORIES.items()}
        df = classified_df.copy()
        for col_c in ["مدين مقارنة", "دائن مقارنة"]:
            if col_c not in df.columns:
                df[col_c] = 0.0
        df["_cat_key"] = df["التصنيف في القوائم والإيضاحات"].map(lambda x: label_to_key.get(x, "GA_EXPENSES"))

        def get_cat_accounts(cat_keys: List[str]) -> List[Dict[str, Any]]:
            sub = df[df["_cat_key"].isin(cat_keys)]
            items = []
            for _, r in sub.iterrows():
                ck = r["_cat_key"]
                d = float(r.get("مدين آخر المدة", 0.0))
                c = float(r.get("دائن آخر المدة", 0.0))
                op_d = float(r.get("مدين أول المدة", 0.0))
                op_c = float(r.get("دائن أول المدة", 0.0))
                p_d = float(r.get("حركة مدين", 0.0))
                p_c = float(r.get("حركة دائن", 0.0))
                cm_d = float(r.get("مدين مقارنة", 0.0))
                cm_c = float(r.get("دائن مقارنة", 0.0))
                if ck in NATURAL_DEBIT_CATEGORIES:
                    bal = round(d - c, 2)
                    op_bal = round(op_d - op_c, 2)
                    comp_bal = round(cm_d - cm_c, 2)
                else:
                    bal = round(c - d, 2)
                    op_bal = round(op_c - op_d, 2)
                    comp_bal = round(cm_c - cm_d, 2)
                if abs(bal) > 0.001 or abs(op_bal) > 0.001 or abs(comp_bal) > 0.001 or abs(p_d) > 0.001 or abs(p_c) > 0.001:
                    items.append({
                        "code": str(r["كود الحساب"]),
                        "name": str(r["اسم الحساب"]),
                        "opening": op_bal,
                        "period_debit": round(p_d, 2),
                        "period_credit": round(p_c, 2),
                        "closing_debit": round(d, 2),
                        "closing_credit": round(c, 2),
                        "balance": bal,
                        "comp_balance": comp_bal
                    })
            return items

        def sum_cat(cat_keys: List[str], field: str = "balance") -> float:
            return round(sum(it[field] for it in get_cat_accounts(cat_keys)), 2)

        rev_sales_items = get_cat_accounts(["REVENUE_SALES"])
        rev_other_items = get_cat_accounts(["REVENUE_OTHER"])
        rev_returns_items = get_cat_accounts(["SALES_RETURNS"])

        gross_sales = round(sum(i["balance"] for i in rev_sales_items), 2)
        other_rev = round(sum(i["balance"] for i in rev_other_items), 2)
        sales_returns = round(sum(i["balance"] for i in rev_returns_items), 2)
        net_revenues = round(gross_sales + other_rev - sales_returns, 2)
        comp_revenues = round(sum_cat(["REVENUE_SALES", "REVENUE_OTHER"], "comp_balance") - sum_cat(["SALES_RETURNS"], "comp_balance"), 2)

        cost_items = get_cat_accounts(["COST_OF_REVENUE"])
        cost_of_revenues = round(sum(i["balance"] for i in cost_items), 2)
        comp_cost = sum_cat(["COST_OF_REVENUE"], "comp_balance")

        inv_items = get_cat_accounts(["INVENTORY"])
        closing_inventory_tb = round(sum(i["balance"] for i in inv_items), 2)
        opening_inventory_tb = round(sum(i["opening"] for i in inv_items), 2)
        implied_purchases = round(cost_of_revenues + closing_inventory_tb - opening_inventory_tb, 2)

        gross_profit = round(net_revenues - cost_of_revenues, 2)
        comp_gross_profit = round(comp_revenues - comp_cost, 2)

        ga_items = get_cat_accounts(["GA_EXPENSES"])
        total_ga_expenses = round(sum(i["balance"] for i in ga_items), 2)
        comp_ga_expenses = sum_cat(["GA_EXPENSES"], "comp_balance")

        dep_exp_items = get_cat_accounts(["DEPRECIATION_EXP"])
        depreciation_expense = round(sum(i["balance"] for i in dep_exp_items), 2)
        comp_dep_expense = sum_cat(["DEPRECIATION_EXP"], "comp_balance")

        total_operating_expenses = round(total_ga_expenses + depreciation_expense, 2)
        net_operating_profit_loss = round(gross_profit - total_operating_expenses, 2)
        profit_before_zakat = net_operating_profit_loss
        comp_profit_before_zakat = round(comp_gross_profit - (comp_ga_expenses + comp_dep_expense), 2)

        ppe_cost_items = get_cat_accounts(["PPE_COST"])
        ppe_accum_items = get_cat_accounts(["PPE_ACCUM_DEP"])
        intang_items = get_cat_accounts(["INTANGIBLES"])

        ppe_gross = round(sum(i["balance"] for i in ppe_cost_items), 2)
        ppe_accum = round(sum(i["balance"] for i in ppe_accum_items), 2)
        net_ppe = round(ppe_gross - ppe_accum, 2)
        comp_net_ppe = round(sum_cat(["PPE_COST"], "comp_balance") - sum_cat(["PPE_ACCUM_DEP"], "comp_balance"), 2)
        op_ppe_gross = sum_cat(["PPE_COST"], "opening")
        op_ppe_accum = sum_cat(["PPE_ACCUM_DEP"], "opening")
        op_net_ppe = round(op_ppe_gross - op_ppe_accum, 2)

        intangibles = round(sum(i["balance"] for i in intang_items), 2)
        op_intangibles = sum_cat(["INTANGIBLES"], "opening")
        total_non_current_assets = round(net_ppe + intangibles, 2)
        comp_non_current_assets = round(comp_net_ppe + sum_cat(["INTANGIBLES"], "comp_balance"), 2)
        op_non_current_assets = round(op_net_ppe + op_intangibles, 2)

        cash_items = get_cat_accounts(["CASH_AND_BANKS"])
        total_cash = round(sum(i["balance"] for i in cash_items), 2)
        comp_cash = sum_cat(["CASH_AND_BANKS"], "comp_balance")
        op_cash = sum_cat(["CASH_AND_BANKS"], "opening")

        ar_items = get_cat_accounts(["TRADE_RECEIVABLES"])
        allowance_items = get_cat_accounts(["ALLOWANCE_DOUBTFUL"])
        total_ar = round(sum(i["balance"] for i in ar_items) - sum(i["balance"] for i in allowance_items), 2)
        comp_ar = round(sum_cat(["TRADE_RECEIVABLES"], "comp_balance") - sum_cat(["ALLOWANCE_DOUBTFUL"], "comp_balance"), 2)
        op_ar = round(sum_cat(["TRADE_RECEIVABLES"], "opening") - sum_cat(["ALLOWANCE_DOUBTFUL"], "opening"), 2)

        other_ar_items = get_cat_accounts(["OTHER_RECEIVABLES"])
        total_other_ar = round(sum(i["balance"] for i in other_ar_items), 2)
        comp_other_ar = sum_cat(["OTHER_RECEIVABLES"], "comp_balance")
        op_other_ar = sum_cat(["OTHER_RECEIVABLES"], "opening")

        total_inventory = closing_inventory_tb
        comp_inventory = sum_cat(["INVENTORY"], "comp_balance")
        total_current_assets = round(total_cash + total_ar + total_other_ar + total_inventory, 2)
        comp_current_assets = round(comp_cash + comp_ar + comp_other_ar + comp_inventory, 2)
        op_current_assets = round(op_cash + op_ar + op_other_ar + opening_inventory_tb, 2)

        total_assets = round(total_non_current_assets + total_current_assets, 2)
        comp_total_assets = round(comp_non_current_assets + comp_current_assets, 2)
        op_total_assets = round(op_non_current_assets + op_current_assets, 2)

        ap_items = get_cat_accounts(["TRADE_PAYABLES"])
        total_ap = round(sum(i["balance"] for i in ap_items), 2)
        comp_ap = sum_cat(["TRADE_PAYABLES"], "comp_balance")
        op_ap = sum_cat(["TRADE_PAYABLES"], "opening")

        other_ap_items = get_cat_accounts(["OTHER_PAYABLES"])
        total_other_ap = round(sum(i["balance"] for i in other_ap_items), 2)
        comp_other_ap = sum_cat(["OTHER_PAYABLES"], "comp_balance")
        op_other_ap = sum_cat(["OTHER_PAYABLES"], "opening")

        rel_party_items = get_cat_accounts(["RELATED_PARTIES_CREDIT"])
        total_related_parties = round(sum(i["balance"] for i in rel_party_items), 2)
        comp_related_parties = sum_cat(["RELATED_PARTIES_CREDIT"], "comp_balance")
        op_related_parties = sum_cat(["RELATED_PARTIES_CREDIT"], "opening")

        lt_liab_items = get_cat_accounts(["LONG_TERM_LIABILITIES"])
        total_non_current_liabilities = round(sum(i["balance"] for i in lt_liab_items), 2)
        op_lt_liabilities = sum_cat(["LONG_TERM_LIABILITIES"], "opening")

        cap_items = get_cat_accounts(["CAPITAL"])
        capital = round(sum(i["balance"] for i in cap_items), 2)
        op_capital = sum_cat(["CAPITAL"], "opening")

        res_items = get_cat_accounts(["STATUTORY_RESERVE"])
        statutory_reserve = round(sum(i["balance"] for i in res_items), 2)
        op_statutory_reserve = sum_cat(["STATUTORY_RESERVE"], "opening")

        ret_items = get_cat_accounts(["RETAINED_EARNINGS"])
        opening_retained_earnings = round(sum(i["balance"] for i in ret_items), 2)
        op_retained = sum_cat(["RETAINED_EARNINGS"], "opening")

        booked_zakat_prov = sum_cat(["ZAKAT_PROVISION"])
        op_zakat_prov = sum_cat(["ZAKAT_PROVISION"], "opening")
        booked_zakat_exp = sum_cat(["ZAKAT_EXPENSE"])

        positive_sources = capital + statutory_reserve + total_related_parties + total_non_current_liabilities
        positive_elements_net = round(profit_before_zakat + positive_sources, 2)
        deductions_zakat = total_non_current_assets + abs(min(0.0, opening_retained_earnings))
        raw_base_after_deductions = round(positive_elements_net - deductions_zakat, 2)

        if raw_base_after_deductions > 0:
            zakat_base_calc = raw_base_after_deductions
        elif positive_elements_net > 0:
            zakat_base_calc = positive_elements_net
        else:
            zakat_base_calc = 0.0

        zakat_rate = float(metadata.get("zakat_rate", 0.0250713))
        calculated_zakat = round(zakat_base_calc * zakat_rate, 0)

        unbooked_zakat = calculated_zakat if (abs(booked_zakat_exp) < 0.001 and abs(booked_zakat_prov) < 0.001) else 0.0
        zakat_due = round(booked_zakat_exp + unbooked_zakat, 2)
        zakat_provision_bs = round(booked_zakat_prov + unbooked_zakat, 2)

        net_profit_after_zakat = round(profit_before_zakat - zakat_due, 2)
        closing_retained_earnings = round(opening_retained_earnings + net_profit_after_zakat, 2)
        total_equity = round(capital + statutory_reserve + closing_retained_earnings, 2)

        total_current_liabilities = round(total_ap + total_other_ap + zakat_provision_bs + total_related_parties, 2)
        total_liabilities = round(total_current_liabilities + total_non_current_liabilities, 2)
        total_liabilities_and_equity = round(total_liabilities + total_equity, 2)
        bs_diff = round(total_assets - total_liabilities_and_equity, 2)

        # التحقق من وجود مركز مالي افتتاحي متزن (أرصدة أول المدة) لحساب التغيرات الفعلية في التدفقات النقدية (IAS 7) وإيضاح الأصول (IAS 16)
        op_total_liab_and_eq = round(
            op_ap + op_other_ap + op_related_parties + op_lt_liabilities + op_capital + op_statutory_reserve + op_retained + op_zakat_prov, 2
        )
        has_opening_bs = (op_total_assets > 0.01) and (abs(op_total_assets - op_total_liab_and_eq) < 1.0)

        cf_before_wc = round(profit_before_zakat + depreciation_expense, 2)
        if has_opening_bs:
            ppe_opening_cost = op_ppe_gross
            ppe_additions_cost = round(ppe_gross - op_ppe_gross, 2)
            ppe_opening_dep = op_ppe_accum
            ppe_additions_dep = round(ppe_accum - op_ppe_accum, 2)

            cf_ar = round(-(total_ar - op_ar), 2)
            cf_other_ar = round(-(total_other_ar - op_other_ar), 2)
            cf_inv = round(-(total_inventory - opening_inventory_tb), 2)
            cf_ap = round(total_ap - op_ap, 2)
            cf_other_ap = round((total_other_ap + booked_zakat_prov - booked_zakat_exp) - (op_other_ap + op_zakat_prov), 2)
            net_operating_cf = round(cf_before_wc + cf_ar + cf_other_ar + cf_inv + cf_ap + cf_other_ap, 2)

            accum_dep_non_pnl_diff = round((ppe_accum - op_ppe_accum) - depreciation_expense, 2)
            net_investing_cf = round(-((ppe_gross - op_ppe_gross) + (intangibles - op_intangibles) - accum_dep_non_pnl_diff), 2)

            cf_rel_parties = round(total_related_parties - op_related_parties, 2)
            cf_cap_change = round(
                (capital + statutory_reserve + opening_retained_earnings + total_non_current_liabilities)
                - (op_capital + op_statutory_reserve + op_retained + op_lt_liabilities),
                2
            )
            net_financing_cf = round(cf_rel_parties + cf_cap_change, 2)
            opening_cash_cf = op_cash
        else:
            ppe_opening_cost = 0.0
            ppe_additions_cost = ppe_gross
            ppe_opening_dep = 0.0
            ppe_additions_dep = ppe_accum

            cf_ar = -total_ar
            cf_other_ar = -total_other_ar
            cf_inv = -total_inventory
            cf_ap = total_ap
            cf_other_ap = round(total_other_ap + booked_zakat_prov - booked_zakat_exp, 2)
            net_operating_cf = round(cf_before_wc + cf_ar + cf_other_ar + cf_inv + cf_ap + cf_other_ap, 2)

            accum_dep_non_pnl_diff = round(ppe_accum - depreciation_expense, 2)
            net_investing_cf = round(-(ppe_gross + intangibles - accum_dep_non_pnl_diff), 2)

            cf_rel_parties = total_related_parties
            cf_cap_change = round(capital + statutory_reserve + total_non_current_liabilities + opening_retained_earnings, 2)
            net_financing_cf = round(cf_rel_parties + cf_cap_change, 2)
            opening_cash_cf = 0.0

        net_cash_change = round(net_operating_cf + net_investing_cf + net_financing_cf, 2)

        has_comparative = bool(metadata.get("show_comparative", False)) or (comp_total_assets > 0 and comp_total_assets != capital)

        return {
            "metadata": metadata,
            "has_comparative": has_comparative,
            "trial_balance_totals": {
                "total_debit": round(float(df["مدين آخر المدة"].sum()), 2),
                "total_credit": round(float(df["دائن آخر المدة"].sum()), 2),
                "difference": round(float(df["مدين آخر المدة"].sum() - df["دائن آخر المدة"].sum()), 2)
            },
            "balance_sheet": {
                "non_current_assets": {
                    "ppe_gross": ppe_gross,
                    "ppe_accum_dep": ppe_accum,
                    "net_ppe": net_ppe,
                    "comp_net_ppe": comp_net_ppe,
                    "intangibles": intangibles,
                    "total": total_non_current_assets,
                    "comp_total": comp_non_current_assets
                },
                "current_assets": {
                    "cash_and_banks": total_cash,
                    "comp_cash": comp_cash,
                    "trade_receivables": total_ar,
                    "comp_ar": comp_ar,
                    "other_receivables": total_other_ar,
                    "comp_other_ar": comp_other_ar,
                    "inventory": total_inventory,
                    "comp_inventory": comp_inventory,
                    "total": total_current_assets,
                    "comp_total": comp_current_assets
                },
                "total_assets": total_assets,
                "comp_total_assets": comp_total_assets,
                "equity": {
                    "capital": capital,
                    "statutory_reserve": statutory_reserve,
                    "opening_retained_earnings": opening_retained_earnings,
                    "net_profit_period": net_profit_after_zakat,
                    "closing_retained_earnings": closing_retained_earnings,
                    "total": total_equity
                },
                "non_current_liabilities": {
                    "total": total_non_current_liabilities
                },
                "current_liabilities": {
                    "trade_payables": total_ap,
                    "comp_ap": comp_ap,
                    "other_payables": total_other_ap,
                    "comp_other_ap": comp_other_ap,
                    "zakat_provision": zakat_provision_bs,
                    "due_to_related_parties": total_related_parties,
                    "comp_related_parties": comp_related_parties,
                    "total": total_current_liabilities
                },
                "total_liabilities": total_liabilities,
                "total_liabilities_and_equity": total_liabilities_and_equity,
                "is_balanced": abs(bs_diff) < 1.0,
                "difference": bs_diff
            },
            "income_statement": {
                "revenues": net_revenues,
                "comp_revenues": comp_revenues,
                "cost_of_revenues": cost_of_revenues,
                "comp_cost_of_revenues": comp_cost,
                "gross_profit": gross_profit,
                "comp_gross_profit": comp_gross_profit,
                "ga_expenses": total_ga_expenses,
                "comp_ga_expenses": comp_ga_expenses,
                "depreciation_expense": depreciation_expense,
                "comp_depreciation_expense": comp_dep_expense,
                "total_operating_expenses": total_operating_expenses,
                "operating_profit_loss": net_operating_profit_loss,
                "profit_before_zakat": profit_before_zakat,
                "comp_profit_before_zakat": comp_profit_before_zakat,
                "zakat_expense": zakat_due,
                "net_profit_loss": net_profit_after_zakat
            },
            "equity_statement": {
                "opening_capital": capital,
                "opening_retained": opening_retained_earnings,
                "opening_total": round(capital + statutory_reserve + opening_retained_earnings, 2),
                "period_net_profit": net_profit_after_zakat,
                "closing_capital": capital,
                "closing_retained": closing_retained_earnings,
                "closing_total": total_equity
            },
            "cash_flow_statement": {
                "profit_before_zakat": profit_before_zakat,
                "depreciation": depreciation_expense,
                "profit_before_wc": cf_before_wc,
                "wc_changes": {
                    "trade_receivables": cf_ar,
                    "other_receivables": cf_other_ar,
                    "inventory": cf_inv,
                    "trade_payables": cf_ap,
                    "other_payables": cf_other_ap
                },
                "net_operating_cf": net_operating_cf,
                "net_investing_cf": net_investing_cf,
                "financing_details": {
                    "due_to_related_parties": cf_rel_parties,
                    "capital_change": cf_cap_change
                },
                "net_financing_cf": net_financing_cf,
                "net_cash_change": net_cash_change,
                "opening_cash": opening_cash_cf,
                "closing_cash": total_cash
            },
            "notes_details": {
                "note_4_ppe": {
                    "items": ppe_cost_items,
                    "opening_cost": ppe_opening_cost,
                    "additions_cost": ppe_additions_cost,
                    "closing_cost": ppe_gross,
                    "opening_dep": ppe_opening_dep,
                    "additions_dep": ppe_additions_dep,
                    "closing_dep": ppe_accum,
                    "net_book_value": net_ppe
                },
                "note_5_cash": {"items": cash_items, "total": total_cash},
                "note_6_ar": {"items": ar_items, "total": total_ar},
                "note_7_other_ar": {"items": other_ar_items, "total": total_other_ar},
                "note_8_inventory": {"items": inv_items, "total": total_inventory},
                "note_9_ap": {"items": ap_items, "total": total_ap},
                "note_10_other_ap": {"items": other_ap_items, "total": total_other_ap},
                "note_11_zakat": {
                    "profit_before_zakat": profit_before_zakat,
                    "adjusted_profit": profit_before_zakat,
                    "capital": capital,
                    "related_parties": total_related_parties,
                    "positive_elements_net": positive_elements_net,
                    "net_fixed_assets": total_non_current_assets,
                    "retained_losses": abs(min(0.0, opening_retained_earnings)),
                    "total_deductions": deductions_zakat,
                    "zakat_base": zakat_base_calc,
                    "zakat_due": zakat_due
                },
                "note_12_related_parties": {
                    "items": rel_party_items,
                    "partner_name": metadata.get("partner_name", "صاحب المؤسسة / الشريك الممول"),
                    "total": total_related_parties
                },
                "note_13_revenues": {
                    "sales": gross_sales,
                    "other_income": other_rev,
                    "sales_returns": sales_returns,
                    "items": rev_sales_items + rev_other_items + rev_returns_items,
                    "total": net_revenues
                },
                "note_14_cost_of_revenues": {
                    "opening_inventory": opening_inventory_tb,
                    "purchases_during_period": implied_purchases,
                    "closing_inventory": closing_inventory_tb,
                    "items": cost_items,
                    "total": cost_of_revenues
                },
                "note_15_ga_expenses": {
                    "items": ga_items,
                    "total": total_ga_expenses
                }
            }
        }

    # =========================================================================
    # 5. توليد صفحة تقرير المراجع المستقل (Independent Auditor's Report - ISA/SOCPA)
    # =========================================================================
    @classmethod
    def _build_auditor_report_page_html(cls, pkg: Dict[str, Any]) -> str:
        m = pkg["metadata"]
        bs = pkg["balance_sheet"]
        pnl = pkg["income_statement"]

        comp_name = m.get("company_name", "مؤسسة تساهيل طيبة التجارية")
        legal_form = m.get("legal_form", "مؤسسة فردية سعودية")
        city = m.get("city", "تبوك - المملكة العربية السعودية")
        period_text = m.get("period_text", "من 30 مارس 2025 م حتى 19 مارس 2026 م")
        auditor_office = m.get("auditor_office", "مكتب ميزان برو محاسبون ومراجعون قانونيون")
        auditor_name = m.get("auditor_name", "تركي بن عبد الله المحيميد")
        auditor_license = m.get("auditor_license", "ترخيص سوكبا رقم (512)")
        opinion_type = m.get("opinion_type", "GOING_CONCERN" if bs["equity"]["total"] < 0 else "UNQUALIFIED")
        custom_note_para = m.get("custom_auditor_paragraph", "")

        opinion_title = "الرأي" if opinion_type != "QUALIFIED" else "الرأي المتحفظ"
        qualification_html = ""
        if opinion_type == "QUALIFIED":
            qualification_html = f"""
            <h4 class="sub-heading">أساس الرأي المتحفظ</h4>
            <p class="policy-p">
                {custom_note_para or 'لم نتمكن من حضور الجرد الفعلي للمخزون في نهاية الفترة المالية، ولم نتمكن بوسائل المراجعة البديلة من التحقق من كميات المخزون المسجلة في قائمة المركز المالي.'}
            </p>
            """

        emphasis_html = ""
        if opinion_type == "GOING_CONCERN" or (bs["equity"]["total"] < 0 and opinion_type != "UNQUALIFIED"):
            loss_val = abs(pnl["net_profit_loss"])
            eq_def = abs(bs["equity"]["total"])
            emphasis_html = f"""
            <h4 class="sub-heading">عدم التأكد الجوهري المتعلق بالاستمرارية</h4>
            <p class="policy-p">
                نلفت الانتباه إلى قائمة الدخل وقائمة المركز المالي والإيضاح رقم (2) حول القوائم المالية، والذي يشير إلى أن المنشأة تكبدت صافي خسارة قدرها ({loss_val:,.0f}) ريال سعودي خلال الفترة المالية {period_text}، وبلغ عجز حقوق الملكية ({eq_def:,.0f}) ريال سعودي، وقد تم تمويل العمليات من خلال الأرصدة الدائنة للأطراف ذات العلاقة (إيضاح 12). وقد أعلن المالك/الشركاء استمرار الدعم المالي للمنشأة، ولم يتم تعديل رأينا فيما يتعلق بهذا الأمر.
            </p>
            """
        elif opinion_type == "EMPHASIS_OF_MATTER" or custom_note_para:
            emphasis_html = f"""
            <h4 class="sub-heading">فقرة لفت انتباه</h4>
            <p class="policy-p">
                {custom_note_para or 'نلفت الانتباه إلى الإيضاح رقم (12) حول القوائم المالية والمتعلق بالمعاملات والأرصدة مع الأطراف ذات العلاقة، ولم يتم تعديل رأينا فيما يتعلق بهذا الأمر.'}
            </p>
            """

        return f"""
        <div class="report-page">
            <div class="page-header">
                <div><b>{auditor_office}</b></div>
                <div>محاسبون ومراجعون قانونيون - المملكة العربية السعودية</div>
                <div><b>تقرير المراجع المستقل إلى مالك / شركاء {comp_name}</b></div>
            </div>
            <h3 class="note-heading" style="text-align:center;">تقرير المراجع المستقل</h3>
            <p class="policy-p"><b>إلى السيد مالك / السادة شركاء {comp_name} ({legal_form}) - {city}</b></p>

            <h4 class="sub-heading">{opinion_title}</h4>
            <p class="policy-p">
                لقد راجعنا القوائم المالية لـ <b>{comp_name}</b>، والتي تشمل قائمة المركز المالي كما في نهاية الفترة المالية {period_text}، وقائمة الدخل والدخل الشامل، وقائمة التغيرات في حقوق الملكية، وقائمة التدفقات النقدية عن الفترة المنتهية في ذلك التاريخ، والإيضاحات المرفقة بالقوائم المالية من (1) إلى (18)، بما في ذلك ملخص للسياسات المحاسبية الهامة.<br>
                في رأينا {"(باستثناء أثر الأمر المبين في فقرة أساس الرأي المتحفظ)" if opinion_type == "QUALIFIED" else ""}، فإن القوائم المالية المرفقة تعرض بعدل، من جميع الجوانب الجوهرية، المركز المالي لـ <b>{comp_name}</b> كما في نهاية الفترة المالية {period_text}، وأداءها المالي وتدفقاتها النقدية للفترة المنتهية في ذلك التاريخ وفقاً للمعيار الدولي للتقرير المالي للمنشآت الصغيرة ومتوسطة الحجم (IFRS for SMEs) المعتمد في المملكة العربية السعودية من قبل الهيئة السعودية للمراجعين والمحاسبين (SOCPA).
            </p>

            {qualification_html}

            <h4 class="sub-heading">أساس الرأي</h4>
            <p class="policy-p">
                لقد قمنا بالمراجعة وفقاً للمعايير الدولية للمراجعة المعتمدة في المملكة العربية السعودية. إن مسؤوليتنا بموجب تلك المعايير تم توضيحها في قسم "مسؤوليات المراجع عن مراجعة القوائم المالية" في تقريرنا هذا. ونحن مستقلون عن المنشأة وفقاً لقواعد سلوك وآداب المهنة الدولية للمحاسبين المهنيين المعتمدة في المملكة العربية السعودية، وقد وفينا أيضاً بمسؤولياتنا الأخلاقية الأخرى وفقاً لتلك القواعد. ونعتقد أن أدلة المراجعة التي حصلنا عليها كافية ومناسبة لتوفير أساس لإبداء رأينا.
            </p>

            {emphasis_html}

            <h4 class="sub-heading">مسؤوليات الإدارة والمكلفين بالحوكمة عن القوائم المالية</h4>
            <p class="policy-p">
                إن الإدارة مسؤولة عن إعداد القوائم المالية وعرضها العادل وفقاً للمعيار الدولي للتقرير المالي للمنشآت الصغيرة ومتوسطة الحجم المعتمد في المملكة العربية السعودية، وعن الرقابة الداخلية التي تراها الإدارة ضرورية لتمكينها من إعداد قوائم مالية خالية من تحريف جوهري سواء بسبب غش أو خطأ. وعند إعداد القوائم المالية، فإن الإدارة مسؤولة عن تقييم قدرة المنشأة على الاستمرار كمنشأة مستمرة.
            </p>

            <h4 class="sub-heading">مسؤوليات المراجع عن مراجعة القوائم المالية</h4>
            <p class="policy-p">
                تتمثل أهدافنا في الحصول على تأكيد معقول عما إذا كانت القوائم المالية ككل خالية من تحريف جوهري سواء بسبب غش أو خطأ، وإصدار تقرير المراجع الذي يتضمن رأينا طبقاً للمعايير الدولية للمراجعة المعتمدة في المملكة العربية السعودية.
            </p>

            <div style="margin-top:35px; display:flex; justify-content:space-between; border-top:1.5px solid #0F172A; padding-top:18px; font-size:13.5px;">
                <div>
                    <b>{auditor_office}</b><br>
                    اسم المراجع المرخص: <b>{auditor_name}</b><br>
                    رقم الترخيص: <b>{auditor_license}</b>
                </div>
                <div style="text-align:left;">
                    <b>التوقيع والختم الرسمي:</b> .................................<br>
                    <b>المدينة:</b> {city}
                </div>
            </div>
        </div>
        """

    # =========================================================================
    # 6. توليد التقرير الرسمي الكامل القابل للطباعة (HTML / PDF + Word .doc)
    # =========================================================================
    @classmethod
    def generate_cpa_printable_html(cls, pkg: Dict[str, Any], for_word: bool = False) -> str:
        m = pkg["metadata"]
        bs = pkg["balance_sheet"]
        pnl = pkg["income_statement"]
        eq = pkg["equity_statement"]
        cf = pkg["cash_flow_statement"]
        nd = pkg["notes_details"]
        has_comp = pkg.get("has_comparative", False)

        comp_name = m.get("company_name", "مؤسسة تساهيل طيبة التجارية")
        legal_form = m.get("legal_form", "مؤسسة فردية سعودية")
        city = m.get("city", "تبوك - المملكة العربية السعودية")
        period_text = m.get("period_text", "من 30 مارس 2025 م حتى 19 مارس 2026 م")
        comp_period_text = m.get("comp_period_text", "سنة المقارنة السابقة")
        cr_no = m.get("cr_number", "3403015089")
        unified_no = m.get("unified_number", "7006126283")
        activity = m.get("activity", "تعمل المؤسسة في مجال أنشطة المقاولات وتشييد المباني والتجارة العامة.")
        include_auditor = bool(m.get("include_auditor_report", True))

        def fmt(val: float) -> str:
            if val is None or abs(val) < 0.005:
                return "-"
            if val < 0:
                return f"({abs(val):,.0f})" if abs(val - round(val)) < 0.01 else f"({abs(val):,.2f})"
            return f"{val:,.0f}" if abs(val - round(val)) < 0.01 else f"{val:,.2f}"

        def page_header() -> str:
            return f"""
            <div class="page-header">
                <div><b>{comp_name}</b></div>
                <div>{legal_form}</div>
                <div>{city}</div>
                <div>إيضاحات حول القوائم المالية عن الفترة المالية {period_text}</div>
                <div style="font-size:12px; color:#475569;">(جميع المبالغ بالريال السعودي ما لم يذكر خلاف ذلك)</div>
            </div>
            """

        def build_note_table(items: List[Dict[str, Any]], total_val: float, default_label: str) -> str:
            rows_html = ""
            if items:
                for it in items:
                    rows_html += f'<tr><td>{it["name"]}</td><td class="num-col">{fmt(it["balance"])}</td></tr>'
            else:
                rows_html += f'<tr><td>{default_label}</td><td class="num-col">{fmt(total_val)}</td></tr>'
            rows_html += f'<tr class="double-bottom"><td><b>المجموع</b></td><td class="num-col"><b>{fmt(total_val)}</b></td></tr>'
            return f"""
            <table class="fin-table note-tbl">
                <thead>
                    <tr><th>البيان</th><th style="width:180px;">{period_text}<br>ريال سعودي</th></tr>
                </thead>
                <tbody>{rows_html}</tbody>
            </table>
            """

        ga_rows_html = ""
        for it in nd["note_15_ga_expenses"]["items"]:
            ga_rows_html += f'<tr><td>{it["name"]}</td><td class="num-col">{fmt(it["balance"])}</td></tr>'
        if not ga_rows_html:
            ga_rows_html = '<tr><td>مصاريف إدارية وعمومية متنوعة</td><td class="num-col">-</td></tr>'
        ga_rows_html += f'<tr class="double-bottom"><td><b>المجموع</b></td><td class="num-col"><b>{fmt(nd["note_15_ga_expenses"]["total"])}</b></td></tr>'

        n4 = nd["note_4_ppe"]
        n11 = nd["note_11_zakat"]
        n12 = nd["note_12_related_parties"]
        n13 = nd["note_13_revenues"]
        n14 = nd["note_14_cost_of_revenues"]

        auditor_page = cls._build_auditor_report_page_html(pkg) if include_auditor else ""

        comp_th = f'<th class="num-col">{comp_period_text}<br>ريال سعودي</th>' if has_comp else ""
        colspan_sec = "4" if has_comp else "3"

        def c_td(val: float) -> str:
            return f'<td class="num-col">{fmt(val)}</td>' if has_comp else ""

        print_bar_html = "" if for_word else """
        <div class="print-bar no-print">
            <button class="print-btn" onclick="window.print()">🖨️ طباعة القوائم المالية وتقرير المراجع والإيضاحات الكاملة (18 إيضاحاً) أو حفظها كملف PDF معتمد</button>
        </div>
        """

        word_xmlns = 'xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns="http://www.w3.org/TR/REC-html40"' if for_word else ""

        return f"""
        <!DOCTYPE html>
        <html lang="ar" dir="rtl" {word_xmlns}>
        <head>
            <meta charset="UTF-8">
            <title>القوائم المالية والإيضاحات المعتمدة - {comp_name}</title>
            <style>
                @page {{ size: A4 portrait; margin: 1.8cm; }}
                * {{ box-sizing: border-box; font-family: 'Cairo', 'Segoe UI', 'Traditional Arabic', Tahoma, sans-serif; }}
                body {{ margin: 0; padding: {'0' if for_word else '20px'}; background: {'#FFFFFF' if for_word else '#E2E8F0'}; color: #0F172A; line-height: 1.65; direction: rtl; text-align: right; }}
                .print-bar {{ max-width: 900px; margin: 0 auto 20px auto; text-align: center; }}
                .print-btn {{ background: #1E3A8A; color: white; border: none; padding: 12px 28px; border-radius: 8px; font-size: 15px; font-weight: bold; cursor: pointer; width: 100%; }}
                .report-page {{ max-width: 900px; margin: 0 auto 24px auto; background: white; padding: 40px 46px; border-radius: 6px; page-break-after: always; }}
                .cover-box {{ display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 580px; text-align: center; border: 3px double #1E3A8A; padding: 38px; }}
                .cover-box h1 {{ font-size: 27px; color: #0F172A; margin: 10px 0; }}
                .cover-box h2 {{ font-size: 19px; color: #334155; margin: 8px 0; font-weight: 600; }}
                .page-header {{ border-bottom: 2px solid #0F172A; padding-bottom: 10px; margin-bottom: 20px; text-align: right; font-size: 13.5px; line-height: 1.5; }}
                .fin-table {{ width: 100%; border-collapse: collapse; margin: 12px 0 20px 0; font-size: 13.5px; direction: rtl; }}
                .fin-table th {{ border-top: 1.5px solid #0F172A; border-bottom: 1.5px solid #0F172A; padding: 8px 10px; background: #F8FAFC; font-weight: 700; text-align: center; }}
                .fin-table td {{ padding: 7px 10px; border-bottom: 1px solid #E2E8F0; text-align: right; }}
                .fin-table td.num-col {{ text-align: center; font-weight: 600; direction: ltr; font-family: 'Segoe UI', Tahoma, monospace; width: 155px; }}
                .fin-table td.note-col {{ text-align: center; width: 65px; color: #334155; }}
                .section-row td {{ font-weight: 800; color: #1E3A8A; background: #F8FAFC; text-decoration: underline; padding-top: 12px; }}
                .subtotal-row td {{ border-top: 1.5px solid #0F172A; border-bottom: 1.5px solid #0F172A; font-weight: 700; background: #F8FAFC; }}
                .double-bottom td {{ border-top: 1.5px solid #0F172A; border-bottom: 4px double #0F172A; font-weight: 800; background: #F1F5F9; }}
                .footer-note {{ text-align: center; font-weight: 700; font-size: 13px; margin-top: 22px; color: #334155; }}
                h3.note-heading {{ font-size: 16px; color: #0F172A; text-decoration: underline; margin: 18px 0 8px 0; }}
                h4.sub-heading {{ font-size: 14.5px; color: #1E3A8A; text-decoration: underline; margin: 12px 0 6px 0; }}
                p.policy-p {{ font-size: 13.5px; text-align: justify; margin: 6px 0 12px 0; color: #1E293B; }}
                @media print {{
                    body {{ background: white; padding: 0; }}
                    .no-print {{ display: none !important; }}
                    .report-page {{ box-shadow: none; margin: 0; max-width: 100%; padding: 20px 25px; }}
                }}
            </style>
        </head>
        <body>
            {print_bar_html}

            <!-- الصفحة 1: الغلاف الرسمي + الفهرس -->
            <div class="report-page">
                <div class="cover-box">
                    <h1>{comp_name}</h1>
                    <h2>{legal_form}</h2>
                    <h2>{city}</h2>
                    <h1 style="margin-top:20px; color:#1E3A8A; text-decoration:underline;">القوائم المالية وتقرير المراجع المستقل</h1>
                    <h2>عن الفترة المالية {period_text}</h2>
                    <div style="width:82%; margin-top:32px; text-align:right;">
                        <h3 style="text-align:center; border-bottom:2px solid #0F172A; padding-bottom:8px;">فهرس القوائم المالية وتقرير المراجع المستقل</h3>
                        <table class="fin-table">
                            <thead><tr><th>البيان</th><th style="width:120px;">القسم</th></tr></thead>
                            <tbody>
                                {'<tr><td>تقرير المراجع المستقل</td><td class="note-col">صفحة 2</td></tr>' if include_auditor else ''}
                                <tr><td>قائمة المركز المالي</td><td class="note-col">القائمة (1)</td></tr>
                                <tr><td>قائمة الدخل والدخل الشامل</td><td class="note-col">القائمة (2)</td></tr>
                                <tr><td>قائمة التغيرات في حقوق الملكية</td><td class="note-col">القائمة (3)</td></tr>
                                <tr><td>قائمة التدفقات النقدية</td><td class="note-col">القائمة (4)</td></tr>
                                <tr><td>سياسات وإيضاحات حول القوائم المالية (إيضاح 1 إلى إيضاح 18)</td><td class="note-col">الإيضاحات (1 - 18)</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            {auditor_page}

            <!-- قائمة المركز المالي -->
            <div class="report-page">
                <div class="page-header">
                    <div><b>{comp_name} ({legal_form}) - {city}</b></div>
                    <div><b>قائمة المركز المالي كما في الفترة المالية {period_text} (بالريال السعودي)</b></div>
                </div>
                <table class="fin-table">
                    <thead>
                        <tr><th>البيان</th><th class="note-col">إيضاح</th><th class="num-col">{period_text}<br>ريال سعودي</th>{comp_th}</tr>
                    </thead>
                    <tbody>
                        <tr class="section-row"><td colspan="{colspan_sec}">الأصول</td></tr>
                        <tr class="section-row"><td colspan="{colspan_sec}">الأصول غير المتداولة:</td></tr>
                        <tr><td>العقارات والآلات والمعدات - بالصافي</td><td class="note-col">4</td><td class="num-col">{fmt(bs['non_current_assets']['net_ppe'])}</td>{c_td(bs['non_current_assets']['comp_net_ppe'])}</tr>
                        <tr class="double-bottom"><td>مجموع الأصول غير المتداولة</td><td class="note-col"></td><td class="num-col">{fmt(bs['non_current_assets']['total'])}</td>{c_td(bs['non_current_assets']['comp_total'])}</tr>

                        <tr class="section-row"><td colspan="{colspan_sec}">الأصول المتداولة:</td></tr>
                        <tr><td>النقدية وما في حكمها</td><td class="note-col">5</td><td class="num-col">{fmt(bs['current_assets']['cash_and_banks'])}</td>{c_td(bs['current_assets']['comp_cash'])}</tr>
                        <tr><td>ذمم مدينة تجارية</td><td class="note-col">6</td><td class="num-col">{fmt(bs['current_assets']['trade_receivables'])}</td>{c_td(bs['current_assets']['comp_ar'])}</tr>
                        <tr><td>أرصدة مدينة أخرى</td><td class="note-col">7</td><td class="num-col">{fmt(bs['current_assets']['other_receivables'])}</td>{c_td(bs['current_assets']['comp_other_ar'])}</tr>
                        <tr><td>المخزون</td><td class="note-col">8</td><td class="num-col">{fmt(bs['current_assets']['inventory'])}</td>{c_td(bs['current_assets']['comp_inventory'])}</tr>
                        <tr class="subtotal-row"><td>مجموع الأصول المتداولة</td><td class="note-col"></td><td class="num-col">{fmt(bs['current_assets']['total'])}</td>{c_td(bs['current_assets']['comp_total'])}</tr>
                        <tr class="double-bottom"><td>إجمالي الأصول المتداولة وغير المتداولة</td><td class="note-col"></td><td class="num-col">{fmt(bs['total_assets'])}</td>{c_td(bs['comp_total_assets'])}</tr>

                        <tr class="section-row"><td colspan="{colspan_sec}">الالتزامات وحقوق الملكية:</td></tr>
                        <tr class="section-row"><td colspan="{colspan_sec}">حقوق الشركاء / المالك:</td></tr>
                        <tr><td>رأس المال</td><td class="note-col"></td><td class="num-col">{fmt(bs['equity']['capital'])}</td>{c_td(bs['equity']['capital'])}</tr>
                        {f'<tr><td>الاحتياطي النظامي</td><td class="note-col"></td><td class="num-col">{fmt(bs["equity"]["statutory_reserve"])}</td>{c_td(bs["equity"]["statutory_reserve"])}</tr>' if bs['equity']['statutory_reserve'] != 0 else ''}
                        <tr><td>أرباح مبقاة / (خسائر متراكمة)</td><td class="note-col"></td><td class="num-col">{fmt(bs['equity']['closing_retained_earnings'])}</td>{c_td(bs['equity']['opening_retained_earnings'])}</tr>
                        <tr class="double-bottom"><td>مجموع حقوق الملكية</td><td class="note-col"></td><td class="num-col">{fmt(bs['equity']['total'])}</td>{c_td(bs['equity']['capital'] + bs['equity']['statutory_reserve'] + bs['equity']['opening_retained_earnings'])}</tr>
                        {f'<tr class="section-row"><td colspan="{colspan_sec}">الالتزامات غير المتداولة:</td></tr><tr><td>قروض طويلة الأجل ومخصص مكافأة نهاية الخدمة</td><td class="note-col">12</td><td class="num-col">{fmt(bs["non_current_liabilities"]["total"])}</td>{c_td(0.0)}</tr>' if bs['non_current_liabilities']['total'] != 0 else ''}

                        <tr class="section-row"><td colspan="{colspan_sec}">الالتزامات المتداولة:</td></tr>
                        <tr><td>ذمم دائنة تجارية</td><td class="note-col">9</td><td class="num-col">{fmt(bs['current_liabilities']['trade_payables'])}</td>{c_td(bs['current_liabilities']['comp_ap'])}</tr>
                        <tr><td>أرصدة دائنة أخرى</td><td class="note-col">10</td><td class="num-col">{fmt(bs['current_liabilities']['other_payables'])}</td>{c_td(bs['current_liabilities']['comp_other_ap'])}</tr>
                        <tr><td>مخصص الزكاة</td><td class="note-col">11</td><td class="num-col">{fmt(bs['current_liabilities']['zakat_provision'])}</td>{c_td(0.0)}</tr>
                        <tr><td>مستحق إلى أطراف ذات علاقة</td><td class="note-col">12</td><td class="num-col">{fmt(bs['current_liabilities']['due_to_related_parties'])}</td>{c_td(bs['current_liabilities']['comp_related_parties'])}</tr>
                        <tr class="subtotal-row"><td>مجموع الالتزامات المتداولة</td><td class="note-col"></td><td class="num-col">{fmt(bs['current_liabilities']['total'])}</td>{c_td(bs['current_liabilities']['comp_ap'] + bs['current_liabilities']['comp_other_ap'] + bs['current_liabilities']['comp_related_parties'])}</tr>
                        <tr class="subtotal-row"><td>إجمالي الالتزامات المتداولة وغير المتداولة</td><td class="note-col"></td><td class="num-col">{fmt(bs['total_liabilities'])}</td>{c_td(bs['current_liabilities']['comp_ap'] + bs['current_liabilities']['comp_other_ap'] + bs['current_liabilities']['comp_related_parties'])}</tr>
                        <tr class="double-bottom"><td>مجموع الالتزامات وحقوق الملكية</td><td class="note-col"></td><td class="num-col">{fmt(bs['total_liabilities_and_equity'])}</td>{c_td(bs['comp_total_assets'])}</tr>
                    </tbody>
                </table>
                <div class="footer-note">"إن الإيضاحات المرفقة جزء لا يتجزأ من هذه القوائم المالية وتقرأ معها"</div>
            </div>

            <!-- قائمة الدخل + قائمة التغيرات في حقوق الملكية -->
            <div class="report-page">
                <div class="page-header">
                    <div><b>{comp_name} ({legal_form}) - {city}</b></div>
                    <div><b>قائمة الدخل والدخل الشامل عن الفترة المالية {period_text} (بالريال السعودي)</b></div>
                </div>
                <table class="fin-table">
                    <thead>
                        <tr><th>البيان</th><th class="note-col">إيضاح</th><th class="num-col">{period_text}<br>ريال سعودي</th>{comp_th}</tr>
                    </thead>
                    <tbody>
                        <tr><td>الإيرادات</td><td class="note-col">13</td><td class="num-col">{fmt(pnl['revenues'])}</td>{c_td(pnl['comp_revenues'])}</tr>
                        <tr><td>يخصم: تكلفة الإيرادات</td><td class="note-col">14</td><td class="num-col">{fmt(-pnl['cost_of_revenues'])}</td>{c_td(-pnl['comp_cost_of_revenues'])}</tr>
                        <tr class="double-bottom"><td>مجمل الربح من الأنشطة الرئيسية</td><td class="note-col"></td><td class="num-col">{fmt(pnl['gross_profit'])}</td>{c_td(pnl['comp_gross_profit'])}</tr>
                        <tr class="section-row"><td colspan="{colspan_sec}">يخصم:</td></tr>
                        <tr><td>المصروفات الإدارية والعمومية</td><td class="note-col">15</td><td class="num-col">{fmt(-pnl['ga_expenses'])}</td>{c_td(-pnl['comp_ga_expenses'])}</tr>
                        <tr><td>استهلاك العقارات وآلات ومعدات</td><td class="note-col">4</td><td class="num-col">{fmt(-pnl['depreciation_expense'])}</td>{c_td(-pnl['comp_depreciation_expense'])}</tr>
                        <tr class="subtotal-row"><td>مجموع المصروفات</td><td class="note-col"></td><td class="num-col">{fmt(-pnl['total_operating_expenses'])}</td>{c_td(-(pnl['comp_ga_expenses'] + pnl['comp_depreciation_expense']))}</tr>
                        <tr class="subtotal-row"><td>صافي الأرباح / (الخسائر) من الأنشطة الرئيسية</td><td class="note-col"></td><td class="num-col">{fmt(pnl['operating_profit_loss'])}</td>{c_td(pnl['comp_profit_before_zakat'])}</tr>
                        <tr class="subtotal-row"><td>صافي أرباح / (خسائر) الفترة قبل خصم الزكاة الشرعية</td><td class="note-col"></td><td class="num-col">{fmt(pnl['profit_before_zakat'])}</td>{c_td(pnl['comp_profit_before_zakat'])}</tr>
                        <tr><td>الزكاة الشرعية</td><td class="note-col">11</td><td class="num-col">{fmt(-pnl['zakat_expense'])}</td>{c_td(0.0)}</tr>
                        <tr class="double-bottom"><td>صافي أرباح / (خسائر) الفترة</td><td class="note-col"></td><td class="num-col">{fmt(pnl['net_profit_loss'])}</td>{c_td(pnl['comp_profit_before_zakat'])}</tr>
                        <tr class="double-bottom"><td>إجمالي الدخل الشامل</td><td class="note-col"></td><td class="num-col">{fmt(pnl['net_profit_loss'])}</td>{c_td(pnl['comp_profit_before_zakat'])}</tr>
                    </tbody>
                </table>

                <h3 class="note-heading" style="margin-top:26px;">قائمة التغير في حقوق الملكية عن الفترة المالية {period_text}</h3>
                <table class="fin-table">
                    <thead>
                        <tr><th>البيان</th><th class="num-col">رأس المال<br>ريال سعودي</th><th class="num-col">أرباح مبقاة / (خسائر متراكمة)<br>ريال سعودي</th><th class="num-col">المجموع<br>ريال سعودي</th></tr>
                    </thead>
                    <tbody>
                        <tr><td>الرصيد في بداية الفترة</td><td class="num-col">{fmt(eq['opening_capital'])}</td><td class="num-col">{fmt(eq['opening_retained'])}</td><td class="num-col">{fmt(eq['opening_total'])}</td></tr>
                        <tr><td>صافي أرباح / (خسائر) العام</td><td class="num-col">-</td><td class="num-col">{fmt(eq['period_net_profit'])}</td><td class="num-col">{fmt(eq['period_net_profit'])}</td></tr>
                        <tr class="double-bottom"><td>الرصيد في نهاية الفترة</td><td class="num-col">{fmt(eq['closing_capital'])}</td><td class="num-col">{fmt(eq['closing_retained'])}</td><td class="num-col">{fmt(eq['closing_total'])}</td></tr>
                    </tbody>
                </table>
                <div class="footer-note">"إن الإيضاحات المرفقة جزء لا يتجزأ من هذه القوائم المالية وتقرأ معها"</div>
            </div>

            <!-- قائمة التدفقات النقدية -->
            <div class="report-page">
                <div class="page-header">
                    <div><b>{comp_name} ({legal_form}) - {city}</b></div>
                    <div><b>قائمة التدفقات النقدية عن الفترة المالية {period_text} (بالريال السعودي)</b></div>
                </div>
                <table class="fin-table">
                    <thead>
                        <tr><th>البيان</th><th class="num-col">{period_text}<br>ريال سعودي</th></tr>
                    </thead>
                    <tbody>
                        <tr class="section-row"><td colspan="2">التدفقات النقدية من أنشطة التشغيل:</td></tr>
                        <tr><td>صافي أرباح / (خسائر) الفترة قبل خصم الزكاة الشرعية</td><td class="num-col">{fmt(cf['profit_before_zakat'])}</td></tr>
                        <tr><td>استهلاك العقارات وآلات ومعدات</td><td class="num-col">{fmt(cf['depreciation'])}</td></tr>
                        <tr class="double-bottom"><td>صافي الأرباح / (الخسائر) قبل التغيرات في رأس المال العامل</td><td class="num-col">{fmt(cf['profit_before_wc'])}</td></tr>

                        <tr class="section-row"><td colspan="2">التغيرات في رأس المال العامل:</td></tr>
                        <tr><td>ذمم مدينة تجارية</td><td class="num-col">{fmt(cf['wc_changes']['trade_receivables'])}</td></tr>
                        <tr><td>أرصدة مدينة أخرى</td><td class="num-col">{fmt(cf['wc_changes']['other_receivables'])}</td></tr>
                        <tr><td>المخزون</td><td class="num-col">{fmt(cf['wc_changes']['inventory'])}</td></tr>
                        <tr><td>ذمم دائنة تجارية</td><td class="num-col">{fmt(cf['wc_changes']['trade_payables'])}</td></tr>
                        <tr><td>أرصدة دائنة أخرى</td><td class="num-col">{fmt(cf['wc_changes']['other_payables'])}</td></tr>
                        <tr class="double-bottom"><td>صافي التدفق النقدي الناتج من / (المستخدم في) الأنشطة التشغيلية</td><td class="num-col">{fmt(cf['net_operating_cf'])}</td></tr>

                        <tr class="section-row"><td colspan="2">التدفقات النقدية من الأنشطة الاستثمارية:</td></tr>
                        <tr><td>مدفوعات لشراء العقارات وآلات ومعدات</td><td class="num-col">{fmt(cf['net_investing_cf'])}</td></tr>
                        <tr class="double-bottom"><td>مجموع النقد (المستخدم في) الأنشطة الاستثمارية</td><td class="num-col">{fmt(cf['net_investing_cf'])}</td></tr>

                        <tr class="section-row"><td colspan="2">التدفقات النقدية من الأنشطة التمويلية:</td></tr>
                        <tr><td>مستحق إلى أطراف ذات علاقة</td><td class="num-col">{fmt(cf['financing_details']['due_to_related_parties'])}</td></tr>
                        <tr><td>التغير في رأس المال وحقوق الملكية</td><td class="num-col">{fmt(cf['financing_details']['capital_change'])}</td></tr>
                        <tr class="double-bottom"><td>مجموع النقد الناتج من الأنشطة التمويلية</td><td class="num-col">{fmt(cf['net_financing_cf'])}</td></tr>

                        <tr class="subtotal-row"><td>مجموع النقد الناتج من / (المستخدم في) جميع الأنشطة</td><td class="num-col">{fmt(cf['net_cash_change'])}</td></tr>
                        <tr><td>رصيد النقد في أول العام</td><td class="num-col">-</td></tr>
                        <tr class="double-bottom"><td>رصيد النقد في آخر العام</td><td class="num-col">{fmt(cf['closing_cash'])}</td></tr>
                    </tbody>
                </table>
                <div class="footer-note">"إن الإيضاحات المرفقة تشكل جزءاً لا يتجزأ من هذه القوائم المالية وتقرأ معها"</div>
            </div>

            <!-- الإيضاحات 1 و 2 و 3 -->
            <div class="report-page">
                {page_header()}
                <h3 class="note-heading">1 - التكوين والنشاط</h3>
                <p class="policy-p">
                    تأسست <b>{comp_name}</b> بموجب السجل التجاري رقم (<b>{cr_no}</b>) بالمملكة العربية السعودية.<br>
                    <b>الكيان القانوني:</b> {legal_form}<br>
                    <b>العنوان:</b> {city}<br>
                    <b>الرقم الموحد للمنشأة:</b> {unified_no}<br>
                    <b>نشاط المنشأة:</b> {activity}<br>
                    <b>السنة المالية:</b> تغطي هذه القوائم المالية الفترة المالية {period_text}.
                </p>
                <h4 class="sub-heading">أسس الإعداد وبيان الالتزام</h4>
                <p class="policy-p">
                    تم إعداد القوائم المالية وفقاً للمعيار الدولي للتقرير المالي للمنشآت الصغيرة ومتوسطة الحجم (IFRS for SMEs) المعتمد في المملكة العربية السعودية من قبل الهيئة السعودية للمراجعين والمحاسبين (SOCPA). وتعرض المنشأة قائمة المركز المالي على أساس متداول وغير متداول، وقد تم إعداد هذه القوائم المالية وفقاً لمبدأ التكلفة التاريخية وعلى أساس الاستحقاق ومبدأ الاستمرارية، وتُعرض بالريال السعودي الذي يمثل العملة الوظيفية وعملة العرض للمنشأة.
                </p>

                <h3 class="note-heading">2 - التقديرات والافتراضات المحاسبية الهامة</h3>
                <p class="policy-p">
                    إن إعداد القوائم المالية يتطلب من الإدارة استخدام تقديرات وافتراضات تؤثر في تطبيق السياسات والقيم الظاهرة للأصول والالتزامات والإيرادات والمصروفات. وتقوم إدارة المنشأة بعمل تقييم لقدرتها على الاستمرار على أساس <b>مبدأ الاستمرارية</b> وتوصلت إلى أن لديها الموارد الكافية للاستمرار في نشاطها في المستقبل المنظور. ويُحتسب <b>الاستهلاك</b> على أساس القسط الثابت طوال الأعمار الإنتاجية المقدرة للأصول (بمعدل 20% سنوياً للسيارات والآلات والمعدات). كما يُقاس <b>المخزون</b> بالتكلفة (وفق طريقة المتوسط المرجح) أو بصافي القيمة القابلة للتحقق أيهما أقل.
                </p>

                <h3 class="note-heading">3 - ملخص السياسات المحاسبية الهامة</h3>
                <p class="policy-p">
                    <b>الممتلكات والآلات والمعدات:</b> تظهر بالتكلفة التاريخية بعد طرح الاستهلاك المتراكم وأي خسائر هبوط في القيمة.<br>
                    <b>النقد وما في حكمه:</b> يتضمن النقدية بالصناديق والأرصدة الجارية والودائع البنكية القابلة للتحويل الفوري.<br>
                    <b>الذمم التجارية المدينة والدائنة:</b> تُثبت الذمم المدينة بمبلغ الفاتورة الأصلي ناقصاً مخصص الخسائر الائتمانية المتوقعة، وتُثبت الذمم الدائنة لقاء المبالغ الواجب دفعها عن البضائع والخدمات المستلمة.<br>
                    <b>هيئة الزكاة والضريبة والجمارك (ZATCA):</b> يتم احتساب مخصص الزكاة الشرعية سنوياً وفقاً لتعليمات هيئة الزكاة والضريبة والجمارك في المملكة العربية السعودية.<br>
                    <b>تحقق الإيرادات والمصروفات:</b> يُقاس الإيراد بالقيمة العادلة للعوض المحصل أو المستحق التحصيل بعد استبعاد المردودات والخصومات، وتُسجل المصروفات الإدارية والعمومية وتكلفة الإيرادات على أساس الاستحقاق.
                </p>
            </div>

            <!-- الإيضاحات التفصيلية 4 و 5 و 6 و 7 و 8 -->
            <div class="report-page">
                {page_header()}
                <h3 class="note-heading">4 - ممتلكات وآلات ومعدات:</h3>
                <table class="fin-table">
                    <thead>
                        <tr><th>البيان</th><th class="num-col">العقارات والآلات والسيارات<br>ريال سعودي</th><th class="num-col">المجموع<br>ريال سعودي</th></tr>
                    </thead>
                    <tbody>
                        <tr class="section-row"><td colspan="3">التكلفة:</td></tr>
                        <tr><td>الرصيد في بداية الفترة</td><td class="num-col">{fmt(n4['opening_cost'])}</td><td class="num-col">{fmt(n4['opening_cost'])}</td></tr>
                        <tr><td>إضافات خلال الفترة</td><td class="num-col">{fmt(n4['additions_cost'])}</td><td class="num-col">{fmt(n4['additions_cost'])}</td></tr>
                        <tr class="double-bottom"><td>الرصيد في نهاية الفترة</td><td class="num-col">{fmt(n4['closing_cost'])}</td><td class="num-col">{fmt(n4['closing_cost'])}</td></tr>
                        <tr class="section-row"><td colspan="3">الاستهلاك المتراكم:</td></tr>
                        <tr><td>الرصيد في بداية الفترة</td><td class="num-col">{fmt(n4['opening_dep'])}</td><td class="num-col">{fmt(n4['opening_dep'])}</td></tr>
                        <tr><td>إضافات (استهلاك الفترة)</td><td class="num-col">{fmt(n4['additions_dep'])}</td><td class="num-col">{fmt(n4['additions_dep'])}</td></tr>
                        <tr class="double-bottom"><td>الرصيد في نهاية الفترة</td><td class="num-col">{fmt(n4['closing_dep'])}</td><td class="num-col">{fmt(n4['closing_dep'])}</td></tr>
                        <tr class="double-bottom"><td><b>صافي القيمة الدفترية في نهاية الفترة</b></td><td class="num-col"><b>{fmt(n4['net_book_value'])}</b></td><td class="num-col"><b>{fmt(n4['net_book_value'])}</b></td></tr>
                    </tbody>
                </table>

                <h3 class="note-heading">5 - النقدية وما في حكمها:</h3>
                {build_note_table(nd["note_5_cash"]["items"], nd["note_5_cash"]["total"], "نقد بالصندوق وبنوك")}

                <h3 class="note-heading">6 - ذمم مدينة تجارية:</h3>
                {build_note_table(nd["note_6_ar"]["items"], nd["note_6_ar"]["total"], "عملاء تجاريون")}

                <h3 class="note-heading">7 - أرصدة مدينة أخرى:</h3>
                {build_note_table(nd["note_7_other_ar"]["items"], nd["note_7_other_ar"]["total"], "أرصدة مدينة أخرى ومدفوعات مقدمة")}

                <h3 class="note-heading">8 - المخزون:</h3>
                {build_note_table(nd["note_8_inventory"]["items"], nd["note_8_inventory"]["total"], "مخزون بضاعة")}
            </div>

            <!-- الإيضاحات التفصيلية 9 و 10 و 11 و 12 -->
            <div class="report-page">
                {page_header()}
                <h3 class="note-heading">9 - ذمم تجارية دائنة:</h3>
                {build_note_table(nd["note_9_ap"]["items"], nd["note_9_ap"]["total"], "موردين")}

                <h3 class="note-heading">10 - أرصدة دائنة أخرى:</h3>
                {build_note_table(nd["note_10_other_ap"]["items"], nd["note_10_other_ap"]["total"], "دائنون متنوعون ومستحقات")}

                <h3 class="note-heading">11 / أ - مخصص الزكاة الشرعية والموقف الزكوي:</h3>
                <table class="fin-table">
                    <thead><tr><th>البيان</th><th class="num-col">{period_text}<br>ريال سعودي</th></tr></thead>
                    <tbody>
                        <tr><td>صافي أرباح / (خسائر) الفترة</td><td class="num-col">{fmt(n11['profit_before_zakat'])}</td></tr>
                        <tr class="subtotal-row"><td>صافي أرباح / (خسائر) الفترة المعدل</td><td class="num-col">{fmt(n11['adjusted_profit'])}</td></tr>
                        <tr><td>رأس المال</td><td class="num-col">{fmt(n11['capital'])}</td></tr>
                        <tr><td>أطراف ذات علاقة</td><td class="num-col">{fmt(n11['related_parties'])}</td></tr>
                        <tr class="subtotal-row"><td>إجمالي العناصر الموجبة</td><td class="num-col">{fmt(n11['positive_elements_net'])}</td></tr>
                        <tr class="section-row"><td colspan="2">يحسم:</td></tr>
                        <tr><td>صافي الأصول الثابتة</td><td class="num-col">{fmt(-n11['net_fixed_assets'])}</td></tr>
                        <tr><td>الخسائر المبقاة</td><td class="num-col">{fmt(-n11['retained_losses'])}</td></tr>
                        <tr class="subtotal-row"><td>إجمالي العناصر السالبة (الحطوم)</td><td class="num-col">{fmt(-n11['total_deductions'])}</td></tr>
                        <tr class="subtotal-row"><td>الوعاء الزكوي</td><td class="num-col">{fmt(n11['zakat_base'])}</td></tr>
                        <tr class="double-bottom"><td><b>مخصص الزكاة المستحقة</b></td><td class="num-col"><b>{fmt(n11['zakat_due'])}</b></td></tr>
                    </tbody>
                </table>
                <p class="policy-p">
                    <b>11 / أ - الموقف الزكوي والضريبي:</b> قدمت المنشأة إقرارات الزكاة وضريبة القيمة المضافة إلى هيئة الزكاة والضريبة والجمارك (ZATCA) في المواعيد النظامية.<br>
                    <b>11 / ب - حركة مخصص الزكاة:</b> الرصيد في بداية الفترة (-) ريال، مخصص الزكاة المكون للفترة ({fmt(n11['zakat_due'])}) ريال، الرصيد في نهاية الفترة ({fmt(n11['zakat_due'])}) ريال.
                </p>

                <h3 class="note-heading">12 - مستحق إلى أطراف ذات علاقة:</h3>
                <table class="fin-table">
                    <thead>
                        <tr><th>البيان</th><th>طبيعة التعامل</th><th>طبيعة العلاقة</th><th class="num-col">الحركة خلال السنة (دائن)</th><th class="num-col">الرصيد النهائي (دائن)</th></tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>{n12['partner_name']}</td>
                            <td style="text-align:center;">تمويلي</td>
                            <td style="text-align:center;">شريك / مالك</td>
                            <td class="num-col">{fmt(n12['total'])}</td>
                            <td class="num-col">{fmt(n12['total'])}</td>
                        </tr>
                        <tr class="double-bottom">
                            <td colspan="3"><b>المجموع</b></td>
                            <td class="num-col"><b>{fmt(n12['total'])}</b></td>
                            <td class="num-col"><b>{fmt(n12['total'])}</b></td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- الإيضاحات التفصيلية 13 و 14 و 15 و 16-18 -->
            <div class="report-page">
                {page_header()}
                <h3 class="note-heading">13 - الإيرادات:</h3>
                <table class="fin-table">
                    <thead><tr><th>البيان</th><th class="num-col">{period_text}<br>ريال سعودي</th></tr></thead>
                    <tbody>
                        <tr><td>إيرادات المبيعات والنشاط</td><td class="num-col">{fmt(n13['sales'])}</td></tr>
                        <tr><td>إيرادات أخرى</td><td class="num-col">{fmt(n13['other_income'])}</td></tr>
                        <tr><td>مردودات المبيعات والخصم المسموح به</td><td class="num-col">{fmt(-n13['sales_returns'])}</td></tr>
                        <tr class="double-bottom"><td><b>المجموع</b></td><td class="num-col"><b>{fmt(n13['total'])}</b></td></tr>
                    </tbody>
                </table>

                <h3 class="note-heading">14 - تكلفة الإيرادات:</h3>
                <table class="fin-table">
                    <thead><tr><th>البيان</th><th class="num-col">{period_text}<br>ريال سعودي</th></tr></thead>
                    <tbody>
                        <tr><td>مخزون أول المدة</td><td class="num-col">{fmt(n14['opening_inventory'])}</td></tr>
                        <tr><td>مشتريات وتكاليف النشاط خلال الفترة</td><td class="num-col">{fmt(n14['purchases_during_period'])}</td></tr>
                        <tr><td>يخصم: مخزون آخر المدة</td><td class="num-col">{fmt(-n14['closing_inventory'])}</td></tr>
                        <tr class="double-bottom"><td><b>المجموع (صافي تكلفة الإيرادات)</b></td><td class="num-col"><b>{fmt(n14['total'])}</b></td></tr>
                    </tbody>
                </table>

                <h3 class="note-heading">15 - المصاريف الإدارية والعمومية:</h3>
                <table class="fin-table">
                    <thead><tr><th>البيان</th><th class="num-col">{period_text}<br>ريال سعودي</th></tr></thead>
                    <tbody>{ga_rows_html}</tbody>
                </table>

                <h3 class="note-heading">16 - الأدوات المالية وإدارة المخاطر:</h3>
                <p class="policy-p">
                    <b>مخاطر السيولة والائتمان والعملات:</b> تتم مراقبة احتياجات السيولة على أساس شهري للتأكد من توفر أموال كافية لمقابلة أي التزامات عند استحقاقها، وتودع المنشأة أموالها في مصارف مالية ذات ملاءة عالية، وتُمسك حساباتها بالريال السعودي، وتقارب القيم العادلة للأصول والالتزامات المالية قيمتها الدفترية.
                </p>
                <h3 class="note-heading">17 - أرقام المقارنة:</h3>
                <p class="policy-p">تم عرض وتبويب بنود القوائم المالية بما يتماشى مع معايير العرض والإفصاح المعتمدة للفترة الحالية.</p>
                <h3 class="note-heading">18 - أحداث لاحقة بعد فترة التقرير المالي:</h3>
                <p class="policy-p">لا توجد أية أحداث جوهرية بعد تاريخ قائمة المركز المالي يترتب عليها تعديلات أو إفصاحات في القوائم المالية.</p>
            </div>
        </body>
        </html>
        """

    @classmethod
    def generate_cpa_word_doc(cls, pkg: Dict[str, Any]) -> bytes:
        """تصدير التقرير الكامل (الغلاف + تقرير المراجع + القوائم الأربع + الـ 18 إيضاحاً) كملف Word قابل للتعديل"""
        word_html = cls.generate_cpa_printable_html(pkg, for_word=True)
        return word_html.encode("utf-8-sig")

    @classmethod
    def generate_cpa_excel_workbook(cls, classified_df: pd.DataFrame, pkg: Dict[str, Any]) -> io.BytesIO:
        """تصدير القوائم المالية الخمس وجداول الإيضاحات الـ 18 وميزان المراجعة المصنف إلى مصنف Excel"""
        wb = openpyxl.Workbook()
        wb.remove(wb.active)

        m = pkg["metadata"]
        bs = pkg["balance_sheet"]
        pnl = pkg["income_statement"]
        eq = pkg["equity_statement"]
        cf = pkg["cash_flow_statement"]
        nd = pkg["notes_details"]
        period_lbl = m.get("period_text", "الفترة المالية")

        header_fill = PatternFill(start_color="1E3A8A", end_color="1E3A8A", fill_type="solid")
        sec_fill = PatternFill(start_color="E2E8F0", end_color="E2E8F0", fill_type="solid")
        tot_fill = PatternFill(start_color="FEF08A", end_color="FEF08A", fill_type="solid")

        f_title = Font(name="Calibri", size=13, bold=True, color="FFFFFF")
        f_bold = Font(name="Calibri", size=11, bold=True)
        f_reg = Font(name="Calibri", size=10)
        border_thin = Border(
            left=Side(style="thin", color="CBD5E1"), right=Side(style="thin", color="CBD5E1"),
            top=Side(style="thin", color="CBD5E1"), bottom=Side(style="thin", color="CBD5E1")
        )
        border_double = Border(
            top=Side(style="thin", color="000000"), bottom=Side(style="double", color="000000"),
            left=Side(style="thin", color="CBD5E1"), right=Side(style="thin", color="CBD5E1")
        )

        def write_sheet_rows(sheet_title: str, banner: str, headers: List[str], rows: List[Tuple]):
            ws = wb.create_sheet(title=sheet_title)
            ws.views.sheetView[0].rightToLeft = True
            ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=len(headers))
            ws.cell(1, 1, f"{m.get('company_name', '')} - {banner}").font = f_title
            ws.cell(1, 1).fill = header_fill
            ws.cell(1, 1).alignment = Alignment(horizontal="center", vertical="center")

            for c_i, h in enumerate(headers, start=1):
                c = ws.cell(2, c_i, h)
                c.font = f_title
                c.fill = header_fill
                c.alignment = Alignment(horizontal="center", vertical="center")

            r_idx = 3
            for r_tuple in rows:
                style_tag = r_tuple[-1]
                vals = r_tuple[:-1]
                for c_i, v in enumerate(vals, start=1):
                    cell = ws.cell(r_idx, c_i, v)
                    cell.font = f_bold if style_tag in ("SEC", "SUB", "TOT") else f_reg
                    cell.border = border_double if style_tag == "TOT" else border_thin
                    if isinstance(v, (int, float)):
                        cell.number_format = "#,##0;(#,##0);\"-\""
                        cell.alignment = Alignment(horizontal="center")
                    else:
                        cell.alignment = Alignment(horizontal="right" if c_i == 1 else "center")
                    if style_tag == "SEC":
                        cell.fill = sec_fill
                    elif style_tag == "TOT":
                        cell.fill = tot_fill
                r_idx += 1

            for col in ws.columns:
                col_letter = get_column_letter(col[0].column)
                ws.column_dimensions[col_letter].width = max(max(len(str(c.value or "")) for c in col) + 5, 16)

        write_sheet_rows(
            "1-قائمة المركز المالي",
            f"قائمة المركز المالي ({period_lbl})",
            ["البيان", "إيضاح", "ريال سعودي (الحالية)", "ريال سعودي (المقارنة)"],
            [
                ("الأصول غير المتداولة", "", "", "", "SEC"),
                ("العقارات والآلات والمعدات - بالصافي", "4", bs["non_current_assets"]["net_ppe"], bs["non_current_assets"]["comp_net_ppe"], "REG"),
                ("مجموع الأصول غير المتداولة", "", bs["non_current_assets"]["total"], bs["non_current_assets"]["comp_total"], "TOT"),
                ("الأصول المتداولة", "", "", "", "SEC"),
                ("النقدية وما في حكمها", "5", bs["current_assets"]["cash_and_banks"], bs["current_assets"]["comp_cash"], "REG"),
                ("ذمم مدينة تجارية", "6", bs["current_assets"]["trade_receivables"], bs["current_assets"]["comp_ar"], "REG"),
                ("أرصدة مدينة أخرى", "7", bs["current_assets"]["other_receivables"], bs["current_assets"]["comp_other_ar"], "REG"),
                ("المخزون", "8", bs["current_assets"]["inventory"], bs["current_assets"]["comp_inventory"], "REG"),
                ("مجموع الأصول المتداولة", "", bs["current_assets"]["total"], bs["current_assets"]["comp_total"], "SUB"),
                ("إجمالي الأصول المتداولة وغير المتداولة", "", bs["total_assets"], bs["comp_total_assets"], "TOT"),
                ("حقوق الملكية والالتزامات", "", "", "", "SEC"),
                ("رأس المال", "", bs["equity"]["capital"], bs["equity"]["capital"], "REG"),
                ("أرباح مبقاة / (خسائر متراكمة)", "", bs["equity"]["closing_retained_earnings"], bs["equity"]["opening_retained_earnings"], "REG"),
                ("مجموع حقوق الملكية", "", bs["equity"]["total"], bs["equity"]["capital"] + bs["equity"]["opening_retained_earnings"], "TOT"),
                ("الالتزامات المتداولة", "", "", "", "SEC"),
                ("ذمم دائنة تجارية", "9", bs["current_liabilities"]["trade_payables"], bs["current_liabilities"]["comp_ap"], "REG"),
                ("أرصدة دائنة أخرى", "10", bs["current_liabilities"]["other_payables"], bs["current_liabilities"]["comp_other_ap"], "REG"),
                ("مخصص الزكاة", "11", bs["current_liabilities"]["zakat_provision"], 0.0, "REG"),
                ("مستحق إلى أطراف ذات علاقة", "12", bs["current_liabilities"]["due_to_related_parties"], bs["current_liabilities"]["comp_related_parties"], "REG"),
                ("مجموع الالتزامات المتداولة", "", bs["current_liabilities"]["total"], bs["current_liabilities"]["comp_ap"] + bs["current_liabilities"]["comp_other_ap"] + bs["current_liabilities"]["comp_related_parties"], "SUB"),
                ("مجموع الالتزامات وحقوق الملكية", "", bs["total_liabilities_and_equity"], bs["comp_total_assets"], "TOT"),
            ]
        )

        write_sheet_rows(
            "2-قائمة الدخل الشامل",
            f"قائمة الدخل والدخل الشامل ({period_lbl})",
            ["البيان", "إيضاح", "ريال سعودي (الحالية)", "ريال سعودي (المقارنة)"],
            [
                ("الإيرادات", "13", pnl["revenues"], pnl["comp_revenues"], "REG"),
                ("يخصم: تكلفة الإيرادات", "14", -pnl["cost_of_revenues"], -pnl["comp_cost_of_revenues"], "REG"),
                ("مجمل الربح من الأنشطة الرئيسية", "", pnl["gross_profit"], pnl["comp_gross_profit"], "TOT"),
                ("المصروفات الإدارية والعمومية", "15", -pnl["ga_expenses"], -pnl["comp_ga_expenses"], "REG"),
                ("استهلاك العقارات وآلات ومعدات", "4", -pnl["depreciation_expense"], -pnl["comp_depreciation_expense"], "REG"),
                ("مجموع المصروفات", "", -pnl["total_operating_expenses"], -(pnl["comp_ga_expenses"] + pnl["comp_depreciation_expense"]), "SUB"),
                ("صافي أرباح / (خسائر) الفترة قبل الزكاة", "", pnl["profit_before_zakat"], pnl["comp_profit_before_zakat"], "SUB"),
                ("الزكاة الشرعية", "11", -pnl["zakat_expense"], 0.0, "REG"),
                ("صافي أرباح / (خسائر) الفترة (الدخل الشامل)", "", pnl["net_profit_loss"], pnl["comp_profit_before_zakat"], "TOT"),
            ]
        )

        write_sheet_rows(
            "3-التغير في حقوق الملكية",
            f"قائمة التغير في حقوق الملكية ({period_lbl})",
            ["البيان", "رأس المال", "أرباح مبقاة / (خسائر متراكمة)", "المجموع"],
            [
                ("الرصيد في بداية الفترة", eq["opening_capital"], eq["opening_retained"], eq["opening_total"], "REG"),
                ("صافي أرباح / (خسائر) العام", 0.0, eq["period_net_profit"], eq["period_net_profit"], "REG"),
                ("الرصيد في نهاية الفترة", eq["closing_capital"], eq["closing_retained"], eq["closing_total"], "TOT"),
            ]
        )

        write_sheet_rows(
            "4-التدفقات النقدية",
            f"قائمة التدفقات النقدية ({period_lbl})",
            ["البيان", "ريال سعودي"],
            [
                ("التدفقات النقدية من أنشطة التشغيل", "", "SEC"),
                ("صافي أرباح / (خسائر) الفترة قبل خصم الزكاة الشرعية", cf["profit_before_zakat"], "REG"),
                ("استهلاك العقارات وآلات ومعدات", cf["depreciation"], "REG"),
                ("صافي قبل التغيرات في رأس المال العامل", cf["profit_before_wc"], "SUB"),
                ("ذمم مدينة تجارية", cf["wc_changes"]["trade_receivables"], "REG"),
                ("أرصدة مدينة أخرى", cf["wc_changes"]["other_receivables"], "REG"),
                ("المخزون", cf["wc_changes"]["inventory"], "REG"),
                ("ذمم دائنة تجارية", cf["wc_changes"]["trade_payables"], "REG"),
                ("أرصدة دائنة أخرى", cf["wc_changes"]["other_payables"], "REG"),
                ("صافي التدفق النقدي من الأنشطة التشغيلية", cf["net_operating_cf"], "TOT"),
                ("التدفقات النقدية من الأنشطة الاستثمارية", cf["net_investing_cf"], "TOT"),
                ("التدفقات النقدية من الأنشطة التمويلية", cf["net_financing_cf"], "TOT"),
                ("رصيد النقد في آخر العام", cf["closing_cash"], "TOT"),
            ]
        )

        notes_rows = [
            ("إيضاح 4 - صافي الممتلكات والآلات والمعدات", nd["note_4_ppe"]["net_book_value"], "TOT"),
            ("إيضاح 5 - النقدية وما في حكمها", nd["note_5_cash"]["total"], "SEC"),
        ]
        for it in nd["note_5_cash"]["items"]:
            notes_rows.append((f"   - {it['name']}", it["balance"], "REG"))
        notes_rows.append(("إيضاح 6 - ذمم مدينة تجارية", nd["note_6_ar"]["total"], "SEC"))
        for it in nd["note_6_ar"]["items"]:
            notes_rows.append((f"   - {it['name']}", it["balance"], "REG"))
        notes_rows.append(("إيضاح 7 - أرصدة مدينة أخرى", nd["note_7_other_ar"]["total"], "SEC"))
        for it in nd["note_7_other_ar"]["items"]:
            notes_rows.append((f"   - {it['name']}", it["balance"], "REG"))
        notes_rows.append(("إيضاح 8 - المخزون", nd["note_8_inventory"]["total"], "SEC"))
        notes_rows.append(("إيضاح 9 - ذمم تجارية دائنة (الموردون)", nd["note_9_ap"]["total"], "SEC"))
        notes_rows.append(("إيضاح 10 - أرصدة دائنة أخرى", nd["note_10_other_ap"]["total"], "SEC"))
        notes_rows.append(("إيضاح 11 - الوعاء الزكوي", nd["note_11_zakat"]["zakat_base"], "SUB"))
        notes_rows.append(("إيضاح 11 - مخصص الزكاة الشرعية المستحقة", nd["note_11_zakat"]["zakat_due"], "TOT"))
        notes_rows.append(("إيضاح 12 - مستحق إلى أطراف ذات علاقة", nd["note_12_related_parties"]["total"], "SEC"))
        notes_rows.append(("إيضاح 13 - صافي الإيرادات", nd["note_13_revenues"]["total"], "TOT"))
        notes_rows.append(("إيضاح 14 - صافي تكلفة الإيرادات", nd["note_14_cost_of_revenues"]["total"], "TOT"))
        notes_rows.append(("إيضاح 15 - تفصيل المصاريف الإدارية والعمومية:", nd["note_15_ga_expenses"]["total"], "SEC"))
        for it in nd["note_15_ga_expenses"]["items"]:
            notes_rows.append((f"   - {it['name']}", it["balance"], "REG"))

        write_sheet_rows("5-الإيضاحات التفصيلية (4-15)", "الإيضاحات حول القوائم المالية", ["البند / الإيضاح", "ريال سعودي"], notes_rows)

        tb_rows = []
        for _, r in classified_df.iterrows():
            tb_rows.append((
                str(r["كود الحساب"]), str(r["اسم الحساب"]),
                float(r["مدين آخر المدة"]), float(r["دائن آخر المدة"]),
                float(r.get("مدين مقارنة", 0.0)), float(r.get("دائن مقارنة", 0.0)),
                str(r["التصنيف في القوائم والإيضاحات"]), "REG"
            ))
        write_sheet_rows(
            "6-ميزان المراجعة المصنف",
            "ميزان المراجعة وتوجيه الإيضاحات",
            ["كود الحساب", "اسم الحساب", "مدين", "دائن", "مدين مقارنة", "دائن مقارنة", "التبويب في القوائم والإيضاحات"],
            tb_rows
        )

        out = io.BytesIO()
        wb.save(out)
        out.seek(0)
        return out
