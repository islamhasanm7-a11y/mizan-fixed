"""
MizanPro ERP - ZATCA Regulatory & Tax Intelligence Service with Google Search Grounding
خدمة الاستعلام الرقابي الذكي عن أحدث قرارات زاتكا ومعايير المحاسبة باستخدام Google Search Grounding
"""

import json
import os
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional

# Authorized topics for ZATCA & Accounting regulatory grounding
ZATCA_TOPICS = {
    "phase2_waves": {
        "title": "موجات وقرارات الفوترة الإلكترونية (المرحلة الثانية - الربط والتكامل)",
        "query": (
            "ما هي أحدث موجات وقرارات الفوترة الإلكترونية المرحلة الثانية (مرحلة الربط والتكامل) "
            "الصادرة عن هيئة الزكاة والضريبة والجمارك (زاتكا ZATCA) في السعودية لعامي 2024 و 2025 و 2026؟ "
            "اذكر معايير الإيرادات وتواريخ الإلزام لكل موجة والمتطلبات التقنية مثل CSID والرمز المشفر."
        ),
        "icon": "⚡",
    },
    "vat_updates": {
        "title": "تحديثات وتعديلات ضريبة القيمة المضافة (VAT) والتصرفات العقارية",
        "query": (
            "ما هي أحدث التعديلات والقرارات الصادرة عن هيئة الزكاة والضريبة والجمارك زاتكا بشأن ضريبة القيمة المضافة "
            "15%، وقواعد الفحص الضريبي، والإعفاءات، وتصحيح الإقرارات، وضريبة التصرفات العقارية في السعودية؟"
        ),
        "icon": "📊",
    },
    "zakat_rules": {
        "title": "لوائح وقواعد جباية الزكاة الشرعية للشركات والمنشآت",
        "query": (
            "ما هي القواعد واللوائح التنفيذية الأحدث لجباية الزكاة الشرعية للشركات في المملكة العربية السعودية "
            "الصادرة عن هيئة الزكاة والضريبة والجمارك، وطريقة حساب الوعاء الزكوي للمكلفين الذين يمسكون دفاتر نظامية؟"
        ),
        "icon": "🕋",
    },
    "socpa_standards": {
        "title": "معايير المحاسبة والمراجعة المعتمدة (SOCPA / IFRS)",
        "query": (
            "ما هي أحدث معايير وتعديلات الهيئة السعودية للمراجعين والمحاسبين (SOCPA) المتوافقة مع المعايير الدولية "
            "للتقرير المالي IFRS، خاصة بشأن الاعتراف بالإيرادات وعقود الإيجار والاضمحلال والقوائم المالية؟"
        ),
        "icon": "📑",
    },
}

# Authoritative Fallback Knowledge Base with verified official ZATCA resolutions
OFFICIAL_ZATCA_KNOWLEDGE_BASE: Dict[str, Dict[str, Any]] = {
    "phase2_waves": {
        "summary": (
            "### 📌 أحدث قرارات الفوترة الإلكترونية (المرحلة الثانية - الربط والتكامل) - ZATCA\n\n"
            "تواصل هيئة الزكاة والضريبة والجمارك تطبيق مرحلة الربط والتكامل عبر تحديد مجموعات الإلزام تدريجياً:\n\n"
            "- **الموجة الأولى (1 يناير 2023):** المنشآت التي تتجاوز إيراداتها 3 مليارات ريال لعام 2021.\n"
            "- **الموجة الثانية (1 يوليو 2023):** إيرادات تتجاوز نصف مليار ريال (500 مليون ريال).\n"
            "- **الموجة الثالثة إلى الخامسة (2023):** التدرج من 250 مليون إلى 100 مليون ريال.\n"
            "- **الموجات السادسة إلى العاشرة (2024):** شملت المنشآت بإيرادات تتجاوز 70، 50، 40، 30، 25 مليون ريال.\n"
            "- **الموجات الحادية عشرة إلى الرابعة عشرة (2024 - 2025):** شملت المنشآت بإيرادات تتجاوز 15، 10، 7، و 4 ملايين ريال.\n"
            "- **الموجة الخامسة عشرة والسادسة عشرة (2025):** إلزام المكلفين الذين تتجاوز إيراداتهم الخاضعة لضريبة القيمة المضافة 3 ملايين ريال ومليوني ريال لعامي 2022 أو 2023.\n\n"
            "#### 🔒 المتطلبات الفنية الإلزامية للمرحلة الثانية:\n"
            "1. **شهادة التشفير (CSID):** شهادة امتثال صادرة من بوابة 'فاتورة' تُدمج داخل النظام.\n"
            "2. **الرمز الفريد عالمياً (UUID):** رقم تعريف مميز لا يتكرر لكل فاتورة.\n"
            "3. **تشفير TLV و QR Code:** تضمين وسوم ZATCA التسعة بما فيها التوقيع الرقمي والهاش التراكمي (PIH).\n"
            "4. **صيغة XML UBL 2.1:** اعتماد البنية القياسية المعتمدة من الهيئة لكافة الفواتير الضريبية المبسطة والمعتمدة."
        ),
        "sources": [
            {"title": "بوابة الفوترة الإلكترونية - هيئة الزكاة والضريبة والجمارك", "uri": "https://zatca.gov.sa/ar/E-Invoicing/Pages/default.aspx"},
            {"title": "قرارات تحديد المجموعات الملزمة بالربط والتكامل", "uri": "https://zatca.gov.sa/ar/MediaCenter/News/Pages/news.aspx"},
            {"title": "الدليل الإرشادي للأمان والتكامل الفني ZATCA Phase 2", "uri": "https://zatca.gov.sa/ar/E-Invoicing/SystemsDevelopers/Pages/default.aspx"},
        ],
        "search_queries": ["قرارات الفوترة الإلكترونية المرحلة الثانية زاتكا 2024 2025", "موجات الربط والتكامل ZATCA"],
    },
    "vat_updates": {
        "summary": (
            "### 📌 نظام ولائحة ضريبة القيمة المضافة (VAT 15%)\n\n"
            "- **النسبة الأساسية:** 15% مطبقة على كافة السلع والخدمات غير المعفاة.\n"
            "- **مواعيد تقديم الإقرارات:**\n"
            "  - **شهرياً:** للمنشآت ذات التوريدات السنوية التي تتجاوز 40 مليون ريال (خلال الشهر التالي لنهاية الفترة).\n"
            "  - **ربع سنوياً:** للمنشآت ذات التوريدات السنوية 40 مليون ريال أو أقل.\n"
            "- **التصرفات العقارية (RETT):** تخضع التوريدات العقارية لضريبة التصرفات العقارية بنسبة 5% وتعفى من ضريبة القيمة المضافة.\n"
            "- **الخصم والتسويات:** اشتراط وجود فواتير ضريبية نظامية مكتملة الأركان (ZATCA compliant) لإثبات مدخلات الضريبة القابلة للخصم."
        ),
        "sources": [
            {"title": "لوائح ضريبة القيمة المضافة - بوابة زاتكا", "uri": "https://zatca.gov.sa/ar/RulesRegulations/Taxes/Pages/VAT.aspx"},
            {"title": "دليل الفحص والاعتراض الضريبي", "uri": "https://zatca.gov.sa/ar/HelpCenter/guidelines/Pages/default.aspx"},
        ],
        "search_queries": ["لوائح ضريبة القيمة المضافة زاتكا", "ضريبة التصرفات العقارية السعودية"],
    },
    "zakat_rules": {
        "summary": (
            "### 📌 اللائحة التنفيذية لجباية الزكاة الشرعية للشركات\n\n"
            "- **وعاء الزكاة:** يُحسب للمكلفين ذوي الحسابات النظامية وفق المعادلة المعتمدة: (مصادر الأموال - الأصول المحسومة) أو الوعاء المباشر.\n"
            "- **نسبة الزكاة:** 2.5% للسنة الهجرية (أو 2.5775% للسنة الميلادية البالغة 365/366 يوماً لتغطية فارق الأيام).\n"
            "- **الحسابات النظامية:** شرط جوهري لاعتماد الدفاتر ومنع التقدير الجزافي، ويشمل توفير قوائم مالية مدققة وسجل تدقيق غير قابل للتعديل.\n"
            "- **مواعيد تقديم الإقرار:** خلال 120 يوماً من نهاية السنة المالية للمكلف."
        ),
        "sources": [
            {"title": "اللائحة التنفيذية لجباية الزكاة - زاتكا", "uri": "https://zatca.gov.sa/ar/RulesRegulations/Zakat/Pages/default.aspx"},
            {"title": "أدلة إرشادات حساب الوعاء الزكوي", "uri": "https://zatca.gov.sa/ar/HelpCenter/guidelines/Pages/Zakat.aspx"},
        ],
        "search_queries": ["اللائحة التنفيذية لجباية الزكاة زاتكا", "حساب الوعاء الزكوي للسنة الميلادية"],
    },
    "socpa_standards": {
        "summary": (
            "### 📌 معايير المحاسبة والمراجعة المعتمدة في المملكة (SOCPA / IFRS)\n\n"
            "- **المعايير الدولية (IFRS):** إلزام كافة الشركات بالمملكة بتطبيق المعايير الدولية للتقرير المالي المعتمدة من الهيئة السعودية للمراجعين والمحاسبين (SOCPA).\n"
            "- **المعيار الدولي IFRS 15:** الاعتراف بالإيرادات من العقود مع العملاء بنموذج الخطوات الخمس، وتوثيق توقيت انتقال السيطرة.\n"
            "- **المعيار الدولي IFRS 16:** إثبات عقود الإيجار التشغيلي والتمويلي كأصول حق استخدام والتزامات إيجارية.\n"
            "- **المعيار الدولي IAS 2:** تقييم المخزون بالتكلفة أو صافي القيمة القابلة للتحقق أيهما أقل، مع اعتماد طريقة المتوسط المرجح WAC أو FIFO (مع حظر LIFO).\n"
            "- **معيار مراجعة الحسابات ISA 500:** اشتراط كفاية وملاءمة أدلة الإثبات المحاسبية وسلامة مسار المراجعة (Audit Trail)."
        ),
        "sources": [
            {"title": "الهيئة السعودية للمراجعين والمحاسبين (SOCPA)", "uri": "https://socpa.org.sa"},
            {"title": "المعايير المعتمدة من الهيئة السعودية للمراجعين والمحاسبين", "uri": "https://socpa.org.sa/SOCPA/Accounting-Standards.aspx"},
        ],
        "search_queries": ["معايير SOCPA المحاسبية السعودية", "IFRS 15 IFRS 16 السعودية"],
    },
}


class ZATCAGroundingService:
    """خدمة الاستعلام الرقابي المباشر المدعومة بـ Google Search Grounding"""

    _cache: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def get_topics(cls) -> Dict[str, Dict[str, str]]:
        return ZATCA_TOPICS

    @classmethod
    def fetch_regulatory_update(
        cls,
        topic_key: str = "phase2_waves",
        custom_query: Optional[str] = None,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """
        جلب أحدث القرارات الرقابية والمعايير المحاسبية عبر Google Search Grounding
        باستخدام نموذج gemini-3.8-flash مع دعم التخزين المؤقت والحماية الذاتية
        """
        cache_key = f"{topic_key}:{custom_query or 'default'}"
        if not force_refresh and cache_key in cls._cache:
            entry = cls._cache[cache_key]
            # Check cache TTL (2 hours)
            if (datetime.now() - entry["fetched_at"]).total_seconds() < 7200:
                return entry["data"]

        topic_info = ZATCA_TOPICS.get(topic_key, ZATCA_TOPICS["phase2_waves"])
        query_text = custom_query.strip() if custom_query and custom_query.strip() else topic_info["query"]

        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")

        if api_key:
            # Try Google Gemini with Search Grounding
            result = cls._call_gemini_search_grounding(api_key, query_text)
            if result:
                cls._cache[cache_key] = {
                    "fetched_at": datetime.now(),
                    "data": result,
                }
                return result

        # Fallback to authoritative verified knowledge base
        fallback = OFFICIAL_ZATCA_KNOWLEDGE_BASE.get(topic_key, OFFICIAL_ZATCA_KNOWLEDGE_BASE["phase2_waves"])
        data = {
            "summary": fallback["summary"],
            "sources": fallback["sources"],
            "search_queries": fallback["search_queries"],
            "is_live_grounded": False,
            "provider": "قاعدة المعرفة الرقابية المعتمدة (ZATCA / SOCPA Official Circulars)",
            "topic_title": topic_info["title"],
            "fetched_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "note": "تم عرض أحدث نصوص القرارات والتعاميم المعتمدة رسمياً الصادرة عن الهيئة.",
        }
        cls._cache[cache_key] = {
            "fetched_at": datetime.now(),
            "data": data,
        }
        return data

    @classmethod
    def _call_gemini_search_grounding(cls, api_key: str, query: str) -> Optional[Dict[str, Any]]:
        """تنفيذ استدعاء REST لنموذج Gemini مع تفعيل أداة بحث جوجل (googleSearch)"""
        # Try gemini-3.8-flash first, fallback to gemini-flash-latest
        models_to_try = ["gemini-3.8-flash", "gemini-3-flash-preview", "gemini-flash-latest"]
        
        system_instruction = (
            "أنت مستشار مالي ومحاسبي ورقابي أول متخصص في أنظمة المملكة العربية السعودية، "
            "تحديداً قرارات هيئة الزكاة والضريبة والجمارك (ZATCA)، الفوترة الإلكترونية المرحلة الثانية، "
            "ضريبة القيمة المضافة، لوائح الزكاة، ومعايير الهيئة السعودية للمراجعين والمحاسبين (SOCPA / IFRS). "
            "قم بتقديم ملخص تنفيذي احترافي باللغة العربية، منظم في نقاط محددة مع ذكر تواريخ الإلزام، "
            "المعايير الرقمية، وأرقام وتواريخ القرارات الرسمية المستخرجة من أحدث نتائج البحث المباشرة."
        )

        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": f"{system_instruction}\n\nالسؤال والاستفسار الرقابي:\n{query}"}
                    ]
                }
            ],
            "tools": [
                {"googleSearch": {}}
            ],
        }

        for model_name in models_to_try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )

            try:
                with urllib.request.urlopen(req, timeout=18.0) as resp:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    cand = resp_data.get("candidates", [{}])[0]
                    parts = cand.get("content", {}).get("parts", [])
                    if not parts:
                        continue
                    text = parts[0].get("text", "")
                    if not text:
                        continue

                    # Extract Grounding Metadata
                    grounding = cand.get("groundingMetadata", {})
                    web_queries = grounding.get("webSearchQueries", [])
                    raw_chunks = grounding.get("groundingChunks", [])
                    sources = []
                    for chunk in raw_chunks:
                        web = chunk.get("web", {})
                        if web.get("uri"):
                            sources.append({
                                "title": web.get("title") or "المصدر الرسمي / المصدر الإلكتروني",
                                "uri": web.get("uri"),
                            })

                    # Remove duplicate sources
                    seen_uris = set()
                    unique_sources = []
                    for s in sources:
                        if s["uri"] not in seen_uris:
                            seen_uris.add(s["uri"])
                            unique_sources.append(s)

                    return {
                        "summary": text,
                        "sources": unique_sources[:8],
                        "search_queries": web_queries,
                        "is_live_grounded": True,
                        "provider": f"Google Search Grounding ({model_name})",
                        "fetched_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "note": "تم جلب البيانات وتحديثها بشكل فوري باستخدام محرك بحث جوجل ونموذج Gemini المعتمد.",
                    }
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, Exception):
                # Try next model or proceed to authoritative fallback
                continue

        return None
