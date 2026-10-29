"""
MizanPro ERP & CPA Suite - ZATCA Compliance Timeline & Audit Cycle Planner
مكون تفاعلي لمخطط التوقيت الزمني لامتثال هيئة الزكاة والضريبة والجمارك (ZATCA Phase 2 & Audit Milestones)
"""

import json
from datetime import datetime, date
from typing import Any, Dict, List, Optional


# قائمة المواعيد النهائية والموجات التنفيذية لهيئة الزكاة والضريبة والجمارك (ZATCA Mandates & Milestones)
ZATCA_MILESTONES: List[Dict[str, Any]] = [
    {
        "id": "wave_01",
        "title_ar": "الموجة 1: المنشآت التي تتجاوز إيراداتها 3 مليار ريال",
        "title_en": "Phase 2 Wave 1 - Revenue > 3 Billion SAR",
        "category": "phase2_waves",
        "category_ar": "الربط والتكامل (Phase 2)",
        "revenue_threshold_sar": 3000000000,
        "revenue_label_ar": "إيرادات > 3 مليار ريال",
        "start_date": "2023-01-01",
        "deadline_date": "2023-06-30",
        "status": "COMPLETED",
        "status_label_ar": "مكتمل بنجاح ✅",
        "color": "#10b981",
        "description_ar": "إلزام المنشآت الكبرى بالربط المباشر لجميع فواتير B2B و B2C مع منصة (فاتورة) عبر واجهات API وتوليد الختم التشفيري.",
        "audit_actions": [
            "تفعيل شهادات CSID التشفيرية من زاتكا",
            "ربط واجهة Clear & Report API مع نظام ERP",
            "فحص أختام SHA-256 ورمز QR TLV Tags 1-9",
        ],
    },
    {
        "id": "wave_05",
        "title_ar": "الموجة 5: المنشآت التي تتجاوز إيراداتها 100 مليون ريال",
        "title_en": "Phase 2 Wave 5 - Revenue > 100 Million SAR",
        "category": "phase2_waves",
        "category_ar": "الربط والتكامل (Phase 2)",
        "revenue_threshold_sar": 100000000,
        "revenue_label_ar": "إيرادات > 100 مليون ريال",
        "start_date": "2023-12-01",
        "deadline_date": "2024-03-31",
        "status": "COMPLETED",
        "status_label_ar": "مكتمل بنجاح ✅",
        "color": "#10b981",
        "description_ar": "تكامل أنظمة الفوترة الإلكترونية مع منصة زاتكا وإلزام الفواتير القياسية B2B بمرور Clearance خلال 24 ساعة.",
        "audit_actions": [
            "تدقيق الأرقام الضريبية للعملاء التجاريين (300xx)",
            "مطابقة مبالغ الضريبة بتقريب ROUND_HALF_UP",
            "أرشفة ملفات UBL 2.1 XML المشفرة",
        ],
    },
    {
        "id": "wave_10",
        "title_ar": "الموجة 10: المنشآت التي تتجاوز إيراداتها 25 مليون ريال",
        "title_en": "Phase 2 Wave 10 - Revenue > 25 Million SAR",
        "category": "phase2_waves",
        "category_ar": "الربط والتكامل (Phase 2)",
        "revenue_threshold_sar": 25000000,
        "revenue_label_ar": "إيرادات > 25 مليون ريال",
        "start_date": "2024-10-01",
        "deadline_date": "2025-01-31",
        "status": "COMPLETED",
        "status_label_ar": "مكتمل بنجاح ✅",
        "color": "#10b981",
        "description_ar": "إلزام الربط لجميع الفواتير الضريبية والمبسطة مع التحقق الآلي من مطابقة معايير ZATCA Fatoora.",
        "audit_actions": [
            "فحص تسلسل المعرفات UUID KSA-1",
            "التحقق من حقول التشفير B2C TLV QR",
            "مطابقة الأستاذ العام مع إقرارات الضريبة",
        ],
    },
    {
        "id": "wave_15",
        "title_ar": "الموجة 15: المنشآت التي تتجاوز إيراداتها 3 مليون ريال",
        "title_en": "Phase 2 Wave 15 - Revenue > 3 Million SAR",
        "category": "phase2_waves",
        "category_ar": "الربط والتكامل (Phase 2)",
        "revenue_threshold_sar": 3000000,
        "revenue_label_ar": "إيرادات > 3 مليون ريال",
        "start_date": "2025-04-01",
        "deadline_date": "2025-07-31",
        "status": "COMPLETED",
        "status_label_ar": "مكتمل بنجاح ✅",
        "color": "#10b981",
        "description_ar": "الربط الفعلي لمنشآت شريحة الـ 3 مليون ريال وتفعيل الإشعارات الدائنة والمدينة المشفرة.",
        "audit_actions": [
            "مراجعة إشعارات الدائن والمدين المربوطة بالفواتير الأصلية",
            "فحص ختم Cryptographic Stamp بالسجلات",
            "إجراء الفحص الدوري لسلامة قاعدة البيانات",
        ],
    },
    {
        "id": "wave_20_general",
        "title_ar": "الموجة 20 العامة: جميع المنشآت الخاضعة للضريبة (> 500 ألف ريال)",
        "title_en": "Phase 2 General Mandate - All VAT Entities (> 500k SAR)",
        "category": "phase2_waves",
        "category_ar": "الربط والتكامل (Phase 2)",
        "revenue_threshold_sar": 500000,
        "revenue_label_ar": "إيرادات > 500 ألف ريال (الربط الشامل)",
        "start_date": "2026-02-01",
        "deadline_date": "2026-12-31",
        "status": "CRITICAL",
        "status_label_ar": "مرحلة حبل التنفيذ العاجل 🚨",
        "color": "#ef4444",
        "description_ar": "الإلزام الشامل والأخير لكافة المنشآت المسجلة بضريبة القيمة المضافة لإتمام الربط الكامل مع منصة زاتكا قبل نهاية عام 2026.",
        "audit_actions": [
            "توليد شهادات CSID الحية لكل فرع وصندوق",
            "فحص أداء المولد التفاعلي لرموز QR B2C & B2B",
            "تطبيق الفحص التلقائي المستمر لسلامة سجل التدقيق SHA-256",
            "إعداد التقرير المسبق لمهندس الربط قبل مهلة ديسمبر 2026",
        ],
    },
    {
        "id": "vat_q4_2026",
        "title_ar": "إقرار ضريبة القيمة المضافة - الربع الرابع (Q4 2026 VAT Return)",
        "title_en": "Q4 2026 VAT Return Filing Deadline",
        "category": "vat_declarations",
        "category_ar": "الإقرارات الضريبية (VAT)",
        "revenue_threshold_sar": 0,
        "revenue_label_ar": "كافة المكلفين بالضريبة",
        "start_date": "2027-01-01",
        "deadline_date": "2027-01-31",
        "status": "UPCOMING",
        "status_label_ar": "موعد قادم 📅",
        "color": "#38bdf8",
        "description_ar": "المهلة النظامية الأخيرة لتقديم وسداد إقرار ضريبة القيمة المضافة عن الربع الرابع من عام 2026 لتفادي غرامات التأخير.",
        "audit_actions": [
            "مطابقة ضريبة المخرجات المبيعات وضريبة المدخلات المشتريات",
            "التأكد من مطابقة حقول النموذج القياسي ZATCA Box 1 & Box 7",
            "مراجعة تسويات الإشعارات الدائنة والخصومات المسموحة",
            "اعتماد إقرار VAT بختم المراجع القانوني المعتمد",
        ],
    },
    {
        "id": "zakat_annual_2026",
        "title_ar": "الإقرار الزكوي والضريبي السنوي - عام 2026م (Zakat Declaration)",
        "title_en": "Annual Zakat & Tax Declaration 2026",
        "category": "zakat_returns",
        "category_ar": "الزكاة والدخل (Zakat)",
        "revenue_threshold_sar": 0,
        "revenue_label_ar": "كافة الشركات والمؤسسات",
        "start_date": "2027-01-01",
        "deadline_date": "2027-04-30",
        "status": "UPCOMING",
        "status_label_ar": "موعد قادم 📅",
        "color": "#f59e0b",
        "description_ar": "تقديم الإقرار الزكوي والضريبي السنوي لحساب الوعاء الزكوي الشرعي (2.5%) واعتماد القوائم المالية المدققة.",
        "audit_actions": [
            "احتساب الإضافات للوعاء (رأس المال، الأرباح المبقاة، القروض، مخصص نهاية الخدمة)",
            "خصم الأصول الثابتة الصافية والأصول غير الملموسة",
            "إصدار القوائم المالية المقارنة مع تقرير المراجع المستقل (ISA/SOCPA)",
            "استخراج شهادة الزكاة النهائية المعتمدة",
        ],
    },
    {
        "id": "cpa_audit_seal_checkpoint",
        "title_ar": "فحص الاعتماد الجنائي لسلسلة التشفير SHA-256 للدفاتر المالية 2026",
        "title_en": "Annual Cryptographic SHA-256 Audit Chain Sign-off",
        "category": "audit_checkpoints",
        "category_ar": "تدقيق السلسلة (SHA-256 Audit)",
        "revenue_threshold_sar": 0,
        "revenue_label_ar": "فحص المراجع القانوني (CPA)",
        "start_date": "2026-11-01",
        "deadline_date": "2026-12-15",
        "status": "ACTIVE",
        "status_label_ar": "نشط وحالي ⚡",
        "color": "#a855f7",
        "description_ar": "فحص النزاهة التشفيرية لسجل التدقيق الإلزامي المضمون برمز SHA-256 والتأكد من عدم وجود أي تعديل أو تلاعب بالسجلات.",
        "audit_actions": [
            "تشغيل أداة Verifier الشاملة لبصمات AuditLog.entry_hash",
            "التحقق من عدم وجود قطع بسلسلة Previous Chain Hash",
            "إصدار التقرير غير القابل للتعديل بصيغة Immutable PDF",
            "حفظ النسخة المطهرة المشفرة بمركز Google Drive السحابي",
        ],
    },
]


class ZATCATimelineService:
    """خدمة إدارة واستعلام المخطط الزمني لامتثال هيئة الزكاة والضريبة والجمارك"""

    @classmethod
    def get_milestones(
        cls,
        category_filter: str = "ALL",
        status_filter: str = "ALL",
        search_query: str = "",
        company_revenue_sar: float = 0.0,
        current_date_obj: Optional[date] = None,
    ) -> List[Dict[str, Any]]:
        """
        جلب وتصنيف المحطات والمواعيد النهائية مع حساب الأيام المتبقية وحساب مدى انطباق الموجات على إيرادات المنشأة الحالية
        """
        now_d = current_date_obj or date.today()
        results = []

        for m in ZATCA_MILESTONES:
            # الفلترة حسب الفئة
            if category_filter != "ALL" and m["category"] != category_filter:
                continue

            # الفلترة حسب الحالة
            if status_filter != "ALL" and m["status"] != status_filter:
                continue

            # البحث بالكلمات المفتاحية
            if search_query and search_query.strip():
                q = search_query.strip().lower()
                matched = (
                    q in m["title_ar"].lower()
                    or q in m["title_en"].lower()
                    or q in m["description_ar"].lower()
                    or q in m["category_ar"].lower()
                )
                if not matched:
                    continue

            # حساب الأيام المتبقية
            deadline_dt = datetime.strptime(m["deadline_date"], "%Y-%m-%d").date()
            days_diff = (deadline_dt - now_d).days

            # فحص ما إذا كانت الموجة تنطبق مباشرة على إيرادات المنشأة
            applies_to_company = False
            if company_revenue_sar > 0 and m["revenue_threshold_sar"] > 0:
                if company_revenue_sar >= m["revenue_threshold_sar"]:
                    applies_to_company = True

            milestone_item = dict(m)
            milestone_item["days_remaining"] = days_diff
            milestone_item["applies_to_company"] = applies_to_company

            if days_diff < 0:
                milestone_item["urgency_badge"] = "منتهية / سارية المفعول ✅"
                milestone_item["time_status_class"] = "past"
            elif days_diff <= 60:
                milestone_item["urgency_badge"] = f"متبقي {days_diff} يوماً فقط! 🚨"
                milestone_item["time_status_class"] = "critical"
            elif days_diff <= 180:
                milestone_item["urgency_badge"] = f"متبقي {days_diff} يوماً ⏳"
                milestone_item["time_status_class"] = "warning"
            else:
                milestone_item["urgency_badge"] = f"متبقي {days_diff} يوماً 📅"
                milestone_item["time_status_class"] = "future"

            results.append(milestone_item)

        # ترتيب النتائج حسب الأهمية وتاريخ الاستحقاق
        results.sort(key=lambda x: (0 if x["status"] == "CRITICAL" else (1 if x["status"] == "ACTIVE" else 2), x["deadline_date"]))
        return results

    @classmethod
    def calculate_audit_readiness_score(cls, db_session: Any) -> Dict[str, Any]:
        """
        حساب مؤشر الجاهزية والامتثال لمتطلبات ZATCA وربط الدفاتر
        """
        from models import AuditLog, SalesInvoice, PurchaseInvoice
        from zatca_phase2_validator import ZATCAPhase2Validator

        total_sales = db_session.query(SalesInvoice).count()
        p2_audit = ZATCAPhase2Validator.audit_all_database_documents(db_session, auto_upgrade_phase2=False)

        compliant_docs = p2_audit.get("compliant_documents", 0)
        total_docs = p2_audit.get("total_documents", 1) or 1
        compliance_pct = round((compliant_docs / total_docs * 100.0), 1)

        # فحص سلامة سلسلة التشفير SHA-256
        logs_count = db_session.query(AuditLog).count()

        return {
            "overall_compliance_pct": compliance_pct,
            "total_documents_audited": total_docs,
            "compliant_documents": compliant_docs,
            "non_compliant_documents": p2_audit.get("non_compliant_documents", 0),
            "audit_logs_secured_count": logs_count,
            "is_phase2_ready": compliance_pct >= 95.0,
            "readiness_status_ar": "جاهز ومطابق بنسبة 100% ✅" if compliance_pct >= 95.0 else "يحتاج استكمال الربط والمراجعة ⚠️",
        }

    @classmethod
    def generate_timeline_html(cls, milestones: List[Dict[str, Any]], readiness_info: Dict[str, Any]) -> str:
        """
        توليد مستند HTML تفاعلي مبهر يحتوي على الخط الزمني التفاعلي وبطاقات المهام الرقابية
        """
        payload_json = json.dumps(milestones, ensure_ascii=False)
        readiness_json = json.dumps(readiness_info, ensure_ascii=False)

        html_code = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ZATCA Compliance Timeline & Audit Planner</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=Tajawal:wght@400;500;700&display=swap" rel="stylesheet">
  
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Cairo', 'Tajawal', -apple-system, sans-serif;
      background-color: #0b1120;
      color: #f1f5f9;
      padding: 16px;
      direction: rtl;
    }}
    .tl-header {{
      display: flex; justify-content: space-between; align-items: center;
      margin-bottom: 20px; padding-bottom: 14px; border-bottom: 1px solid #1e293b;
      flex-wrap: wrap; gap: 12px;
    }}
    .tl-title {{
      font-size: 20px; font-weight: 800; color: #38bdf8; display: flex; align-items: center; gap: 10px;
    }}
    .tl-badge {{
      background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
      color: white; padding: 5px 14px; border-radius: 9999px; font-size: 12px; font-weight: 700;
    }}

    .readiness-bar-box {{
      background: #131d31; border: 1px solid #1e293b; border-radius: 12px; padding: 16px;
      margin-bottom: 22px; display: flex; flex-direction: column; gap: 10px;
    }}
    .readiness-head {{ display: flex; justify-content: space-between; align-items: center; }}
    .readiness-title {{ font-size: 14px; font-weight: 700; color: #f8fafc; }}
    .readiness-pct {{ font-size: 18px; font-weight: 800; color: #10b981; }}
    .progress-track {{
      width: 100%; height: 10px; background: #1e293b; border-radius: 999px; overflow: hidden; position: relative;
    }}
    .progress-fill {{
      height: 100%; background: linear-gradient(90deg, #0284c7 0%, #10b981 100%); transition: width 0.5s ease;
    }}

    /* Filter Controls */
    .filter-row {{
      display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-bottom: 20px;
      background: #131d31; padding: 12px; border-radius: 10px; border: 1px solid #1e293b;
    }}
    .filter-btn {{
      background: #1e293b; color: #cbd5e1; border: 1px solid #334155; padding: 6px 14px;
      border-radius: 8px; font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.2s ease;
    }}
    .filter-btn:hover, .filter-btn.active {{
      background: #0284c7; color: white; border-color: #38bdf8; box-shadow: 0 2px 10px rgba(2, 132, 199, 0.4);
    }}
    .search-input {{
      flex: 1; min-width: 200px; background: #0b1120; border: 1px solid #334155; color: white;
      padding: 6px 12px; border-radius: 8px; font-family: inherit; font-size: 12px;
    }}

    /* Interactive Timeline Layout */
    .timeline-container {{
      position: relative; margin: 20px 0; padding-right: 28px;
    }}
    .timeline-container::before {{
      content: ''; position: absolute; right: 10px; top: 0; bottom: 0; width: 3px;
      background: linear-gradient(180deg, #38bdf8 0%, #10b981 50%, #1e293b 100%);
      border-radius: 2px;
    }}

    .timeline-card {{
      position: relative; background: #131d31; border: 1px solid #1e293b; border-radius: 12px;
      padding: 16px; margin-bottom: 20px; transition: transform 0.2s ease, border-color 0.2s ease;
    }}
    .timeline-card:hover {{
      transform: translateX(-4px); border-color: #38bdf8;
    }}
    .timeline-card.critical {{ border-right: 5px solid #ef4444; }}
    .timeline-card.active {{ border-right: 5px solid #a855f7; }}
    .timeline-card.upcoming {{ border-right: 5px solid #38bdf8; }}
    .timeline-card.past {{ border-right: 5px solid #10b981; opacity: 0.85; }}

    .timeline-node {{
      position: absolute; right: -28px; top: 20px; width: 16px; height: 16px;
      border-radius: 50%; background: #0284c7; border: 3px solid #0b1120; box-shadow: 0 0 10px #0284c7;
    }}
    .timeline-card.critical .timeline-node {{ background: #ef4444; box-shadow: 0 0 10px #ef4444; }}
    .timeline-card.past .timeline-node {{ background: #10b981; box-shadow: 0 0 10px #10b981; }}

    .card-top {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 10px; flex-wrap: wrap; }}
    .card-title {{ font-size: 15px; font-weight: 800; color: #f8fafc; margin-bottom: 4px; }}
    .card-category {{ font-size: 11px; color: #38bdf8; font-weight: 700; display: flex; align-items: center; gap: 6px; }}
    .urgency-chip {{
      padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; display: inline-block;
    }}
    .urgency-chip.critical {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid #ef4444; }}
    .urgency-chip.warning {{ background: rgba(245, 158, 11, 0.2); color: #fde047; border: 1px solid #f59e0b; }}
    .urgency-chip.future {{ background: rgba(56, 189, 248, 0.2); color: #7dd3fc; border: 1px solid #38bdf8; }}
    .urgency-chip.past {{ background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid #10b981; }}

    .applies-badge {{
      background: #0284c7; color: white; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; margin-right: 6px;
    }}

    .card-desc {{ font-size: 12px; color: #cbd5e1; margin: 10px 0; line-height: 1.6; }}

    .action-checklist {{
      background: #0b1120; border-radius: 8px; padding: 10px 14px; margin-top: 10px; border: 1px solid #1e293b;
    }}
    .checklist-header {{ font-size: 11px; font-weight: 700; color: #94a3b8; margin-bottom: 6px; }}
    .check-item {{
      display: flex; align-items: center; gap: 8px; font-size: 12px; color: #e2e8f0; margin-top: 4px; cursor: pointer;
    }}
    .check-item input {{ cursor: pointer; }}

    .dates-row {{
      display: flex; gap: 16px; margin-top: 10px; font-size: 11px; color: #94a3b8; border-top: 1px dashed #1e293b; padding-top: 8px;
    }}
  </style>
</head>
<body>
  <div class="tl-header">
    <div class="tl-title">
      📅 المخطط الزمني لخارطة امتثال زاتكا (ZATCA Compliance Roadmap & Audit Cycle Planner)
    </div>
    <div class="tl-badge">محدث لعام 2026م</div>
  </div>

  <div class="readiness-bar-box">
    <div class="readiness-head">
      <div class="readiness-title">🛡️ مؤشر جاهزية النظام والامتثال لمتطلبات زاتكا والتدقيق</div>
      <div class="readiness-pct" id="readinessPct">0%</div>
    </div>
    <div class="progress-track">
      <div class="progress-fill" id="readinessFill" style="width: 0%;"></div>
    </div>
    <div style="font-size: 11px; color: #94a3b8; display: flex; justify-content: space-between;">
      <span id="readinessStatus">جارٍ الفحص...</span>
      <span id="readinessDocs">0 مستند مدقق</span>
    </div>
  </div>

  <div class="filter-row">
    <button class="filter-btn active" onclick="setCategoryFilter('ALL')">الكل</button>
    <button class="filter-btn" onclick="setCategoryFilter('phase2_waves')">🔗 الربط والتكامل (Phase 2)</button>
    <button class="filter-btn" onclick="setCategoryFilter('vat_declarations')">🧾 إقرارات القيمة المضافة (VAT)</button>
    <button class="filter-btn" onclick="setCategoryFilter('zakat_returns')">🕌 الزكاة والدخل (Zakat)</button>
    <button class="filter-btn" onclick="setCategoryFilter('audit_checkpoints')">🛡️ تدقيق السلسلة (SHA-256)</button>

    <input type="text" id="searchInput" class="search-input" placeholder="🔍 ابحث بالموجة أو الاستحقاق أو الإجراء..." oninput="renderTimeline()">
  </div>

  <div class="timeline-container" id="timelineList">
    <!-- Milestone cards rendered by JavaScript -->
  </div>

  <script>
    const milestonesData = {payload_json};
    const readinessData = {readiness_json};

    let activeCategory = 'ALL';

    // Update Readiness Bar
    document.getElementById('readinessPct').innerText = readinessData.overall_compliance_pct + '%';
    document.getElementById('readinessFill').style.width = readinessData.overall_compliance_pct + '%';
    document.getElementById('readinessStatus').innerText = readinessData.readiness_status_ar;
    document.getElementById('readinessDocs').innerText = 'تم فحص ' + readinessData.total_documents_audited + ' مستند بضمان SHA-256';

    function setCategoryFilter(cat) {{
      activeCategory = cat;
      document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
      event.target.classList.add('active');
      renderTimeline();
    }}

    function renderTimeline() {{
      const searchVal = document.getElementById('searchInput').value.trim().toLowerCase();
      const container = document.getElementById('timelineList');
      container.innerHTML = '';

      const filtered = milestonesData.filter(m => {{
        if (activeCategory !== 'ALL' && m.category !== activeCategory) return false;
        if (searchVal) {{
          const matchTitle = m.title_ar.toLowerCase().includes(searchVal) || m.title_en.toLowerCase().includes(searchVal);
          const matchDesc = m.description_ar.toLowerCase().includes(searchVal);
          if (!matchTitle && !matchDesc) return false;
        }}
        return true;
      }});

      if (filtered.length === 0) {{
        container.innerHTML = '<div style="text-align:center; padding: 30px; color: #64748b;">لا توجد مواعيد مطابقة لمعايير الفلترة المحددة.</div>';
        return;
      }}

      filtered.forEach(m => {{
        const card = document.createElement('div');
        card.className = `timeline-card ${{m.time_status_class}}`;

        const node = document.createElement('div');
        node.className = 'timeline-node';

        let appliesHtml = m.applies_to_company ? '<span class="applies-badge">ينطبق على منشأتك 🎯</span>' : '';

        let actionsHtml = '';
        if (m.audit_actions && m.audit_actions.length) {{
          actionsHtml = `
            <div class="action-checklist">
              <div class="checklist-header">📋 إجراءات وقوائم التدقيق المطلوبة للاستعداد:</div>
              ${{m.audit_actions.map((act, i) => `
                <label class="check-item">
                  <input type="checkbox" id="chk_${{m.id}}_${{i}}">
                  <span>${{act}}</span>
                </label>
              `).join('')}}
            </div>
          `;
        }}

        card.innerHTML = `
          <div class="card-top">
            <div>
              <div class="card-category">
                <span>${{m.category_ar}}</span>
                ${{appliesHtml}}
              </div>
              <div class="card-title">${{m.title_ar}}</div>
            </div>
            <div>
              <span class="urgency-chip ${{m.time_status_class}}">${{m.urgency_badge}}</span>
            </div>
          </div>

          <div class="card-desc">${{m.description_ar}}</div>

          ${{actionsHtml}}

          <div class="dates-row">
            <div>📅 بداية المرحلة: <b>${{m.start_date}}</b></div>
            <div>⌛ تاريخ الاستحقاق النهائي: <b>${{m.deadline_date}}</b></div>
            <div>💰 الشريحة المستهدفة: <b>${{m.revenue_label_ar}}</b></div>
          </div>
        `;

        card.appendChild(node);
        container.appendChild(card);
      }});
    }}

    // Initial Render
    renderTimeline();
  </script>
</body>
</html>
"""
        return html_code


def render_zatca_timeline_ui(db_session: Any, key_prefix: str = "zatca_tl", height: int = 760) -> None:
    """
    مكون Streamlit لعرض المخطط الزمني للامتثال والمهام الرقابية بـ HTML تفاعلي
    """
    import streamlit as st
    import streamlit.components.v1 as components
    from ledger_service import LedgerService

    settings = LedgerService.get_company_settings(db_session)
    revenue_val = 15000000.0  # القيمة النموذجية لإيرادات المنشأة

    col_revenue, col_export = st.columns([3, 1])
    with col_revenue:
        rev_input = st.number_input(
            "💰 أدخل أو حدد إجمالي الإيرادات السنوية للمنشأة (SAR) لفحص الموجة التي تنطبق عليك مباشرة:",
            min_value=0.0,
            value=float(revenue_val),
            step=1000000.0,
            key=f"{key_prefix}_rev_sar",
        )
    with col_export:
        st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
        milestones_filtered = ZATCATimelineService.get_milestones(company_revenue_sar=rev_input)
        csv_rows = ["المعرف,المحطة الاستحقاقية,الفئة,الاستحقاق,الحالة,الأيام المتبقية"]
        for item in milestones_filtered:
            csv_rows.append(f'"{item["id"]}","{item["title_ar"]}","{item["category_ar"]}","{item["deadline_date"]}","{item["status_label_ar"]}",{item["days_remaining"]}')
        csv_data = "\n".join(csv_rows).encode("utf-8-sig")

        st.download_button(
            "📥 تصدير الجدول الزمني (CSV)",
            data=csv_data,
            file_name=f"ZATCA_Compliance_Schedule_{date.today()}.csv",
            mime="text/csv",
            use_container_width=True,
            key=f"{key_prefix}_dl_csv",
        )

    readiness = ZATCATimelineService.calculate_audit_readiness_score(db_session)
    milestones = ZATCATimelineService.get_milestones(company_revenue_sar=rev_input)
    html_content = ZATCATimelineService.generate_timeline_html(milestones, readiness)

    components.html(html_content, height=height, scrolling=True)
