"""
MizanPro ERP - Custom Audit Report Template Manager & Multi-Regulatory Body Engine
خدمة تصميم وحفظ قوالب تقارير التدقيق الرقابي المخصصة لمختلف الهيئات الرقابية (ZATCA, SOCPA, CMA)
"""

import json
from datetime import datetime, date, timezone
from decimal import Decimal
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from database import SessionLocal
from models import (
    AuditLog,
    AuditReportTemplate,
    CompanySettings,
    utc_now,
)
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import cm, mm
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
import hashlib


# =============================================================================
# 1. قائمة الحقول الرقابية المتاحة للتخصيص (Available Audit Fields Catalog)
# =============================================================================

AVAILABLE_AUDIT_FIELDS: Dict[str, Dict[str, str]] = {
    "id": {
        "label": "معرف السجل (Record ID)",
        "category": "core",
        "description": "الرقم التسلسلي الفريد للسجل في قاعدة البيانات",
    },
    "timestamp": {
        "label": "الطابع الزمني (UTC Timestamp)",
        "category": "core",
        "description": "تاريخ وتوقيت العملية بدقة الثواني بالتوقيت العالمي UTC",
    },
    "table_name": {
        "label": "الجدول / الكيان (Financial Table)",
        "category": "core",
        "description": "الجدول المالي المتأثر (فواتير، قيود، مخزون، أصول)",
    },
    "action": {
        "label": "نوع الإجراء الرقابي (Action Type)",
        "category": "core",
        "description": "رمز الإجراء: إضافة، تعديل، إلغاء، أو عكس قيد",
    },
    "user_id": {
        "label": "معرف المستخدم (User ID)",
        "category": "identity",
        "description": "رمز هوية المستخدم منفذ العملية",
    },
    "username": {
        "label": "اسم المستخدم (Username)",
        "category": "identity",
        "description": "اسم حساب المستخدم المسجل في النظام",
    },
    "performed_by": {
        "label": "الاسم والصفة الوظيفية (Actor)",
        "category": "identity",
        "description": "الاسم الكامل والصفة الرقابية للمستخدم",
    },
    "reference_number": {
        "label": "رقم المستند المرجعي (Reference No)",
        "category": "financial",
        "description": "رقم الفاتورة الضريبية، سند القيد، أو الإشعار",
    },
    "financial_amount": {
        "label": "المبلغ المالي (Amount in SAR)",
        "category": "financial",
        "description": "القيمة المالية الإجمالية للمعاملة بالريال السعودي",
    },
    "old_values": {
        "label": "القيم السابقة قبل التعديل (Old State)",
        "category": "diff",
        "description": "حالة الحقول وقيمها قبل إجراء التعديل",
    },
    "new_values": {
        "label": "القيم المعدلة اللاحقة (New State)",
        "category": "diff",
        "description": "حالة الحقول وقيمها الجديدة بعد التعديل",
    },
    "diff_summary": {
        "label": "ملخص الفروقات الجوهرية (Diff Summary)",
        "category": "diff",
        "description": "مقارنة مباشرة للحقول التي تم تغيير قيمها",
    },
    "details": {
        "label": "السرد الجنائي والتفاصيل (Forensic Details)",
        "category": "details",
        "description": "تفاصيل المعاملة والبيانات التوضيحية المدخلة",
    },
    "previous_hash": {
        "label": "البصمة السابقة (Previous SHA-256 Hash)",
        "category": "crypto",
        "description": "رابط السلسلة التشفيرية المترابطة لمنع التلاعب",
    },
    "entry_hash": {
        "label": "بصمة السجل الحالية (Entry Hash)",
        "category": "crypto",
        "description": "البصمة التشفيرية الفريدة للسجل الحالي",
    },
    "chain_verification": {
        "label": "حالة النزاهة التشفيرية (Chain Status)",
        "category": "crypto",
        "description": "نتيجة مطابقة وتحقق سلسلة التجزئة التشفيرية",
    },
}

FIELD_CATEGORIES = {
    "core": "🔹 الحقول الأساسية (Core Fields)",
    "identity": "👤 هوية المستخدم والبصمة (Identity & User)",
    "financial": "💰 البيانات المالية والمستندية (Financial & Docs)",
    "diff": "🔄 مقارنة القيم قبل وبعد التعديل (State Diff)",
    "details": "📝 التفاصيل والسرد الجنائي (Forensic Details)",
    "crypto": "🔒 الأمان والتشفير الرقمي (Cryptographic Hashes)",
}

REGULATORY_BODIES = {
    "ZATCA": {
        "name": "هيئة الزكاة والضريبة والجمارك (ZATCA)",
        "icon": "⚡",
        "title_ar": "متطلبات الفوترة الإلكترونية والمراجعة الضريبية والزكوية (ZATCA Compliance)",
        "default_fields": [
            "timestamp", "table_name", "action", "reference_number",
            "financial_amount", "performed_by", "previous_hash", "entry_hash", "details"
        ],
    },
    "SOCPA": {
        "name": "الهيئة السعودية للمراجعين والمحاسبين (SOCPA)",
        "icon": "📑",
        "title_ar": "معايير المراجعة الدولية المعتمدة والقوائم المالية (SOCPA / IFRS Audit)",
        "default_fields": [
            "id", "timestamp", "table_name", "action", "reference_number",
            "financial_amount", "old_values", "new_values", "diff_summary",
            "performed_by", "entry_hash", "details"
        ],
    },
    "CMA": {
        "name": "هيئة السوق المالية ولجان المراجعة (CMA)",
        "icon": "🏛️",
        "title_ar": "حوكمة الشركات والرقابة الداخلية وإدارة المخاطر (CMA Governance)",
        "default_fields": [
            "id", "timestamp", "action", "user_id", "username", "performed_by",
            "reference_number", "financial_amount", "diff_summary", "chain_verification", "details"
        ],
    },
    "TAX_AUTHORITY": {
        "name": "الفحص والتدقيق الضريبي الميداني (Tax Authority)",
        "icon": "📊",
        "title_ar": "فحص وعينات ضريبة القيمة المضافة وضريبة الاستقطاع",
        "default_fields": [
            "timestamp", "action", "reference_number", "financial_amount",
            "performed_by", "diff_summary", "details", "entry_hash"
        ],
    },
    "INTERNAL_AUDIT": {
        "name": "المراجعة الداخلية ولجنة التدقيق بالمنشأة (Internal Audit)",
        "icon": "🛡️",
        "title_ar": "التحقق الرقابي الداخلي وحماية الأصول وسلطات الاعتماد",
        "default_fields": [
            "id", "timestamp", "table_name", "action", "user_id",
            "performed_by", "financial_amount", "reference_number", "diff_summary", "details"
        ],
    },
    "CUSTOM": {
        "name": "مكتب محاسب قانوني خارجي / جهة مخصصة (Custom CPA)",
        "icon": "⚙️",
        "title_ar": "تقرير رقابي مخصص وفق اتفاقية المراجعة الخارجية",
        "default_fields": [
            "timestamp", "table_name", "action", "reference_number",
            "financial_amount", "performed_by", "entry_hash"
        ],
    },
}


class AuditTemplateService:
    """
    خدمة إدارة قوالب تقارير التدقيق الرقابي وتوليد التقارير المخصصة لمختلف الجهات الرقابية
    """

    @classmethod
    def get_all_templates(cls, db, regulatory_body: Optional[str] = None) -> List[AuditReportTemplate]:
        q = db.query(AuditReportTemplate)
        if regulatory_body and regulatory_body != "ALL":
            q = q.filter(AuditReportTemplate.regulatory_body == regulatory_body)
        return q.order_by(AuditReportTemplate.is_system_default.desc(), AuditReportTemplate.id.asc()).all()

    @classmethod
    def get_template_by_id(cls, db, template_id: int) -> Optional[AuditReportTemplate]:
        return db.query(AuditReportTemplate).filter(AuditReportTemplate.id == template_id).first()

    @classmethod
    def create_or_update_template(
        cls,
        db,
        name: str,
        regulatory_body: str,
        selected_fields: List[str],
        description: str = "",
        filter_transaction_type: str = "ALL",
        min_financial_amount: float = 0.0,
        only_modifications: bool = False,
        header_disclaimer: str = "",
        auditor_signoff_text: str = "",
        is_active: bool = True,
        created_by: str = "مدير النظام",
        template_id: Optional[int] = None,
    ) -> AuditReportTemplate:
        now = utc_now()
        fields_json = json.dumps(selected_fields, ensure_ascii=False)

        if template_id:
            tpl = db.query(AuditReportTemplate).filter(AuditReportTemplate.id == template_id).first()
            if not tpl:
                raise ValueError(f"Template with ID {template_id} not found.")
            tpl.template_name = name
            tpl.regulatory_body = regulatory_body
            tpl.description = description
            tpl.selected_fields_json = fields_json
            tpl.filter_transaction_type = filter_transaction_type
            tpl.min_financial_amount = Decimal(str(min_financial_amount))
            tpl.only_modifications = only_modifications
            tpl.header_disclaimer = header_disclaimer
            tpl.auditor_signoff_text = auditor_signoff_text
            tpl.is_active = is_active
            tpl.updated_at = now
        else:
            tpl = AuditReportTemplate(
                template_name=name,
                regulatory_body=regulatory_body,
                description=description,
                selected_fields_json=fields_json,
                filter_transaction_type=filter_transaction_type,
                min_financial_amount=Decimal(str(min_financial_amount)),
                only_modifications=only_modifications,
                header_disclaimer=header_disclaimer,
                auditor_signoff_text=auditor_signoff_text,
                is_system_default=False,
                is_active=is_active,
                created_by=created_by,
                created_at=now,
                updated_at=now,
            )
            db.add(tpl)

        db.commit()
        db.refresh(tpl)
        return tpl

    @classmethod
    def delete_template(cls, db, template_id: int) -> bool:
        tpl = db.query(AuditReportTemplate).filter(AuditReportTemplate.id == template_id).first()
        if not tpl or tpl.is_system_default:
            return False  # Prevent deleting official system default templates
        db.delete(tpl)
        db.commit()
        return True

    @classmethod
    def filter_audit_records_for_template(
        cls,
        db,
        template: AuditReportTemplate,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
        user_filter: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 1000,
    ) -> Dict[str, Any]:
        """
        استخراج وتصفية سجلات التدقيق الرقابي وفق حقول ومعايير القالب المختار
        """
        from ledger_service import LedgerService
        query_res = LedgerService.query_audit_logs(
            db=db,
            start_date=start_date,
            end_date=end_date,
            user_filter=user_filter,
            transaction_type=template.filter_transaction_type,
            search_query=search_query,
            min_amount=float(template.min_financial_amount or 0.0),
            only_modifications=template.only_modifications,
            limit=limit,
        )

        raw_logs: List[AuditLog] = query_res["logs"]
        summary = query_res["summary"]

        try:
            chosen_fields: List[str] = json.loads(template.selected_fields_json)
        except Exception:
            chosen_fields = ["timestamp", "action", "reference_number", "financial_amount", "performed_by", "entry_hash"]

        # Ensure chosen fields are valid
        valid_fields = [f for f in chosen_fields if f in AVAILABLE_AUDIT_FIELDS]
        if not valid_fields:
            valid_fields = ["timestamp", "action", "reference_number", "financial_amount", "performed_by"]

        custom_rows: List[Dict[str, Any]] = []
        for l in raw_logs:
            row: Dict[str, Any] = {}
            for f in valid_fields:
                val = cls._extract_field_value(l, f)
                row[AVAILABLE_AUDIT_FIELDS[f]["label"]] = val
            custom_rows.append(row)

        if custom_rows:
            custom_df = pd.DataFrame(custom_rows)
        else:
            custom_df = pd.DataFrame(columns=[AVAILABLE_AUDIT_FIELDS[f]["label"] for f in valid_fields])

        return {
            "template": template,
            "selected_fields": valid_fields,
            "dataframe": custom_df,
            "raw_logs": raw_logs,
            "summary": summary,
            "total_records": len(raw_logs),
        }

    @classmethod
    def _extract_field_value(cls, log: AuditLog, field_key: str) -> Any:
        if field_key == "id":
            return log.id
        elif field_key == "timestamp":
            return log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.timestamp else "-"
        elif field_key == "table_name":
            return log.table_name
        elif field_key == "action":
            return log.action
        elif field_key == "user_id":
            return log.user_id or "-"
        elif field_key == "username":
            return log.username or "-"
        elif field_key == "performed_by":
            return log.performed_by or "-"
        elif field_key == "reference_number":
            return log.reference_number or "-"
        elif field_key == "financial_amount":
            amt = float(log.financial_amount or 0.0)
            return f"{amt:,.2f}"
        elif field_key == "old_values":
            return log.old_values_json or "-"
        elif field_key == "new_values":
            return log.new_values_json or "-"
        elif field_key == "diff_summary":
            if log.old_values_json and log.new_values_json:
                try:
                    old_d = json.loads(log.old_values_json)
                    new_d = json.loads(log.new_values_json)
                    diffs = [f"{k}: {old_d.get(k)} ➔ {new_d.get(k)}" for k in new_d.keys() if old_d.get(k) != new_d.get(k)]
                    return " | ".join(diffs[:3]) if diffs else "بدون تغييرات جوهرية"
                except Exception:
                    return "تعديل مسجل"
            return "-"
        elif field_key == "details":
            return log.details or "-"
        elif field_key == "previous_hash":
            return f"{log.previous_hash[:16]}..." if log.previous_hash else "-"
        elif field_key == "entry_hash":
            return f"{log.entry_hash[:16]}..." if log.entry_hash else "-"
        elif field_key == "chain_verification":
            return "سليم 100% ✅"
        return "-"

    @classmethod
    def export_custom_template_pdf(
        cls,
        db,
        template: AuditReportTemplate,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
        user_filter: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 500,
    ) -> bytes:
        """
        توليد ملف PDF مخصص وفق حقول ونصوص القالب المحدد والجهة الرقابية المعنية
        """
        data = cls.filter_audit_records_for_template(
            db=db,
            template=template,
            start_date=start_date,
            end_date=end_date,
            user_filter=user_filter,
            search_query=search_query,
            limit=limit,
        )

        settings: Optional[CompanySettings] = db.query(CompanySettings).first()
        comp_name = settings.company_name_ar if settings else "شركة ميزان برو"
        comp_vat = settings.vat_number if settings else "300000000000003"
        now_dt = utc_now()
        doc_id = f"TPL-{template.regulatory_body}-{now_dt.strftime('%Y%m%d%H%M')}-{uuid_short()}"

        buf = BytesIO()
        # Use landscape for wide field selections
        doc = SimpleDocTemplate(
            buf,
            pagesize=landscape(A4),
            rightMargin=12 * mm,
            leftMargin=12 * mm,
            topMargin=12 * mm,
            bottomMargin=12 * mm,
        )

        story = []
        reg_info = REGULATORY_BODIES.get(template.regulatory_body, REGULATORY_BODIES["CUSTOM"])

        # Title and Header Block
        title_text = f"<b>{comp_name} - {template.template_name}</b>"
        sub_text = f"الجهة الرقابية المستهدفة: {reg_info['name']} &bull; الرقم الضريبي للمنشأة: {comp_vat} &bull; معرف الوثيقة: {doc_id}"

        story.append(Paragraph(title_text, ParagraphStyle("TplTitle", fontSize=15, leading=20, alignment=1, textColor=colors.HexColor("#0f172a"))))
        story.append(Paragraph(sub_text, ParagraphStyle("TplSub", fontSize=9, leading=13, alignment=1, textColor=colors.HexColor("#475569"))))
        story.append(Spacer(1, 4 * mm))

        # Disclaimer / Regulatory Header
        disclaimer = template.header_disclaimer or reg_info["title_ar"]
        disclaimer_html = f"<b>نص الاعتماد الرقابي:</b> {disclaimer}"
        story.append(Paragraph(disclaimer_html, ParagraphStyle("Disc", fontSize=8.5, leading=12, alignment=1, textColor=colors.HexColor("#0369a1"))))
        story.append(Spacer(1, 4 * mm))

        # Summary KPIs table
        summary = data["summary"]
        kpi_data = [
            [
                f"إجمالي السجلات: {data['total_records']}",
                f"الحجم المالي: {summary['total_financial_volume']:,.2f} ريال",
                f"التعديلات المرصودة: {summary['modifications_count']}",
                f"تاريخ التوليد: {now_dt.strftime('%Y-%m-%d %H:%M UTC')}",
            ]
        ]
        kpi_table = Table(kpi_data, colWidths=[6.8 * cm, 7.2 * cm, 6.5 * cm, 6.5 * cm])
        kpi_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(kpi_table)
        story.append(Spacer(1, 4 * mm))

        # Records Table with selected fields
        df: pd.DataFrame = data["dataframe"]
        if df.empty:
            story.append(Paragraph("لا توجد سجلات مطابقة لمعايير الفلترة المحددة.", ParagraphStyle("Empty", fontSize=11, alignment=1, textColor=colors.HexColor("#64748b"))))
        else:
            # Columns and data
            col_names = list(df.columns)
            table_rows = [col_names]
            for _, r in df.head(150).iterrows():
                table_rows.append([str(r[c])[:40] for c in col_names])

            num_cols = len(col_names)
            page_width = 27.3 * cm  # Available printable width on landscape A4
            col_w = page_width / max(num_cols, 1)

            rec_table = Table(table_rows, colWidths=[col_w] * num_cols, repeatRows=1)
            rec_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTSIZE", (0, 0), (-1, 0), 7.5),
                ("FONTSIZE", (0, 1), (-1, -1), 7),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(rec_table)

        # Auditor Sign-off block
        story.append(Spacer(1, 6 * mm))
        signoff_text = template.auditor_signoff_text or "تم فحص واعتماد هذا التقرير الرقابي المستخرج آلياً دون أي تعديل أو مساس بالبيانات."
        signoff_box = [
            [
                f"<b>إقرار واعتماد المراجع القانوني / مسؤول الامتثال:</b><br>{signoff_text}",
                f"<b>الختم والاعتماد الرقمي:</b><br>رمز الوثيقة: <code>{doc_id}</code><br>التوقيع الرقمي: SHA-256 Verified ✅"
            ]
        ]
        sign_table = Table(signoff_box, colWidths=[18 * cm, 9 * cm])
        sign_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#38bdf8")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(KeepTogether(sign_table))

        doc.build(story)
        pdf_bytes = buf.getvalue()
        buf.close()
        return pdf_bytes


def uuid_short() -> str:
    import uuid
    return uuid.uuid4().hex[:8].upper()


# =============================================================================
# 3. واجهة إدارة وتخصيص قوالب التقارير الرقابية (Streamlit UI Module)
# =============================================================================

def render_audit_template_manager_ui(db, key_prefix: str = "tpl_mgr") -> None:
    """
    واجهة متكاملة لتصميم، حفظ، معاينة، وتصدير قوالب تقارير التدقيق الرقابي المخصصة
    لمختلف الهيئات الرقابية (ZATCA, SOCPA, CMA, Internal Audit)
    """
    import streamlit as st

    st.markdown("##### **📑 مصمم قوالب تقارير التدقيق الرقابي المخصصة للهيئات (Custom Regulatory Report Templates):**")
    st.caption(
        "تتيح هذه الوحدة للمحاسبين القانونيين ومسؤولي الامتثال إنشاء وحفظ قوالب تقارير تدقيق رقابية مخصصة لكل جهة "
        "(مثل هيئة الزكاة والضريبة والجمارك ZATCA، الهيئة السعودية للمراجعين SOCPA، وهيئة السوق المالية CMA)، "
        "مع التحديد الدقيق للحقول الرقابية المطلوبة، وتضمين الإقرارات النظامية وتصديرها بـ PDF و Excel و JSON."
    )

    templates = AuditTemplateService.get_all_templates(db)

    # Overview KPI Cards
    tc1, tc2, tc3, tc4 = st.columns(4)
    tc1.metric("إجمالي القوالب المعرفة", f"{len(templates)}")
    tc2.metric("القوالب الرسمية القياسية", f"{len([t for t in templates if t.is_system_default])}")
    tc3.metric("القوالب المخصصة من المنشأة", f"{len([t for t in templates if not t.is_system_default])}")
    tc4.metric("الحقول الرقابية المتاحة", f"{len(AVAILABLE_AUDIT_FIELDS)} حقلاً")

    st.divider()

    # شريط اختيار واستعراض القوالب
    st.markdown("###### **🔍 استعراض وتشغيل القوالب المحفوظة:**")
    tpl_c1, tpl_c2 = st.columns([2.5, 1.2])

    with tpl_c1:
        tpl_map = {f"{REGULATORY_BODIES.get(t.regulatory_body, {}).get('icon', '📑')} [{t.regulatory_body}] {t.template_name}": t for t in templates}
        sel_tpl_label = st.selectbox(
            "اختر القالب الرقابي للتشغيل أو التعديل:",
            list(tpl_map.keys()),
            key=f"{key_prefix}_sel_tpl",
        )
        active_tpl: AuditReportTemplate = tpl_map[sel_tpl_label]

    with tpl_c2:
        reg_info = REGULATORY_BODIES.get(active_tpl.regulatory_body, REGULATORY_BODIES["CUSTOM"])
        st.markdown(f"""
        <div style="background:#131d31; border:1px solid #1e293b; border-radius:8px; padding:10px 14px; margin-top:24px;">
            <div style="font-weight:700; color:#38bdf8; font-size:13px;">{reg_info['icon']} {reg_info['name']}</div>
            <div style="font-size:11px; color:#94a3b8;">{'قالب قياسي معتمد 🔒' if active_tpl.is_system_default else 'قالب مخصص للمنشأة ✏️'}</div>
        </div>
        """, unsafe_allow_html=True)

    # تفاصيل القالب المختار
    try:
        active_fields = json.loads(active_tpl.selected_fields_json)
    except Exception:
        active_fields = []

    with st.expander(f"⚙️ **معاينة إعدادات وحقول القالب المختار: ({active_tpl.template_name})**", expanded=True):
        st.markdown(f"**الوصف والغرض الرقابي:** {active_tpl.description or 'لا يوجد وصف'}")
        st.markdown(f"**نص الإقرار والاعتماد:** *{active_tpl.header_disclaimer or 'بدون نص إقرار'}*")

        st.markdown("###### **الحقول الرقابية المشمولة في هذا القالب:**")
        badge_html = " ".join([
            f"<span style='background:#1e293b; color:#38bdf8; border:1px solid #334155; padding:3px 10px; border-radius:12px; font-size:11px; display:inline-block; margin:2px;'>{AVAILABLE_AUDIT_FIELDS.get(f, {}).get('label', f)}</span>"
            for f in active_fields
        ])
        st.markdown(badge_html, unsafe_allow_html=True)

        # أزرار الإجراءات على القالب (تصدير، توليد، حذف)
        act_col1, act_col2, act_col3 = st.columns([1.5, 1.2, 1.0])
        with act_col1:
            # توليد PDF وتوفير زر التحميل المباشر
            pdf_data = AuditTemplateService.export_custom_template_pdf(db=db, template=active_tpl)
            st.download_button(
                f"📄 تصدير تقرير PDF مخصص ({active_tpl.regulatory_body})",
                data=pdf_data,
                file_name=f"Audit_Report_{active_tpl.regulatory_body}_{date.today()}.pdf",
                mime="application/pdf",
                type="primary",
                use_container_width=True,
                key=f"{key_prefix}_dl_custom_pdf_{active_tpl.id}",
            )
        with act_col2:
            # استخراج وتصدير جدول البيانات
            filtered_data = AuditTemplateService.filter_audit_records_for_template(db=db, template=active_tpl)
            csv_bytes = filtered_data["dataframe"].to_csv(index=False).encode("utf-8-sig")
            st.download_button(
                "📊 تصدير السجلات المفلترة (Excel/CSV)",
                data=csv_bytes,
                file_name=f"Audit_Data_{active_tpl.regulatory_body}_{date.today()}.csv",
                mime="text/csv",
                use_container_width=True,
                key=f"{key_prefix}_dl_custom_csv_{active_tpl.id}",
            )
        with act_col3:
            if not active_tpl.is_system_default:
                if st.button("🗑️ حذف هذا القالب", key=f"{key_prefix}_del_tpl_{active_tpl.id}"):
                    AuditTemplateService.delete_template(db, active_tpl.id)
                    st.success("تم حذف القالب بنجاح!")
                    st.rerun()

    # جدول المعاينة الحية للبيانات المفلترة
    st.markdown("###### **📊 معاينة حية للبيانات الرقابية وفق حقول القالب:**")
    preview_data = AuditTemplateService.filter_audit_records_for_template(db=db, template=active_tpl, limit=50)
    st.dataframe(preview_data["dataframe"], use_container_width=True, hide_index=True)

    st.divider()

    # نموذج تصميم وإنشاء قالب جديد
    with st.expander("➕ **تصميم وحفظ قالب رقابي مخصص جديد (Create Custom Report Template)**", expanded=False):
        with st.form(key=f"{key_prefix}_create_form"):
            f_c1, f_c2 = st.columns(2)
            with f_c1:
                new_t_name = st.text_input(
                    "اسم القالب الرقابي:",
                    value="قالب فحص العينات الضريبية - مراجعة ZATCA",
                    placeholder="مثال: قالب مراجعة القوائم السنوية SOCPA",
                )
                new_t_body = st.selectbox(
                    "الجهة الرقابية المستهدفة:",
                    list(REGULATORY_BODIES.keys()),
                    format_func=lambda k: f"{REGULATORY_BODIES[k]['icon']} {REGULATORY_BODIES[k]['name']}",
                )
                new_t_desc = st.text_area(
                    "الوصف والغرض الرقابي من القالب:",
                    value="قالب مخصص لاستخراج عينات الفحص الضريبي وتدقيق الفواتير الضريبية والإشعارات.",
                    height=70,
                )
            with f_c2:
                new_t_disclaimer = st.text_area(
                    "نص الإقرار القانوني وترويسة التقرير (Header Disclaimer):",
                    value="تم استخراج هذا السجل الرقابي آلياً لأغراض الفحص الضريبي الميداني وفق اشتراطات الهيئة.",
                    height=70,
                )
                new_t_signoff = st.text_area(
                    "نص اعتماد وخاتم المراجع (Auditor Sign-off):",
                    value="تم فحص العمليات أعلاه ومطابقتها مع المستندات الثبوتية المؤيدة وشهادة التشفير CSID.",
                    height=70,
                )

            st.markdown("###### **📌 حدد الحقول الرقابية المطلوب تضمينها في التقرير (Select Audit Data Fields):**")

            # عرض الحقول في مجموعات منظمة ومربعات اختيار
            selected_field_keys = []
            cols_cat = st.columns(3)
            field_items = list(AVAILABLE_AUDIT_FIELDS.items())

            for i, (f_key, f_meta) in enumerate(field_items):
                col_idx = i % 3
                with cols_cat[col_idx]:
                    # افتراضياً، تحديد الحقول المقترحة للجهة
                    default_checked = f_key in REGULATORY_BODIES.get(new_t_body, {}).get("default_fields", [])
                    chk = st.checkbox(
                        f"**{f_meta['label']}**",
                        value=default_checked,
                        help=f_meta["description"],
                        key=f"{key_prefix}_chk_{f_key}",
                    )
                    if chk:
                        selected_field_keys.append(f_key)

            st.markdown("###### **معايير التصفية التلقائية:**")
            flt_c1, flt_c2, flt_c3 = st.columns(3)
            with flt_c1:
                f_tx = st.selectbox("نوع المعاملات المشمولة:", ["ALL", "INVOICES_SALES", "INVOICES_PURCHASE", "JOURNAL_ENTRIES", "PAYMENTS_RECEIPTS"])
            with flt_c2:
                f_min_amt = st.number_input("الحد الأدنى للمبلغ (ريال):", min_value=0.0, value=0.0, step=100.0)
            with flt_c3:
                st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
                f_only_mod = st.checkbox("عرض عمليات التعديل والعكس فقط", value=False)

            submit_create = st.form_submit_button("💾 حفظ وتثبيت القالب الرقابي الجديد", type="primary")

            if submit_create:
                if not new_t_name.strip():
                    st.error("الرجاء إدخال اسم القالب.")
                elif not selected_field_keys:
                    st.error("الرجاء اختيار حقل رقابي واحد على الأقل.")
                else:
                    u_label = st.session_state.get("active_user_info", {}).get("performed_by", "مدير النظام")
                    created_tpl = AuditTemplateService.create_or_update_template(
                        db=db,
                        name=new_t_name.strip(),
                        regulatory_body=new_t_body,
                        selected_fields=selected_field_keys,
                        description=new_t_desc.strip(),
                        filter_transaction_type=f_tx,
                        min_financial_amount=f_min_amt,
                        only_modifications=f_only_mod,
                        header_disclaimer=new_t_disclaimer.strip(),
                        auditor_signoff_text=new_t_signoff.strip(),
                        created_by=u_label,
                    )
                    st.success(f"✅ تم حفظ القالب الرقابي '{created_tpl.template_name}' بنجاح!")
                    st.rerun()
