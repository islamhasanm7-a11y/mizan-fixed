"""
MizanPro ERP & CPA Suite - Auditor Digital Annotations & Private Notes Service
خدمة التعليقات الرقمية والملاحظات الخاصة للمراجعين القانونيين على سجلات التدقيق
"""

import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy import text as sa_text


ANNOTATION_CATEGORIES: Dict[str, Dict[str, str]] = {
    "INSPECTION_NOTE": {
        "title_ar": "📝 ملاحظة فحص ومعاينة (Inspection Note)",
        "icon": "📝",
        "badge_color": "#2563EB",
        "bg_color": "#EFF6FF",
    },
    "RISK_FLAG": {
        "title_ar": "⚠️ إشارة مخاطر وملاحظة رقابية (Risk Flag)",
        "icon": "⚠️",
        "badge_color": "#DC2626",
        "bg_color": "#FEF2F2",
    },
    "COMPLIANCE_REVIEW": {
        "title_ar": "⚖️ مراجعة امتثال معايير (ZATCA / SOCPA Review)",
        "icon": "⚖️",
        "badge_color": "#059669",
        "bg_color": "#ECFDF5",
    },
    "JUSTIFICATION": {
        "title_ar": "💡 مبرر محاسبي وملاحظة إيضاحية (Justification)",
        "icon": "💡",
        "badge_color": "#D97706",
        "bg_color": "#FFFBEB",
    },
    "SAMPLE_SELECTION": {
        "title_ar": "🔍 عينة مراجعة واختبار كفاءة (Sample Selection)",
        "icon": "🔍",
        "badge_color": "#7C3AED",
        "bg_color": "#F5F3FF",
    },
}


class AuditAnnotationService:
    """خدمة أرشفة وتوثيق التعليقات والملاحظات الرقمية الخاصة للمراجعين"""

    @classmethod
    def add_annotation(
        cls,
        db_session: Any,
        audit_log_id: int,
        auditor_id: str,
        auditor_name: str,
        annotation_text: str,
        category: str = "INSPECTION_NOTE",
        is_private: bool = True,
    ) -> Dict[str, Any]:
        """
        إضافة تعليق رقمي أو ملاحظة خاصة غير قابلة للتعديل أو الحذف ومحمية بختم تشفيري SHA-256
        """
        from models import AuditLog, AuditLogAnnotation, compute_annotation_hash, utc_now

        if not annotation_text or not annotation_text.strip():
            return {
                "success": False,
                "message_ar": "خطأ: نص الملاحظة أو التعليق لا يمكن أن يكون فارغاً.",
            }

        target_log = db_session.query(AuditLog).filter(AuditLog.id == audit_log_id).first()
        if not target_log:
            return {
                "success": False,
                "message_ar": f"خطأ: لم يتم العثور على سجل تدقيق برقم المعاملة (#{audit_log_id}).",
            }

        clean_cat = category if category in ANNOTATION_CATEGORIES else "INSPECTION_NOTE"
        now_ts = utc_now()
        clean_auditor_id = str(auditor_id or "USR-001").strip()
        clean_auditor_name = str(auditor_name or "المراجع القانوني").strip()
        clean_text = annotation_text.strip()

        calc_hash = compute_annotation_hash(
            audit_log_id=audit_log_id,
            auditor_id=clean_auditor_id,
            auditor_name=clean_auditor_name,
            category=clean_cat,
            created_at=now_ts,
            annotation_text=clean_text,
        )

        annotation_obj = AuditLogAnnotation(
            audit_log_id=audit_log_id,
            auditor_id=clean_auditor_id,
            auditor_name=clean_auditor_name,
            annotation_text=clean_text,
            category=clean_cat,
            is_private=is_private,
            created_at=now_ts,
            annotation_hash=calc_hash,
        )

        db_session.add(annotation_obj)
        db_session.commit()

        return {
            "success": True,
            "annotation_id": annotation_obj.id,
            "annotation_hash": calc_hash,
            "audit_log_id": audit_log_id,
            "created_at": now_ts.strftime("%Y-%m-%d %H:%M:%S"),
            "message_ar": f"تم توثيق ملاحظة المراجع الرقمية بنجاح تحت الختم التشفيري ({calc_hash[:16]}...).",
        }

    @classmethod
    def get_annotations_for_log(cls, db_session: Any, audit_log_id: int) -> List[Dict[str, Any]]:
        """
        جلب كافة الملاحظات والتعليقات الرقمية المرتبطة بسجل تدقيق معين مع التحقق من الختم التشفيري
        """
        from models import AuditLogAnnotation, compute_annotation_hash

        records = (
            db_session.query(AuditLogAnnotation)
            .filter(AuditLogAnnotation.audit_log_id == audit_log_id)
            .order_by(AuditLogAnnotation.created_at.desc())
            .all()
        )

        results = []
        for r in records:
            expected_hash = compute_annotation_hash(
                audit_log_id=r.audit_log_id,
                auditor_id=r.auditor_id,
                auditor_name=r.auditor_name,
                category=r.category,
                created_at=r.created_at,
                annotation_text=r.annotation_text,
            )
            is_intact = (expected_hash == r.annotation_hash)
            cat_meta = ANNOTATION_CATEGORIES.get(r.category, ANNOTATION_CATEGORIES["INSPECTION_NOTE"])

            results.append({
                "id": r.id,
                "audit_log_id": r.audit_log_id,
                "auditor_id": r.auditor_id,
                "auditor_name": r.auditor_name,
                "annotation_text": r.annotation_text,
                "category": r.category,
                "category_title_ar": cat_meta["title_ar"],
                "category_icon": cat_meta["icon"],
                "category_color": cat_meta["badge_color"],
                "is_private": r.is_private,
                "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "annotation_hash": r.annotation_hash,
                "is_intact": is_intact,
            })

        return results

    @classmethod
    def get_all_annotations_summary(
        cls,
        db_session: Any,
        auditor_id: Optional[str] = None,
        category: Optional[str] = None,
        search_query: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        جلب ملخص وإحصائيات سجل ملاحظات وتعليقات المراجعين عبر كامل النظام
        """
        from models import AuditLog, AuditLogAnnotation, compute_annotation_hash

        query = db_session.query(AuditLogAnnotation, AuditLog).join(
            AuditLog, AuditLogAnnotation.audit_log_id == AuditLog.id
        )

        if auditor_id and auditor_id != "ALL":
            query = query.filter(AuditLogAnnotation.auditor_id == auditor_id)
        if category and category != "ALL":
            query = query.filter(AuditLogAnnotation.category == category)
        if search_query and search_query.strip():
            sq = f"%{search_query.strip()}%"
            query = query.filter(
                (AuditLogAnnotation.annotation_text.like(sq))
                | (AuditLogAnnotation.auditor_name.like(sq))
                | (AuditLog.reference_number.like(sq))
                | (AuditLog.action.like(sq))
            )

        rows = query.order_by(AuditLogAnnotation.created_at.desc()).all()

        items = []
        intact_count = 0
        private_count = 0

        for ann, log in rows:
            expected_hash = compute_annotation_hash(
                audit_log_id=ann.audit_log_id,
                auditor_id=ann.auditor_id,
                auditor_name=ann.auditor_name,
                category=ann.category,
                created_at=ann.created_at,
                annotation_text=ann.annotation_text,
            )
            is_intact = (expected_hash == ann.annotation_hash)
            if is_intact:
                intact_count += 1
            if ann.is_private:
                private_count += 1

            cat_meta = ANNOTATION_CATEGORIES.get(ann.category, ANNOTATION_CATEGORIES["INSPECTION_NOTE"])

            items.append({
                "id": ann.id,
                "audit_log_id": ann.audit_log_id,
                "log_action": log.action,
                "log_table": log.table_name,
                "log_reference": log.reference_number or "—",
                "log_amount": float(log.financial_amount or 0.0),
                "log_timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "auditor_id": ann.auditor_id,
                "auditor_name": ann.auditor_name,
                "annotation_text": ann.annotation_text,
                "category": ann.category,
                "category_title_ar": cat_meta["title_ar"],
                "category_icon": cat_meta["icon"],
                "category_color": cat_meta["badge_color"],
                "is_private": ann.is_private,
                "created_at": ann.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "annotation_hash": ann.annotation_hash,
                "is_intact": is_intact,
            })

        total_count = len(items)
        unique_auditors = len({i["auditor_id"] for i in items})

        return {
            "total_count": total_count,
            "intact_count": intact_count,
            "tampered_count": total_count - intact_count,
            "private_count": private_count,
            "unique_auditors": unique_auditors,
            "is_all_intact": (total_count == intact_count),
            "items": items,
        }

    @classmethod
    def verify_annotation_integrity(cls, db_session: Any, annotation_id: int) -> Dict[str, Any]:
        """
        التحقق التشفيري الفردي لسجل ملاحظة مراجع قانوني
        """
        from models import AuditLogAnnotation, compute_annotation_hash

        ann = db_session.query(AuditLogAnnotation).filter(AuditLogAnnotation.id == annotation_id).first()
        if not ann:
            return {"is_valid": False, "message_ar": "سجل الملاحظة غير موجود."}

        exp_hash = compute_annotation_hash(
            audit_log_id=ann.audit_log_id,
            auditor_id=ann.auditor_id,
            auditor_name=ann.auditor_name,
            category=ann.category,
            created_at=ann.created_at,
            annotation_text=ann.annotation_text,
        )

        is_valid = (exp_hash == ann.annotation_hash)
        return {
            "is_valid": is_valid,
            "stored_hash": ann.annotation_hash,
            "computed_hash": exp_hash,
            "annotation_id": annotation_id,
            "audit_log_id": ann.audit_log_id,
        }


def render_audit_annotations_ui(
    db_session: Any,
    selected_audit_log_id: Optional[int] = None,
    current_user_id: str = "USR-001",
    current_username: str = "المراجع القانوني (Auditor)",
    key_prefix: str = "audit_annot",
) -> None:
    """
    واجهة Streamlit لإدارة وعرض وإضافة الملاحظات والتعليقات الرقمية الخاصة للمراجعين
    """
    import streamlit as st
    from models import AuditLog

    st.markdown("##### **🔒 التعليقات والملاحظات الرقمية الخاصة للمراجعين (Auditor Private Annotations):**")
    st.caption(
        "تتيح للمراجعين القانونيين والرقابيين إضافة ملاحظات خاصة وتوثيقات رقمية غير قابلة للتعديل أو الحذف، "
        "مع ختم تشفيري مستقل (SHA-256) يضمن سلامة الملاحظات وعدم التلاعب بها لأغراض الفحص الدوري والامتثال."
    )

    t_add, t_browse = st.tabs([
        "✏️ إضافة ملاحظة مراجع على سجل تدقيق",
        "📂 استعراض كافة ملاحظات المراجعين بالكامل",
    ])

    with t_add:
        # البحث بـ ID أو اختيار سجل التدقيق
        col_sel1, col_sel2 = st.columns([1.5, 2.5])
        with col_sel1:
            input_log_id = st.number_input(
                "أدخل رقم سجل التدقيق (Audit Log ID):",
                min_value=1,
                value=int(selected_audit_log_id or 1),
                step=1,
                key=f"{key_prefix}_input_log_id",
            )
        with col_sel2:
            st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
            log_obj = db_session.query(AuditLog).filter(AuditLog.id == input_log_id).first()
            if log_obj:
                st.success(
                    f"✅ **السجل المحدد:** #{log_obj.id} | الإجراء: `{log_obj.action}` | "
                    f"المستند: `{log_obj.reference_number or '—'}` | المبلغ: `{float(log_obj.financial_amount or 0.0):,.2f} ريال`"
                )
            else:
                st.warning(f"⚠️ لم يتم العثور على سجل تدقيق بالرقم (#{input_log_id}).")

        if log_obj:
            existing_notes = AuditAnnotationService.get_annotations_for_log(db_session, log_obj.id)
            if existing_notes:
                st.markdown(f"###### **📋 الملاحظات المسجلة سابقاً على هذا السجل ({len(existing_notes)} ملاحظة):**")
                for n in existing_notes:
                    integrity_badge = "✅ البصمة سليمة" if n["is_intact"] else "❌ تنبيه تلاعب"
                    st.markdown(f"""
                    <div style="background:{ANNOTATION_CATEGORIES.get(n['category'], {})['bg_color']}; border-right:4px solid {n['category_color']}; padding:10px 14px; border-radius:8px; margin-bottom:10px;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <strong>{n['category_icon']} {n['category_title_ar']}</strong>
                            <span style="font-size:11px; color:#64748B;">🔒 {n['auditor_name']} ({n['auditor_id']}) &bull; {n['created_at']} &bull; {integrity_badge}</span>
                        </div>
                        <p style="margin:6px 0 2px 0; color:#1E293B; font-size:13px;">{n['annotation_text']}</p>
                        <div style="font-size:10px; color:#94A3B8; font-family:monospace;">SHA-256 Seal: {n['annotation_hash']}</div>
                    </div>
                    """, unsafe_allow_html=True)

            st.divider()
            st.markdown("###### **✍️ إضافة ملاحظة أو تعليق رقمي جديد:**")
            with st.form(key=f"{key_prefix}_add_form"):
                ca1, ca2 = st.columns([2, 1])
                with ca1:
                    cat_key = st.selectbox(
                        "تصنيف الملاحظة الرقابية:",
                        list(ANNOTATION_CATEGORIES.keys()),
                        format_func=lambda k: ANNOTATION_CATEGORIES[k]["title_ar"],
                        key=f"{key_prefix}_cat_select",
                    )
                with ca2:
                    is_priv = st.checkbox(
                        "🔒 ملاحظة سرية خاصة بالمراجعين",
                        value=True,
                        key=f"{key_prefix}_chk_private",
                    )

                new_note_text = st.text_area(
                    "نص الملاحظة الرقمية / تعليق المراجع القانوني:",
                    placeholder="اكتب ملاحظة التوثيق، مبرر المعاملة، نتيجة اختبار العينة، أو توجيه المراجعة...",
                    height=100,
                    key=f"{key_prefix}_text_area",
                )

                submit_ann = st.form_submit_button("💾 توثيق وحفظ الملاحظة التشفيرية", type="primary")

                if submit_ann:
                    if not new_note_text.strip():
                        st.error("يرجى كتابة نص الملاحظة قبل الحفظ.")
                    else:
                        u_act_id = st.session_state.get("active_user_info", {}).get("user_id", current_user_id)
                        u_act_name = st.session_state.get("active_user", current_username)
                        res = AuditAnnotationService.add_annotation(
                            db_session,
                            audit_log_id=log_obj.id,
                            auditor_id=u_act_id,
                            auditor_name=u_act_name,
                            annotation_text=new_note_text,
                            category=cat_key,
                            is_private=is_priv,
                        )
                        if res.get("success"):
                            st.success(f"🎉 {res['message_ar']}")
                            st.rerun()
                        else:
                            st.error(f"❌ {res.get('message_ar')}")

    with t_browse:
        st.markdown("###### **🔎 تصفية واستعراض كافة الملاحظات الرقابية المسجلة:**")
        fc1, fc2, fc3 = st.columns([1.5, 1.5, 2.0])
        with fc1:
            f_cat = st.selectbox(
                "فلترة حسب الفئة:",
                ["ALL"] + list(ANNOTATION_CATEGORIES.keys()),
                format_func=lambda k: "جميع الفئات" if k == "ALL" else ANNOTATION_CATEGORIES[k]["title_ar"],
                key=f"{key_prefix}_filter_cat",
            )
        with fc2:
            f_search = st.text_input(
                "بحث بالنص أو المراجع:",
                placeholder="ابحث بالكلمات المفتاحية...",
                key=f"{key_prefix}_filter_search",
            )
        with fc3:
            st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
            st.caption("⚡ يتم التحقق التلقائي من سلامة البصمات التشفيرية لجميع الملاحظات.")

        master_annot = AuditAnnotationService.get_all_annotations_summary(
            db_session,
            category=f_cat,
            search_query=f_search,
        )

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("إجمالي الملاحظات المسجلة", f"{master_annot['total_count']}")
        m2.metric("سلامة البصمات التشفيرية", "100% سليمة ✅" if master_annot["is_all_intact"] else f"{master_annot['tampered_count']} تلاعب ❌")
        m3.metric("الملاحظات السرية الخاصة", f"{master_annot['private_count']}")
        m4.metric("عدد المراجعين المشاركين", f"{master_annot['unique_auditors']}")

        st.divider()

        if master_annot["items"]:
            for item in master_annot["items"]:
                sec_badge = "🔒 خاصة للمراجعين" if item["is_private"] else "🌐 ملاحظة عامة"
                verif_badge = "✅ ختم التشفير مطابق" if item["is_intact"] else "❌ تنبيه: خرق تشفيري"

                st.markdown(f"""
                <div style="background:{item['category_color']}0F; border:1px solid {item['category_color']}40; border-right:5px solid {item['category_color']}; border-radius:10px; padding:12px 16px; margin-bottom:12px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap;">
                        <span style="font-weight:700; color:{item['category_color']}; font-size:14px;">
                            {item['category_icon']} {item['category_title_ar']} &bull; سجل تدقيق #{item['audit_log_id']} ({item['log_action']})
                        </span>
                        <span style="font-size:11px; background:#1E293B; color:#F8FAFC; padding:2px 8px; border-radius:12px;">
                            {sec_badge} &bull; {verif_badge}
                        </span>
                    </div>
                    <div style="font-size:12px; color:#475569; margin:4px 0;">
                        <strong>المراجع:</strong> {item['auditor_name']} ({item['auditor_id']}) &bull; <strong>التاريخ:</strong> {item['created_at']} &bull; <strong>المستند المالي:</strong> {item['log_reference']} ({item['log_amount']:,.2f} ريال)
                    </div>
                    <div style="font-size:13px; color:#0F172A; background:white; padding:8px 12px; border-radius:6px; margin-top:6px; border:1px solid #E2E8F0;">
                        {item['annotation_text']}
                    </div>
                    <div style="font-size:10px; color:#94A3B8; font-family:monospace; margin-top:4px;">
                        SHA-256 Annotation Hash: {item['annotation_hash']}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("لا توجد ملاحظات مراجعين قانونيين مطابقة لمعايير البحث حالياً.")
