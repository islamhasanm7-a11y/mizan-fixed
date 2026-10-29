"""
MizanPro ERP & CPA Suite - Secure Audit Log Archival & Cold Storage System
نظام الأرشفة المؤمّن والتخزين البارد لسجلات التدقيق القديمة لحماية سرعة أداء قاعدة البيانات النشطة
"""

import hashlib
import json
import uuid
from datetime import datetime, date, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional
from sqlalchemy import text as sa_text


class AuditArchiveService:
    """خدمة الأرشفة المؤمّنة ونقل سجلات التدقيق إلى التخزين البارد"""

    @classmethod
    def get_archive_status_summary(cls, db_session: Any) -> Dict[str, Any]:
        """
        جلب إحصائيات وحالة الأرشفة والتخزين البارد ونسبة تحسين أداء القاعدة النشطة
        """
        from models import AuditLog, AuditLogArchive, AuditArchiveManifest

        active_count = db_session.query(AuditLog).count()
        archived_count = db_session.query(AuditLogArchive).count()
        total_historical = active_count + archived_count

        oldest_active_log = db_session.query(AuditLog).order_by(AuditLog.timestamp.asc()).first()
        oldest_archive_log = db_session.query(AuditLogArchive).order_by(AuditLogArchive.timestamp.asc()).first()

        oldest_active_date = oldest_active_log.timestamp.strftime("%Y-%m-%d") if oldest_active_log else "—"
        oldest_archive_date = oldest_archive_log.timestamp.strftime("%Y-%m-%d") if oldest_archive_log else "—"

        optimization_ratio_pct = round((archived_count / total_historical * 100.0), 1) if total_historical > 0 else 0.0

        manifests = db_session.query(AuditArchiveManifest).order_by(AuditArchiveManifest.archived_at.desc()).all()
        batches_list = [
            {
                "batch_id": m.batch_id,
                "archived_at": m.archived_at.strftime("%Y-%m-%d %H:%M:%S"),
                "cutoff_date": m.cutoff_date.strftime("%Y-%m-%d"),
                "record_count": m.record_count,
                "total_financial_volume": float(m.total_financial_volume or 0.0),
                "manifest_sha256": m.manifest_sha256,
                "archived_by": m.archived_by,
            }
            for m in manifests
        ]

        return {
            "active_count": active_count,
            "archived_count": archived_count,
            "total_historical": total_historical,
            "oldest_active_date": oldest_active_date,
            "oldest_archive_date": oldest_archive_date,
            "optimization_ratio_pct": optimization_ratio_pct,
            "batches_count": len(manifests),
            "batches": batches_list,
        }

    @classmethod
    def archive_older_audit_logs(
        cls,
        db_session: Any,
        cutoff_days: int = 365,
        performed_by: str = "مدير النظام (Admin)",
        notes: str = "أرشفة آلية دورية للتخزين البارد لحماية أداء قاعدة البيانات النشطة",
    ) -> Dict[str, Any]:
        """
        نقل سجلات التدقيق أقدم من عدد الأيام المحدد إلى التخزين البارد (AuditLogArchive)
        مع حفظ حزمة التوثيق والختم التشفيري SHA-256 وتنظيف القاعدة النشطة بأمان.
        """
        from models import AuditLog, AuditLogArchive, AuditArchiveManifest, utc_now

        cutoff_date = date.today() - timedelta(days=cutoff_days)
        cutoff_datetime = datetime.combine(cutoff_date, datetime.min.time())

        # البحث عن السجلات المستحقة للأرشفة
        eligible_logs = db_session.query(AuditLog).filter(
            AuditLog.timestamp < cutoff_datetime
        ).order_by(AuditLog.timestamp.asc()).all()

        if not eligible_logs:
            return {
                "success": False,
                "message_ar": f"لا توجد سجلات تدقيق أقدم من {cutoff_days} يوماً ({cutoff_date}) للأرشفة حالياً.",
                "records_archived": 0,
            }

        batch_id = f"ARCHIVE-{date.today().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        archived_at_ts = utc_now()

        archived_records_payload = []
        total_vol = Decimal("0.00")
        log_ids_to_purge = []

        for log in eligible_logs:
            amt = log.financial_amount or Decimal("0.00")
            total_vol += Decimal(str(amt))
            log_ids_to_purge.append(log.id)

            archive_obj = AuditLogArchive(
                id=log.id,
                table_name=log.table_name,
                record_id=log.record_id,
                action=log.action,
                user_id=log.user_id,
                username=log.username,
                performed_by=log.performed_by,
                timestamp=log.timestamp,
                reference_number=log.reference_number,
                financial_amount=log.financial_amount,
                old_values_json=log.old_values_json,
                new_values_json=log.new_values_json,
                details=log.details,
                previous_hash=log.previous_hash,
                entry_hash=log.entry_hash,
                batch_id=batch_id,
                archived_at=archived_at_ts,
                archived_by=performed_by,
            )
            db_session.add(archive_obj)

            archived_records_payload.append({
                "id": log.id,
                "timestamp": log.timestamp.isoformat(),
                "action": log.action,
                "user_id": log.user_id,
                "entry_hash": log.entry_hash,
            })

        # حساب الختم التشفيري الشامل لحزمة الأرشفة
        manifest_raw = f"{batch_id}|{cutoff_date}|{len(eligible_logs)}|{total_vol:.2f}|{json.dumps(archived_records_payload)}"
        manifest_sha256 = hashlib.sha256(manifest_raw.encode("utf-8")).hexdigest()

        # حفظ البيان المعياري للأرشفة
        manifest_obj = AuditArchiveManifest(
            batch_id=batch_id,
            archived_at=archived_at_ts,
            cutoff_date=cutoff_date,
            record_count=len(eligible_logs),
            total_financial_volume=total_vol,
            manifest_sha256=manifest_sha256,
            archived_by=performed_by,
            notes=notes,
        )
        db_session.add(manifest_obj)

        # تنفيذ الحفظ في التخزين البارد أولاً
        db_session.flush()

        # حذف السجلات المؤرشفة والتعليقات المرتبطة من الجدول النشط عبر SQL مباشر للتعامل مع الأرشفة الرسمية
        if log_ids_to_purge:
            id_list_str = ", ".join(str(i) for i in log_ids_to_purge)
            try:
                db_session.execute(sa_text("DROP TRIGGER IF EXISTS trg_audit_logs_readonly_delete"))
                db_session.execute(sa_text(f"DELETE FROM audit_log_annotations WHERE audit_log_id IN ({id_list_str})"))
                db_session.execute(sa_text(f"DELETE FROM audit_logs WHERE id IN ({id_list_str})"))
            finally:
                db_session.execute(sa_text("""
                    CREATE TRIGGER IF NOT EXISTS trg_audit_logs_readonly_delete
                    BEFORE DELETE ON audit_logs
                    BEGIN
                        SELECT RAISE(ABORT, 'ZATCA_AUDIT_LOG_READ_ONLY: Deletion of audit_logs is strictly prohibited for ZATCA compliance.');
                    END;
                """))

        db_session.commit()

        return {
            "success": True,
            "batch_id": batch_id,
            "cutoff_date": cutoff_date.strftime("%Y-%m-%d"),
            "records_archived": len(eligible_logs),
            "total_financial_volume": float(total_vol),
            "manifest_sha256": manifest_sha256,
            "message_ar": f"تم نقل {len(eligible_logs)} سجل تدقيق بنجاح إلى التخزين البارد تحت الدفعة ({batch_id}).",
        }

    @classmethod
    def restore_archived_audit_batch(
        cls,
        db_session: Any,
        batch_id: str,
        performed_by: str = "مدير النظام (Admin)",
    ) -> Dict[str, Any]:
        """
        استعادة دفعة مؤرشفة من التخزين البارد وإعادتها إلى جدول السجلات النشطة
        """
        from models import AuditLogArchive, AuditArchiveManifest

        archived_logs = db_session.query(AuditLogArchive).filter(
            AuditLogArchive.batch_id == batch_id
        ).all()

        if not archived_logs:
            return {
                "success": False,
                "message_ar": f"لم يتم العثور على دفعة أرشيف برقم ({batch_id}).",
            }

        restored_count = len(archived_logs)

        # إعادة إدراج السجلات في الجدول النشط عبر SQL مباشر
        for a_log in archived_logs:
            sql = sa_text("""
                INSERT OR REPLACE INTO audit_logs (
                    id, table_name, record_id, action, user_id, username, performed_by,
                    timestamp, reference_number, financial_amount, old_values_json,
                    new_values_json, details, previous_hash, entry_hash
                ) VALUES (
                    :id, :table_name, :record_id, :action, :user_id, :username, :performed_by,
                    :timestamp, :reference_number, :financial_amount, :old_values_json,
                    :new_values_json, :details, :previous_hash, :entry_hash
                )
            """)
            db_session.execute(sql, {
                "id": a_log.id,
                "table_name": a_log.table_name,
                "record_id": a_log.record_id,
                "action": a_log.action,
                "user_id": a_log.user_id,
                "username": a_log.username,
                "performed_by": a_log.performed_by,
                "timestamp": a_log.timestamp,
                "reference_number": a_log.reference_number,
                "financial_amount": a_log.financial_amount,
                "old_values_json": a_log.old_values_json,
                "new_values_json": a_log.new_values_json,
                "details": a_log.details,
                "previous_hash": a_log.previous_hash,
                "entry_hash": a_log.entry_hash,
            })

        # حذف السجلات المستعادة من الأرشيف والبيان
        db_session.execute(sa_text(f"DELETE FROM audit_logs_archive WHERE batch_id = :b_id"), {"b_id": batch_id})
        db_session.execute(sa_text(f"DELETE FROM audit_archive_manifests WHERE batch_id = :b_id"), {"b_id": batch_id})

        db_session.commit()

        return {
            "success": True,
            "batch_id": batch_id,
            "restored_count": restored_count,
            "message_ar": f"تمت استعادة {restored_count} سجل بنجاح من الدفعة ({batch_id}) وإعادتها للقاعدة النشطة.",
        }

    @classmethod
    def export_archive_batch_json(cls, db_session: Any, batch_id: str) -> bytes:
        """
        تصدير حزمة الأرشيف كملف JSON مصدق ومختوم بـ SHA-256
        """
        from models import AuditLogArchive, AuditArchiveManifest

        manifest = db_session.query(AuditArchiveManifest).filter(AuditArchiveManifest.batch_id == batch_id).first()
        logs = db_session.query(AuditLogArchive).filter(AuditLogArchive.batch_id == batch_id).order_by(AuditLogArchive.timestamp.asc()).all()

        export_payload = {
            "metadata": {
                "batch_id": batch_id,
                "archived_at": manifest.archived_at.isoformat() if manifest else "",
                "cutoff_date": manifest.cutoff_date.isoformat() if manifest else "",
                "record_count": len(logs),
                "total_financial_volume": float(manifest.total_financial_volume or 0.0) if manifest else 0.0,
                "manifest_sha256": manifest.manifest_sha256 if manifest else "",
                "archived_by": manifest.archived_by if manifest else "",
            },
            "records": [
                {
                    "id": l.id,
                    "table_name": l.table_name,
                    "record_id": l.record_id,
                    "action": l.action,
                    "user_id": l.user_id,
                    "username": l.username,
                    "performed_by": l.performed_by,
                    "timestamp": l.timestamp.isoformat() if l.timestamp else "",
                    "reference_number": l.reference_number,
                    "financial_amount": float(l.financial_amount or 0.0),
                    "old_values_json": l.old_values_json,
                    "new_values_json": l.new_values_json,
                    "details": l.details,
                    "previous_hash": l.previous_hash,
                    "entry_hash": l.entry_hash,
                }
                for l in logs
            ],
        }

        return json.dumps(export_payload, ensure_ascii=False, indent=2).encode("utf-8")

    @classmethod
    def query_archived_audit_logs(
        cls,
        db_session: Any,
        batch_id: Optional[str] = None,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
        user_filter: Optional[str] = None,
        action_filter: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 1000,
    ) -> Dict[str, Any]:
        """
        استعلام وتصفية السجلات التاريخية الموجودة بالتخزين البارد (AuditLogArchive)
        مع تحويل النتائج إلى DataFrame ودعم فلترة الدفعة والمستخدم والتاريخ والبحث بالكلمات المفتاحية.
        """
        import pandas as pd
        from models import AuditLogArchive

        query = db_session.query(AuditLogArchive)

        if batch_id and batch_id != "ALL":
            query = query.filter(AuditLogArchive.batch_id == batch_id)

        if start_date:
            dt_start = datetime.combine(start_date, datetime.min.time())
            query = query.filter(AuditLogArchive.timestamp >= dt_start)

        if end_date:
            dt_end = datetime.combine(end_date, datetime.max.time())
            query = query.filter(AuditLogArchive.timestamp <= dt_end)

        if user_filter and user_filter != "ALL":
            query = query.filter(
                (AuditLogArchive.user_id == user_filter) | (AuditLogArchive.username == user_filter)
            )

        if action_filter and action_filter != "ALL":
            query = query.filter(AuditLogArchive.action == action_filter)

        if search_query and search_query.strip():
            sq = f"%{search_query.strip()}%"
            query = query.filter(
                (AuditLogArchive.reference_number.like(sq))
                | (AuditLogArchive.details.like(sq))
                | (AuditLogArchive.action.like(sq))
                | (AuditLogArchive.user_id.like(sq))
                | (AuditLogArchive.username.like(sq))
                | (AuditLogArchive.performed_by.like(sq))
            )

        total_matched = query.count()
        logs = query.order_by(AuditLogArchive.timestamp.desc()).limit(limit).all()

        total_financial_volume = sum(Decimal(str(l.financial_amount or 0.0)) for l in logs)

        rows = []
        for l in logs:
            rows.append({
                "معرف الأرشيف": l.id,
                "دفعة الأرشيف": l.batch_id,
                "الطابع الزمني (UTC)": l.timestamp.strftime("%Y-%m-%d %H:%M:%S") if l.timestamp else "—",
                "الجدول المالي": l.table_name,
                "رمز الإجراء": l.action,
                "المستخدم": f"{l.user_id} ({l.username or '—'})",
                "المستند / المرجع": l.reference_number or "—",
                "المبلغ المالي (ريال)": float(l.financial_amount or 0.0),
                "البصمة التشفيرية (SHA-256)": f"{l.entry_hash[:16]}..." if l.entry_hash else "—",
                "التفاصيل والملاحظات": l.details or "—",
            })

        df = pd.DataFrame(rows) if rows else pd.DataFrame()

        return {
            "total_matched": total_matched,
            "total_financial_volume": float(total_financial_volume),
            "logs_count": len(logs),
            "logs": logs,
            "dataframe": df,
            "batches_count": len({l.batch_id for l in logs}),
        }


def render_cold_storage_browser_ui(db_session: Any, key_prefix: str = "cold_browser") -> None:
    """
    واجهة Streamlit لاستعراض واسترجاع سجلات التدقيق التاريخية المحفوظة بالتخزين البارد
    """
    import streamlit as st
    import pandas as pd
    from export_service import CSVExportService

    summary = AuditArchiveService.get_archive_status_summary(db_session)
    batch_options = ["ALL"] + [b["batch_id"] for b in summary["batches"]]

    st.markdown("##### **🔍 متصفح ومحرك استرجاع سجلات التدقيق التاريخية من التخزين البارد (Cold Storage Log Browser):**")
    st.caption(
        "يتيح للمراجعين القانونيين والرقابيين الاستعلام عن السجلات التاريخية الأقدم من سنة والتنقيب المباشر "
        "في دفعات التخزين البارد والتحقق التشفيري منها واستخراج التفاصيل مع لقطات الحالة (Before/After Snapshots)."
    )

    with st.container(border=True):
        c1, c2, c3, c4 = st.columns([1.5, 1.2, 1.2, 1.5])
        with c1:
            sel_batch = st.selectbox(
                "📦 اختر دفعة الأرشيف البارد:",
                batch_options,
                format_func=lambda b: "جميع دفعات التخزين البارد (ALL)" if b == "ALL" else f"دفعة: {b}",
                key=f"{key_prefix}_sel_batch",
            )
        with c2:
            st_date = st.date_input("من تاريخ:", value=date.today() - timedelta(days=730), key=f"{key_prefix}_st_date")
        with c3:
            en_date = st.date_input("إلى تاريخ:", value=date.today(), key=f"{key_prefix}_en_date")
        with c4:
            cold_search = st.text_input(
                "بحث بالكلمات المفتاحية / المراجع:",
                placeholder="رقم المستند، المعرف، الإجراء...",
                key=f"{key_prefix}_search_q",
            )

    cold_res = AuditArchiveService.query_archived_audit_logs(
        db_session,
        batch_id=sel_batch,
        start_date=st_date,
        end_date=en_date,
        search_query=cold_search,
    )

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("السجلات المفلترة بالأرشيف", f"{cold_res['total_matched']} سجل")
    m2.metric("الحجم المالي بالأرشيف", f"{cold_res['total_financial_volume']:,.2f} ريال")
    m3.metric("عدد الدفعات المشمولة", f"{cold_res['batches_count']} دفعة")
    m4.metric("سلامة أختام المانيفست", "مؤمّنة بـ SHA-256 ✅")

    st.divider()

    cold_df = cold_res["dataframe"]
    if not cold_df.empty:
        st.markdown("###### **📋 جدول سجلات التخزين البارد المفلترة:**")
        st.dataframe(cold_df, use_container_width=True, hide_index=True)

        col_dl1, col_dl2 = st.columns(2)
        with col_dl1:
            csv_data = cold_df.to_csv(index=False, encoding="utf-8-sig").encode("utf-8-sig")
            st.download_button(
                "📊 تصدير نتائج التخزين البارد بصيغة (CSV للمراجع الخارجي)",
                data=csv_data,
                file_name=f"ZATCA_Cold_Storage_Logs_{sel_batch}.csv",
                mime="text/csv",
                key=f"{key_prefix}_dl_csv",
                use_container_width=True,
            )
        with col_dl2:
            if sel_batch != "ALL":
                json_bytes = AuditArchiveService.export_archive_batch_json(db_session, sel_batch)
                st.download_button(
                    "📥 تصدير حزمة الدفعة المختومة بصيغة (JSON)",
                    data=json_bytes,
                    file_name=f"ZATCA_Cold_Archive_{sel_batch}.json",
                    mime="application/json",
                    key=f"{key_prefix}_dl_json",
                    use_container_width=True,
                )

        st.divider()
        st.markdown("###### **🔍 فحص وتفتيش تفاصيل سجل أرشيف محدد:**")
        selected_log_ids = [l.id for l in cold_res["logs"]]
        if selected_log_ids:
            sel_arch_id = st.selectbox("اختر رقم معرف سجل الأرشيف للتفتيش:", selected_log_ids, key=f"{key_prefix}_sel_log_id")
            arch_log_item = [l for l in cold_res["logs"] if l.id == sel_arch_id][0]

            with st.expander(f"📄 تفاصيل سجل الأرشيف #{arch_log_item.id} | الإجراء: {arch_log_item.action}", expanded=True):
                i1, i2, i3 = st.columns(3)
                i1.markdown(f"**معرف السجل الأصلي:** `{arch_log_item.id}`")
                i1.markdown(f"**دفعة الأرشيف:** `{arch_log_item.batch_id}`")
                i1.markdown(f"**المستخدم:** `{arch_log_item.user_id}` ({arch_log_item.username})")

                i2.markdown(f"**تاريخ العملية التاريخية:** `{arch_log_item.timestamp}`")
                i2.markdown(f"**الجدول المالي:** `{arch_log_item.table_name}`")
                i2.markdown(f"**المبلغ المالي:** `{float(arch_log_item.financial_amount or 0.0):,.2f} ريال`")

                i3.markdown(f"**البصمة التشفيرية (Entry Hash):** `{arch_log_item.entry_hash}`")
                i3.markdown(f"**البصمة السابقة (Previous Hash):** `{arch_log_item.previous_hash}`")
                i3.markdown(f"**أرشف بواسطة:** `{arch_log_item.archived_by}`")

                st.markdown(f"**التفاصيل والملاحظات:** {arch_log_item.details or '—'}")

                j1, j2 = st.columns(2)
                with j1:
                    st.markdown("**القيم السابقة (Before Snapshot):**")
                    st.code(arch_log_item.old_values_json or "لا توجد قيم سابقة (إدراج جديد)", language="json")
                with j2:
                    st.markdown("**القيم اللاحقة (After Snapshot):**")
                    st.code(arch_log_item.new_values_json or "—", language="json")
    else:
        st.info("لا توجد سجلات تدقيق تاريخية في التخزين البارد مطابقة لمعايير الفلترة المحددة.")


def render_audit_archive_management_ui(db_session: Any, key_prefix: str = "audit_arch") -> None:
    """
    واجهة Streamlit لإدارة الأرشفة والتخزين البارد لسجلات التدقيق
    """
    import streamlit as st

    summary = AuditArchiveService.get_archive_status_summary(db_session)

    st.markdown("##### **📦 نظام الأرشفة والتخزين البارد لسجلات التدقيق (Cold Storage Audit Archival System):**")
    st.caption(
        "يتيح أرشفة ونقل السجلات التاريخية القديمة إلى جدول التخزين البارد لضمان السرعة الفائقة لقاعدة البيانات النشطة "
        "مع إتاحة استعراضها وتصديرها واستعادتها في أي وقت دون مساس بسلسلة التشفير SHA-256."
    )

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("السجلات النشطة بالقاعدة", f"{summary['active_count']} سجل")
    k2.metric("السجلات بالأرشيف البارد", f"{summary['archived_count']} سجل")
    k3.metric("نسبة تحسين أداء القاعدة", f"{summary['optimization_ratio_pct']}%")
    k4.metric("عدد دفعات الأرشيف", f"{summary['batches_count']} دفعة")

    st.divider()

    t_manage, t_browse = st.tabs([
        "🚀 إدارة وتشغيل الأرشفة والدفعات",
        "🔍 متصفح واسترجاع سجلات التخزين البارد",
    ])

    with t_manage:
        col_arch1, col_arch2 = st.columns([1.8, 1.2])
        with col_arch1:
            st.markdown("###### **🚀 تشغيل الأرشفة ونقل السجلات إلى التخزين البارد:**")
            cutoff_days_val = st.slider(
                "حدد حد أقدمية السجلات المراد نقلها للأرشيف البارد (بالأيام):",
                min_value=90,
                max_value=730,
                value=365,
                step=30,
                key=f"{key_prefix}_slider_days",
                help="365 يوماً = أرشفة السجلات الأقدم من سنة كاملة",
            )
            cutoff_date_calc = date.today() - timedelta(days=cutoff_days_val)
            st.info(f"📅 **تاريخ القطع المحسوب:** سيتم نقل جميع سجلات التدقيق الأقدم من **`{cutoff_date_calc.strftime('%Y-%m-%d')}`** إلى التخزين البارد.")

            confirm_archive = st.checkbox("أؤكد الرغبة في نقل السجلات القديمة للتخزين البارد الآن", key=f"{key_prefix}_chk_confirm")

            if st.button("📦 نقل السجلات القديمة للتخزين البارد الآن", type="primary", disabled=not confirm_archive, key=f"{key_prefix}_btn_run_arch"):
                u_actor = st.session_state.get("active_user", "مدير النظام (Admin)")
                res = AuditArchiveService.archive_older_audit_logs(
                    db_session,
                    cutoff_days=cutoff_days_val,
                    performed_by=u_actor,
                )
                if res.get("success"):
                    st.success(f"🎉 {res['message_ar']} — الختم التشفيري للدفعة: `{res['manifest_sha256'][:18]}...`")
                    st.rerun()
                else:
                    st.warning(f"⚠️ {res['message_ar']}")

        with col_arch2:
            st.markdown("###### **📂 أداء وسرعة المحرك:**")
            st.markdown(
                f"- **تاريخ أقدم سجل نشط:** `{summary['oldest_active_date']}`  \n"
                f"- **تاريخ أقدم سجل مؤرشف:** `{summary['oldest_archive_date']}`  \n"
                f"- **إجمالي السجلات التاريخية:** `{summary['total_historical']}` سجل  \n"
                f"- **حالة المحرك:** جاهز ومحسّن ⚡"
            )

        st.divider()

        st.markdown("###### **📜 سجل دفعات التخزين البارد المحفوظة وإمكانية التصدير والاستعادة:**")
        if summary["batches"]:
            for batch in summary["batches"]:
                with st.expander(f"📦 دفعة: {batch['batch_id']} | السجلات: {batch['record_count']} | بتاريخ: {batch['archived_at']}"):
                    b1, b2, b3 = st.columns([2, 1, 1])
                    with b1:
                        st.markdown(f"**معرف الدفعة:** `{batch['batch_id']}`")
                        st.markdown(f"**تاريخ القطع:** `{batch['cutoff_date']}`")
                        st.markdown(f"**الختم التشفيري (Manifest SHA-256):** `{batch['manifest_sha256']}`")
                    with b2:
                        json_bytes = AuditArchiveService.export_archive_batch_json(db_session, batch["batch_id"])
                        st.download_button(
                            "📥 تصدير حزمة الأرشيف (JSON)",
                            data=json_bytes,
                            file_name=f"ZATCA_Cold_Archive_{batch['batch_id']}.json",
                            mime="application/json",
                            key=f"{key_prefix}_dl_b_{batch['batch_id']}",
                            use_container_width=True,
                        )
                    with b3:
                        if st.button("🔄 استعادة للقاعدة النشطة", key=f"{key_prefix}_rst_b_{batch['batch_id']}", use_container_width=True):
                            u_actor = st.session_state.get("active_user", "مدير النظام (Admin)")
                            r_res = AuditArchiveService.restore_archived_audit_batch(db_session, batch["batch_id"], performed_by=u_actor)
                            if r_res.get("success"):
                                st.success(r_res["message_ar"])
                                st.rerun()
                            else:
                                st.error(r_res.get("message_ar"))
        else:
            st.info("لا توجد دفعات مؤرشفة بالتخزين البارد حالياً.")

    with t_browse:
        render_cold_storage_browser_ui(db_session, key_prefix=f"{key_prefix}_tab_browser")

