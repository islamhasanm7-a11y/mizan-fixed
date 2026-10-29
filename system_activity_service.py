"""
MizanPro ERP - System Activity & Configuration Audit Module
محرك تتبع وتوثيق نشاط النظام وسجل دخول وخروج المستخدمين وتغييرات الإعدادات والسياسات
يكمل سجلات التدقيق المالي ويوفر رؤية شاملة لأمان وتهيئة النظام
"""

import json
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from models import (
    AppUser,
    ConfigurationChangeLog,
    UserLoginHistory,
    utc_now,
)


CONFIG_CATEGORIES: Dict[str, Dict[str, str]] = {
    "COMPANY_SETTINGS": {
        "label": "إعدادات المنشأة والضرائب (Company Settings & VAT)",
        "icon": "🏢",
        "description": "تعديل اسم المنشأة، الرقم الضريبي، السجل التجاري، ونسبة الضريبة الافتراضية",
    },
    "USER_PERMISSIONS": {
        "label": "صلاحيات وحسابات المستخدمين (User Accounts & RBAC)",
        "icon": "👤",
        "description": "إنشاء المستخدمين، تعديل الصلاحيات الحرة، وتغيير سقف نسب الخصم المسموح بها",
    },
    "CUSTOM_ROLES": {
        "label": "قوالب الأدوار الوظيفية (Role Templates)",
        "icon": "🎭",
        "description": "إضافة أو تعديل قوالب الأدوار الوظيفية المخصصة (أمين صندوق، محاسب رواتب، إلخ)",
    },
    "FISCAL_PERIODS": {
        "label": "الفترات والسنوات المالية (Fiscal Periods & Closing)",
        "icon": "📅",
        "description": "فتح أو إقفال وقفل الفترات والسنوات المالية ومنع ترحيل الحركات عليها",
    },
    "AUDIT_SCHEDULES": {
        "label": "جدولة تقارير التدقيق (Audit Report Schedules)",
        "icon": "⏰",
        "description": "إنشاء وتعديل جداول الإرسال الآلي لتقارير التدقيق للمراجعين الخارجيين",
    },
    "REPORT_TEMPLATES": {
        "label": "قوالب التقارير الرقابية (Custom Report Templates)",
        "icon": "📑",
        "description": "تصميم وتحديث قوالب تقارير التدقيق الرقابي لهيئات ZATCA و SOCPA و CMA",
    },
    "SECURITY_POLICY": {
        "label": "سياسات الأمان ورموز الدخول (Security Policies & PINs)",
        "icon": "🔒",
        "description": "تغيير رموز الـ PIN وتدوير الرموز المكشوفة وفرض تغيير الرمز عند أول دخول",
    },
}

LOGIN_STATUS_META: Dict[str, Dict[str, str]] = {
    "SUCCESS": {
        "label_ar": "دخول ناجح",
        "badge_color": "#10b981",
        "bg_color": "#064e3b",
        "icon": "✅",
    },
    "FAILED_BAD_PIN": {
        "label_ar": "فشل - رمز PIN غير صحيح",
        "badge_color": "#ef4444",
        "bg_color": "#7f1d1d",
        "icon": "❌",
    },
    "FAILED_USER_LOCKED": {
        "label_ar": "فشل - الحساب مقفل أو موقوف",
        "badge_color": "#f59e0b",
        "bg_color": "#78350f",
        "icon": "🔒",
    },
    "FAILED_USER_NOT_FOUND": {
        "label_ar": "فشل - اسم المستخدم غير موجود",
        "badge_color": "#f87171",
        "bg_color": "#450a0a",
        "icon": "⚠️",
    },
    "LOGOUT": {
        "label_ar": "تسجيل خروج آمن",
        "badge_color": "#94a3b8",
        "bg_color": "#1e293b",
        "icon": "🚪",
    },
    "PIN_CHANGE": {
        "label_ar": "تحديث رمز الدخول السري (PIN)",
        "badge_color": "#38bdf8",
        "bg_color": "#0c4a6e",
        "icon": "🔑",
    },
}


class SystemActivityService:
    """
    خدمة تتبع وتوثيق نشاط النظام: سجل الدخول والخروج وتغييرات الإعدادات والسياسات
    """

    # -------------------------------------------------------------------------
    # 1. تسجيل وتوثيق حركات الدخول والخروج (User Login History)
    # -------------------------------------------------------------------------
    @classmethod
    def log_login_attempt(
        cls,
        db: Session,
        username: str,
        status: str,
        user_id: Optional[int] = None,
        full_name_ar: Optional[str] = None,
        failure_reason: Optional[str] = None,
        ip_address: str = "127.0.0.1",
        user_agent: str = "Web Client / Streamlit",
        session_id: Optional[str] = None,
        details: Optional[str] = None,
    ) -> UserLoginHistory:
        """توثيق محاولة تسجيل الدخول (سواء كانت ناجحة أو فاشلة) في جدول مخصص"""
        rec = UserLoginHistory(
            user_id=user_id,
            username=str(username or "").strip(),
            full_name_ar=full_name_ar,
            timestamp=utc_now(),
            status=status,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            failure_reason=failure_reason,
            details=details,
        )
        db.add(rec)
        db.commit()
        db.refresh(rec)
        return rec

    @classmethod
    def log_logout(
        cls,
        db: Session,
        user_id: Optional[int],
        username: str,
        full_name_ar: Optional[str] = None,
        ip_address: str = "127.0.0.1",
        details: Optional[str] = None,
    ) -> UserLoginHistory:
        """توثيق تسجيل خروج المستخدم من النظام"""
        rec = UserLoginHistory(
            user_id=user_id,
            username=str(username or "").strip(),
            full_name_ar=full_name_ar,
            timestamp=utc_now(),
            status="LOGOUT",
            ip_address=ip_address,
            user_agent="Web Client / Streamlit",
            details=details or "تسجيل خروج يدوي آمن من شريط الأدوات",
        )
        db.add(rec)
        db.commit()
        db.refresh(rec)
        return rec

    # -------------------------------------------------------------------------
    # 2. تسجيل وتوثيق تغييرات الإعدادات والسياسات (Configuration Changes)
    # -------------------------------------------------------------------------
    @classmethod
    def log_configuration_change(
        cls,
        db: Session,
        config_category: str,
        target_item: str,
        action_type: str,
        old_values: Optional[Dict[str, Any]] = None,
        new_values: Optional[Dict[str, Any]] = None,
        performed_by: str = "مدير النظام (Admin)",
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        change_reason: Optional[str] = None,
        ip_address: str = "127.0.0.1",
        details: Optional[str] = None,
    ) -> ConfigurationChangeLog:
        """توثيق تغيير إعدادات المنشأة أو الصلاحيات أو الفترات مع حفظ المقارنة قبل وبعد التعديل"""
        old_json = json.dumps(old_values, ensure_ascii=False) if old_values is not None else None
        new_json = json.dumps(new_values, ensure_ascii=False) if new_values is not None else None

        # إنشاء ملخص الفروقات تلقائياً
        diff_summary = ""
        if old_values and new_values:
            diff_items = []
            for k, new_v in new_values.items():
                old_v = old_values.get(k)
                if old_v != new_v:
                    diff_items.append(f"{k}: '{old_v}' ➔ '{new_v}'")
            diff_summary = " | ".join(diff_items) if diff_items else "بدون تغييرات في القيم"
        elif new_values and not old_values:
            diff_summary = f"إنشاء عنصر جديد: {', '.join(list(new_values.keys())[:5])}"
        elif old_values and not new_values:
            diff_summary = f"حذف عنصر: {', '.join(list(old_values.keys())[:5])}"

        rec = ConfigurationChangeLog(
            timestamp=utc_now(),
            user_id=user_id or "USR-001",
            username=username or "admin",
            performed_by=performed_by,
            config_category=config_category,
            target_item=target_item,
            action_type=action_type,
            old_values_json=old_json,
            new_values_json=new_json,
            diff_summary=diff_summary,
            change_reason=change_reason,
            ip_address=ip_address,
            details=details,
        )
        db.add(rec)
        db.commit()
        db.refresh(rec)
        return rec

    # -------------------------------------------------------------------------
    # 3. استعلام وفلترة سجل الدخول (Query Login History)
    # -------------------------------------------------------------------------
    @classmethod
    def query_login_history(
        cls,
        db: Session,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
        username: Optional[str] = None,
        status: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 500,
    ) -> Dict[str, Any]:
        """استعلام وفلترة سجل تسجيل دخول المستخدمين"""
        q = db.query(UserLoginHistory)

        if start_date:
            s_dt = datetime.combine(start_date, datetime.min.time())
            q = q.filter(UserLoginHistory.timestamp >= s_dt)
        if end_date:
            e_dt = datetime.combine(end_date, datetime.max.time())
            q = q.filter(UserLoginHistory.timestamp <= e_dt)

        if username and username not in ("الكل", "ALL", ""):
            q = q.filter(func.lower(UserLoginHistory.username) == username.strip().lower())

        if status and status not in ("الكل", "ALL", ""):
            q = q.filter(UserLoginHistory.status == status.strip())

        if search_query and search_query.strip():
            sq = f"%{search_query.strip().lower()}%"
            q = q.filter(
                (func.lower(UserLoginHistory.username).like(sq))
                | (func.lower(UserLoginHistory.full_name_ar).like(sq))
                | (func.lower(UserLoginHistory.failure_reason).like(sq))
                | (func.lower(UserLoginHistory.details).like(sq))
                | (func.lower(UserLoginHistory.ip_address).like(sq))
            )

        records = q.order_by(desc(UserLoginHistory.timestamp)).limit(limit).all()

        rows = []
        for r in records:
            st_meta = LOGIN_STATUS_META.get(r.status, {"label_ar": r.status, "icon": "ℹ️"})
            rows.append({
                "المعرف": f"#{r.id}",
                "الطابع الزمني (UTC)": r.timestamp.strftime("%Y-%m-%d %H:%M:%S") if r.timestamp else "-",
                "اسم المستخدم": r.username,
                "الاسم الكامل": r.full_name_ar or "-",
                "الحالة": f"{st_meta['icon']} {st_meta['label_ar']}",
                "رمز الحالة": r.status,
                "عنوان IP": r.ip_address or "-",
                "سبب الفشل": r.failure_reason or "-",
                "التفاصيل": r.details or "-",
            })

        df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=[
            "المعرف", "الطابع الزمني (UTC)", "اسم المستخدم", "الاسم الكامل", "الحالة", "رمز الحالة", "عنوان IP", "سبب الفشل", "التفاصيل"
        ])

        return {
            "records": records,
            "dataframe": df,
            "total_count": len(records),
        }

    # -------------------------------------------------------------------------
    # 4. استعلام وفلترة تغييرات الإعدادات (Query Configuration Changes)
    # -------------------------------------------------------------------------
    @classmethod
    def query_configuration_changes(
        cls,
        db: Session,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
        category: Optional[str] = None,
        user_filter: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 500,
    ) -> Dict[str, Any]:
        """استعلام وفلترة سجل تغييرات الإعدادات والسياسات"""
        q = db.query(ConfigurationChangeLog)

        if start_date:
            s_dt = datetime.combine(start_date, datetime.min.time())
            q = q.filter(ConfigurationChangeLog.timestamp >= s_dt)
        if end_date:
            e_dt = datetime.combine(end_date, datetime.max.time())
            q = q.filter(ConfigurationChangeLog.timestamp <= e_dt)

        if category and category not in ("الكل", "ALL", ""):
            q = q.filter(ConfigurationChangeLog.config_category == category.strip())

        if user_filter and user_filter not in ("الكل", "ALL", ""):
            u_clean = user_filter.strip().lower()
            q = q.filter(
                (func.lower(ConfigurationChangeLog.username) == u_clean)
                | (func.lower(ConfigurationChangeLog.performed_by).like(f"%{u_clean}%"))
            )

        if search_query and search_query.strip():
            sq = f"%{search_query.strip().lower()}%"
            q = q.filter(
                (func.lower(ConfigurationChangeLog.target_item).like(sq))
                | (func.lower(ConfigurationChangeLog.diff_summary).like(sq))
                | (func.lower(ConfigurationChangeLog.change_reason).like(sq))
                | (func.lower(ConfigurationChangeLog.details).like(sq))
            )

        records = q.order_by(desc(ConfigurationChangeLog.timestamp)).limit(limit).all()

        rows = []
        for r in records:
            cat_meta = CONFIG_CATEGORIES.get(r.config_category, {"label": r.config_category, "icon": "⚙️"})
            rows.append({
                "المعرف": f"#{r.id}",
                "الطابع الزمني (UTC)": r.timestamp.strftime("%Y-%m-%d %H:%M:%S") if r.timestamp else "-",
                "التصنيف": f"{cat_meta['icon']} {cat_meta['label']}",
                "العنصر المستهدف": r.target_item,
                "نوع الإجراء": r.action_type,
                "المستخدم المنفذ": r.performed_by,
                "ملخص التغيير": r.diff_summary or "-",
                "سبب التعديل": r.change_reason or "-",
                "القيم السابقة (Old)": r.old_values_json or "-",
                "القيم الجديدة (New)": r.new_values_json or "-",
            })

        df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=[
            "المعرف", "الطابع الزمني (UTC)", "التصنيف", "العنصر المستهدف", "نوع الإجراء", "المستخدم المنفذ", "ملخص التغيير", "سبب التعديل", "القيم السابقة (Old)", "القيم الجديدة (New)"
        ])

        return {
            "records": records,
            "dataframe": df,
            "total_count": len(records),
        }

    # -------------------------------------------------------------------------
    # 5. ملخص إحصائيات الأمان والنشاط (Summary & KPI Metrics)
    # -------------------------------------------------------------------------
    @classmethod
    def get_system_activity_summary(cls, db: Session) -> Dict[str, Any]:
        """توليد مؤشرات الأمان والنشاط الإداري لنظام MizanPro"""
        now = utc_now()
        yesterday = now - timedelta(days=1)
        last_7_days = now - timedelta(days=7)

        total_logins = db.query(UserLoginHistory).count()
        success_logins = db.query(UserLoginHistory).filter(UserLoginHistory.status == "SUCCESS").count()
        failed_logins = db.query(UserLoginHistory).filter(UserLoginHistory.status.like("FAILED_%")).count()
        failed_24h = (
            db.query(UserLoginHistory)
            .filter(UserLoginHistory.status.like("FAILED_%"), UserLoginHistory.timestamp >= yesterday)
            .count()
        )
        logouts = db.query(UserLoginHistory).filter(UserLoginHistory.status == "LOGOUT").count()

        total_config_changes = db.query(ConfigurationChangeLog).count()
        config_24h = (
            db.query(ConfigurationChangeLog)
            .filter(ConfigurationChangeLog.timestamp >= yesterday)
            .count()
        )

        active_users_cnt = db.query(AppUser).filter(AppUser.is_active == True).count()

        return {
            "total_logins": total_logins,
            "success_logins": success_logins,
            "failed_logins": failed_logins,
            "failed_24h": failed_24h,
            "logouts": logouts,
            "total_config_changes": total_config_changes,
            "config_24h": config_24h,
            "active_users_cnt": active_users_cnt,
        }


# =============================================================================
# 4. واجهة المستخدم الرقابية لنشاط النظام (Streamlit UI Component)
# =============================================================================

def render_system_activity_module(db: Session, key_prefix: str = "sys_act") -> None:
    """
    واجهة نشاط النظام وسجل الدخول والإعدادات (System Activity & Configuration Audit UI)
    تعمل مكملاً لسجلات التدقيق المالي وتركز على أمان الجلسات وحوكمة التعديلات الإدارية
    """
    import streamlit as st

    st.markdown("""
    <div style="background: linear-gradient(135deg, #0b1329 0%, #172554 100%); color: white; padding: 20px 24px; border-radius: 12px; border-right: 6px solid #38bdf8; margin-bottom: 20px;">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
            <div>
                <h3 style="margin:0; color:#F8FAFC;">🖥️ نشاط النظام وسجل الدخول والإعدادات (System Activity & Configuration Audit)</h3>
                <p style="margin:6px 0 0 0; color:#93c5fd; font-size:13.5px;">
                    وحدة رقابية مكملة لسجلات التدقيق المالي — توثق وتتتبع جلسات تسجيل الدخول والخروج للمستخدمين، وتغييرات إعدادات المنشأة، والضرائب، وتعديل صلاحيات المستخدمين وقوالب الأدوار وإقفال الفترات المحاسبية.
                </p>
            </div>
            <div style="background:#1e3a8a; color:#bfdbfe; padding:8px 16px; border-radius:20px; font-size:12px; font-weight:700; border:1px solid #60a5fa;">
                🛡️ حوكمة أمن النظام ومسار الجلسات
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    summary = SystemActivityService.get_system_activity_summary(db)

    # بطاقات المؤشرات الرئيسية
    kc1, kc2, kc3, kc4 = st.columns(4)
    kc1.metric("إجمالي جلسات الدخول المسجلة", f"{summary['total_logins']}", f"+{summary['success_logins']} ناجحة")
    kc2.metric("محاولات الدخول الفاشلة", f"{summary['failed_logins']}", f"{summary['failed_24h']} آخر 24 ساعة", delta_color="inverse")
    kc3.metric("تعديلات الإعدادات والسياسات", f"{summary['total_config_changes']}", f"+{summary['config_24h']} آخر 24 ساعة")
    kc4.metric("الحسابات النشطة والمخولين", f"{summary['active_users_cnt']} مستخدمين", "نشط ومفعل")

    st.divider()

    tab_login, tab_config, tab_analytics = st.tabs([
        "🔐 سجل دخول وخروج المستخدمين (User Login & Auth History)",
        "⚙️ سجل تغييرات الإعدادات والسياسات (Configuration & Policy Changes)",
        "📊 التحليل الإحصائي للأمان والنشاط (Security & Activity Analytics)",
    ])

    # -------------------------------------------------------------------------
    # تبويب 1: سجل تسجيل الدخول والخروج
    # -------------------------------------------------------------------------
    with tab_login:
        st.markdown("##### **🔐 سجل محاولات الدخول وجلسات المستخدمين:**")
        st.caption("توثيق زمني دقيق لكل محاولة دخول ناجحة أو فاشلة (رمز سري غير صحيح أو حساب موقوف) مع عنوان IP وسبب الفشل.")

        with st.container(border=True):
            fl1, fl2, fl3, fl4 = st.columns([1.2, 1.2, 1.2, 1.6])
            with fl1:
                log_preset = st.selectbox(
                    "📅 النطاق الزمني:",
                    ["الكل", "اليوم فقط", "آخر 7 أيام", "آخر 30 يوماً"],
                    key=f"{key_prefix}_log_preset",
                )
                today_d = date.today()
                if log_preset == "اليوم فقط":
                    l_sdate, l_edate = today_d, today_d
                elif log_preset == "آخر 7 أيام":
                    l_sdate, l_edate = today_d - timedelta(days=7), today_d
                elif log_preset == "آخر 30 يوماً":
                    l_sdate, l_edate = today_d - timedelta(days=30), today_d
                else:
                    l_sdate, l_edate = None, None

            with fl2:
                all_users = [u.username for u in db.query(AppUser).all()]
                sel_u = st.selectbox("👤 المستخدم:", ["الكل"] + all_users, key=f"{key_prefix}_log_user")

            with fl3:
                sel_st = st.selectbox(
                    "🚦 حالة العملية:",
                    ["الكل", "SUCCESS", "FAILED_BAD_PIN", "FAILED_USER_LOCKED", "FAILED_USER_NOT_FOUND", "LOGOUT", "PIN_CHANGE"],
                    format_func=lambda k: f"{LOGIN_STATUS_META.get(k, {}).get('icon', '')} {LOGIN_STATUS_META.get(k, {}).get('label_ar', k)}",
                    key=f"{key_prefix}_log_st",
                )

            with fl4:
                log_search_q = st.text_input(
                    "🔍 بحث بالكلمة المفتاحية (IP / سبب الفشل / تفاصيل):",
                    placeholder="مثال: 127.0.0.1 أو admin أو فشل",
                    key=f"{key_prefix}_log_search_q",
                )

        login_res = SystemActivityService.query_login_history(
            db=db,
            start_date=l_sdate,
            end_date=l_edate,
            username=None if sel_u == "الكل" else sel_u,
            status=None if sel_st == "الكل" else sel_st,
            search_query=log_search_q,
            limit=500,
        )

        st.caption(f"تم العثور على **({login_res['total_count']})** سجل دخول وخروج مطابق لمعايير البحث.")

        if not login_res["dataframe"].empty:
            st.dataframe(login_res["dataframe"], use_container_width=True, hide_index=True)

            csv_data = login_res["dataframe"].to_csv(index=False).encode("utf-8-sig")
            st.download_button(
                "📥 تصدير سجل الدخول (Excel / CSV)",
                data=csv_data,
                file_name=f"User_Login_History_{date.today()}.csv",
                mime="text/csv",
                key=f"{key_prefix}_dl_log_csv",
            )
        else:
            st.info("لا توجد حركات تسجيل دخول مطابقة للبحث المحدد.")

    # -------------------------------------------------------------------------
    # تبويب 2: سجل تغييرات الإعدادات والسياسات
    # -------------------------------------------------------------------------
    with tab_config:
        st.markdown("##### **⚙️ سجل تعديلات الإعدادات والسياسات وحوكمة التغيير:**")
        st.caption("مقارنة تفصيلية وتاريخية لكافة التعديلات الإدارية على إعدادات المنشأة والضرائب والصلاحيات وحالة إقفال الفترات.")

        with st.container(border=True):
            fc1, fc2, fc3 = st.columns([1.5, 1.2, 1.8])
            with fc1:
                cat_choices = ["الكل"] + list(CONFIG_CATEGORIES.keys())
                sel_cat = st.selectbox(
                    "🗂️ تصنيف الإعدادات:",
                    cat_choices,
                    format_func=lambda k: f"{CONFIG_CATEGORIES.get(k, {}).get('icon', '📋')} {CONFIG_CATEGORIES.get(k, {}).get('label', k)}",
                    key=f"{key_prefix}_cfg_cat",
                )
            with fc2:
                sel_cfg_user = st.selectbox("👤 المنفّذ:", ["الكل"] + all_users, key=f"{key_prefix}_cfg_user")
            with fc3:
                cfg_search_q = st.text_input(
                    "🔍 بحث بالكلمة المفتاحية في العنصر أو سبب التعديل:",
                    placeholder="مثال: الضريبة أو الصلاحيات أو USR-001",
                    key=f"{key_prefix}_cfg_search_q",
                )

        cfg_res = SystemActivityService.query_configuration_changes(
            db=db,
            category=None if sel_cat == "الكل" else sel_cat,
            user_filter=None if sel_cfg_user == "الكل" else sel_cfg_user,
            search_query=cfg_search_q,
            limit=500,
        )

        st.caption(f"تم العثور على **({cfg_res['total_count']})** سجل تعديل إعدادات مطابق لمعايير الفلترة.")

        if not cfg_res["dataframe"].empty:
            st.dataframe(cfg_res["dataframe"], use_container_width=True, hide_index=True)

            # فاحص الفروقات التفاعلي (Interactive Diff Inspector)
            st.markdown("###### **🔍 فاحص الفروقات التفصيلي (Before & After Inspector):**")
            with st.expander("👁️ عرض ومقارنة القيم قبل وبعد التعديل لسجل محدد", expanded=False):
                cfg_id_map = {f"#{c.id} - {c.target_item} ({c.action_type}) - {c.timestamp.strftime('%Y-%m-%d %H:%M') if c.timestamp else ''}": c for c in cfg_res["records"]}
                if cfg_id_map:
                    sel_diff_lbl = st.selectbox("اختر السجل للفحص:", list(cfg_id_map.keys()), key=f"{key_prefix}_sel_diff_rec")
                    active_cfg: ConfigurationChangeLog = cfg_id_map[sel_diff_lbl]

                    d_col1, d_col2 = st.columns(2)
                    with d_col1:
                        st.markdown("**🔴 القيم السابقة قبل التعديل (Old State):**")
                        if active_cfg.old_values_json:
                            try:
                                st.json(json.loads(active_cfg.old_values_json))
                            except Exception:
                                st.code(active_cfg.old_values_json)
                        else:
                            st.info("لا توجد قيم سابقة (إنشاء جديد)")

                    with d_col2:
                        st.markdown("**🟢 القيم المعدلة الجديدة (New State):**")
                        if active_cfg.new_values_json:
                            try:
                                st.json(json.loads(active_cfg.new_values_json))
                            except Exception:
                                st.code(active_cfg.new_values_json)
                        else:
                            st.info("لا توجد قيم جديدة (تم الحذف)")

                    st.markdown(f"**📝 ملخص التغييرات:** `{active_cfg.diff_summary or 'غير محدد'}`")
                    st.markdown(f"**👤 المنفذ:** `{active_cfg.performed_by}` | **IP:** `{active_cfg.ip_address}`")

            cfg_csv = cfg_res["dataframe"].to_csv(index=False).encode("utf-8-sig")
            st.download_button(
                "📥 تصدير سجل تغييرات الإعدادات (Excel / CSV)",
                data=cfg_csv,
                file_name=f"Configuration_Changes_{date.today()}.csv",
                mime="text/csv",
                key=f"{key_prefix}_dl_cfg_csv",
            )
        else:
            st.info("لا توجد تعديلات إعدادات مسجلة مطابقة لمعايير البحث.")

    # -------------------------------------------------------------------------
    # تبويب 3: التحليل الإحصائي للأمان والنشاط
    # -------------------------------------------------------------------------
    with tab_analytics:
        st.markdown("##### **📊 التحليل الإحصائي لأمان الجلسات والتغييرات الإدارية:**")

        a_col1, a_col2 = st.columns(2)
        with a_col1:
            st.markdown("###### **توزيع محاولات الدخول حسب الحالة:**")
            status_counts = (
                db.query(UserLoginHistory.status, func.count(UserLoginHistory.id))
                .group_by(UserLoginHistory.status)
                .all()
            )
            if status_counts:
                st_df = pd.DataFrame([
                    {"الحالة": LOGIN_STATUS_META.get(st_key, {}).get("label_ar", st_key), "العدد": cnt}
                    for st_key, cnt in status_counts
                ])
                st.dataframe(st_df, use_container_width=True, hide_index=True)
            else:
                st.info("لا توجد بيانات تسجيل دخول كافية للتحليل الإحصائي.")

        with a_col2:
            st.markdown("###### **توزيع تغييرات الإعدادات حسب التصنيف:**")
            cat_counts = (
                db.query(ConfigurationChangeLog.config_category, func.count(ConfigurationChangeLog.id))
                .group_by(ConfigurationChangeLog.config_category)
                .all()
            )
            if cat_counts:
                cat_df = pd.DataFrame([
                    {"التصنيف": CONFIG_CATEGORIES.get(cat_k, {}).get("label", cat_k), "عدد التعديلات": cnt}
                    for cat_k, cnt in cat_counts
                ])
                st.dataframe(cat_df, use_container_width=True, hide_index=True)
            else:
                st.info("لا توجد تغييرات إعدادات كافية للتحليل الإحصائي.")
