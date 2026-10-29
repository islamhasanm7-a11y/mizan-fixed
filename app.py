"""
MizanPro - Enterprise Financial, Inventory (WAC), Treasury, Fixed Assets, Payroll, Aging, Bank Rec, CPA Audit Suite & ZATCA Platform
النظام المالي المتكامل - ميزان برو (الإصدار المؤسسي المتكامل)
التطبيق الرئيسي الشامل لكافة المحركات المحاسبية والمخزنية والرقابية وباقة مكاتب المراجعة المعتمدة
"""

import importlib.util
import io
import os
import select
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request


from setup_env import check_installed_dependencies, provision_environment


def _run_streamlit_server_with_proxy() -> None:
    """Bind port 3000 immediately and proxy HTTP/WebSocket traffic to the local Streamlit worker."""
    port = int(os.environ.get("PORT", "3000"))
    internal_port = int(os.environ.get("STREAMLIT_INTERNAL_PORT", "8501"))

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", port))
    server_sock.listen(128)

    if check_installed_dependencies():
        provision_environment(use_lock=True)

    env = os.environ.copy()
    env["_MIZAN_STREAMLIT_WORKER"] = "1"
    env["BROWSER_GATHER_USAGE_STATS"] = "false"

    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        os.path.abspath(__file__),
        "--server.port",
        str(internal_port),
        "--server.address",
        "127.0.0.1",
        "--server.headless",
        "true",
        "--browser.gatherUsageStats",
        "false",
        "--server.enableCORS",
        "false",
        "--server.enableXsrfProtection",
        "false",
    ]
    worker_proc = subprocess.Popen(cmd, env=env)

    def _shutdown(signum, frame):
        try:
            server_sock.close()
        except OSError:
            pass
        if worker_proc.poll() is None:
            worker_proc.terminate()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    def _pipe(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _handle_client(client_sock: socket.socket) -> None:
        upstream_sock = None
        try:
            ready, _, _ = select.select([client_sock], [], [], 5.0)
            if not ready:
                return
            first_chunk = client_sock.recv(65536)
            if not first_chunk:
                return

            deadline = time.monotonic() + 30.0
            while True:
                try:
                    upstream_sock = socket.create_connection(("127.0.0.1", internal_port), timeout=2.0)
                    upstream_sock.settimeout(None)
                    break
                except OSError:
                    if time.monotonic() >= deadline or worker_proc.poll() is not None:
                        return
                    time.sleep(0.1)

            upstream_sock.sendall(first_chunk)
            t_up = threading.Thread(target=_pipe, args=(client_sock, upstream_sock), daemon=True)
            t_down = threading.Thread(target=_pipe, args=(upstream_sock, client_sock), daemon=True)
            t_up.start()
            t_down.start()
            t_up.join()
            t_down.join()
        except OSError:
            pass
        finally:
            try:
                client_sock.close()
            except OSError:
                pass
            if upstream_sock is not None:
                try:
                    upstream_sock.close()
                except OSError:
                    pass

    try:
        while worker_proc.poll() is None:
            ready, _, _ = select.select([server_sock], [], [], 0.5)
            if not ready:
                continue
            try:
                client_sock, _ = server_sock.accept()
                threading.Thread(target=_handle_client, args=(client_sock,), daemon=True).start()
            except OSError:
                break
    finally:
        try:
            server_sock.close()
        except OSError:
            pass
        if worker_proc.poll() is None:
            worker_proc.terminate()
            try:
                worker_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                worker_proc.kill()
        sys.exit(worker_proc.returncode or 0)


if __name__ == "__main__" and os.environ.get("_MIZAN_STREAMLIT_WORKER") != "1":
    _run_streamlit_server_with_proxy()

import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
from datetime import date, datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go

from database import SessionLocal, BASE_DIR, create_sanitized_backup_bytes
from models import (
    Account, JournalEntry, EntryStatus, DocumentType,
    Customer, Supplier, Product, InventoryTransaction,
    SalesInvoice, PurchaseInvoice, CreditDebitNote,
    CashVoucher, PaymentMethod, InvoiceType, NoteType,
    VoucherType, VoucherPartyType, CostCenter, FixedAsset,
    Employee, PayrollRun, AppUser, UserRole, TBMappingProfile, AuditLog,
    CustomRoleTemplate, Warehouse, WarehouseStock, SYSTEM_MODULES, MODULE_LABEL_TO_KEY, SYSTEM_ACTIONS,
    ALL_PERMISSION_KEYS, get_default_permissions_for_role, verify_pin_code,
    AUDIT_TRANSACTION_TYPES, classify_audit_transaction_type, get_audit_transaction_type_label, compute_audit_entry_hash
)
import base64
import sqlite3
import shutil
import tempfile
import json
from seed_coa import init_database_and_seed, get_initial_admin_bootstrap_pin
from ledger_service import LedgerService, LedgerValidationError
from financial_engine import FinancialStatementsEngine, ExportService
from export_service import ExcelExportService, PrintTemplateService
from tb_analyzer_service import ExternalTBAnalyzerService, CPA_CATEGORIES, AUDIT_OPINION_TYPES
from google_drive_service import GoogleDriveService, SCOPES as GOOGLE_DRIVE_SCOPES
from zatca_phase2_validator import ZATCAPhase2Validator, ZATCA_TLV_TAG_SPECS
from zatca_qr_tlv import (
    ZATCATLVQRGenerator,
    decode_zatca_tlv_qr_base64,
    format_zatca_timestamp,
    generate_zatca_tlv_qr_base64,
)


# =============================================================================
# 1. إعدادات الصفحة والتصميم العربي الاحترافي
# =============================================================================
st.set_page_config(
    page_title="MizanPro ERP & CPA Suite | ميزان برو المتكامل",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="expanded"
)


@st.cache_resource
def ensure_db_initialized():
    """تهيئة وترقية قاعدة البيانات مرة واحدة فقط عند إقلاع السيرفر لضمان السرعة الفائقة"""
    init_database_and_seed(seed_demo_data=False)
    return True


ensure_db_initialized()

st.markdown("""
<style>
    html, body, .stMarkdown, p, h1, h2, h3, h4, h5, h6, span, label, input, button, select {
        font-family: 'Cairo', 'Segoe UI', Tahoma, sans-serif !important;
    }

    .stApp {
        background-color: #F8FAFC;
        direction: rtl;
        text-align: right;
    }

    [data-testid="stIconMaterial"], [class*="material-symbols"], [class*="material-icons"] {
        font-family: "Material Symbols Rounded", "Material Icons" !important;
        direction: ltr !important;
    }

    .stExpander svg {
        direction: ltr !important;
    }

    .main-header {
        background: linear-gradient(135deg, #1E3A8A 0%, #0F172A 100%);
        color: white;
        padding: 22px 26px;
        border-radius: 12px;
        margin-bottom: 22px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }

    .kpi-card {
        background: white;
        padding: 16px;
        border-radius: 10px;
        border-right: 5px solid #3B82F6;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        margin-bottom: 14px;
    }

    .kpi-title {
        color: #64748B;
        font-size: 13px;
        font-weight: 600;
        margin-bottom: 5px;
    }

    .kpi-value {
        color: #0F172A;
        font-size: 21px;
        font-weight: 700;
    }

    .balanced-badge {
        background-color: #DCFCE7;
        color: #166534;
        padding: 8px 16px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 14px;
        display: inline-block;
        border: 1px solid #86EFAC;
    }

    div[data-testid="stMetricValue"] {
        font-size: 22px !important;
    }
</style>
""", unsafe_allow_html=True)


def get_db_session():
    """الحصول على جلسة قاعدة بيانات آمنة مع ربطها التلقائي بمعرف المستخدم النشط (User ID) لسجل التدقيق الرقابي"""
    sess = SessionLocal()
    u_info = st.session_state.get("active_user_info")
    if isinstance(u_info, dict) and u_info.get("id"):
        sess.info["user_id"] = f"USR-{int(u_info['id']):03d}"
        sess.info["username"] = str(u_info.get("username") or "admin")
        sess.info["performed_by"] = f"{u_info.get('full_name_ar', 'مدير النظام')} ({u_info.get('username', 'admin')})"
    return sess


# =============================================================================
# 2. بوابة تسجيل الدخول الإلزامي وإدارة الجلسة الآمنة (Mandatory Auth Gate)
# =============================================================================
db_auth = get_db_session()
try:
    company_cfg = LedgerService.get_company_settings(db_auth)
    comp_name_display = company_cfg.company_name_ar
    comp_vat_display = company_cfg.vat_number
    comp_year_display = company_cfg.fiscal_year

    auth_user_id = st.session_state.get("authenticated_user_id")
    authenticated_user = None
    if auth_user_id:
        authenticated_user = db_auth.query(AppUser).filter(
            AppUser.id == int(auth_user_id),
            AppUser.is_active == True
        ).first()
        if not authenticated_user:
            st.session_state.pop("authenticated_user_id", None)
            st.session_state.pop("active_user", None)
            st.session_state.pop("active_user_info", None)

    if not authenticated_user:
        st.markdown(f"""
        <div class="main-header" style="text-align:center;">
            <h2 style="margin:0; color:white;">🔐 بوابة الدخول الآمن الإلزامي - {comp_name_display}</h2>
            <p style="margin:6px 0 0 0; color:#CBD5E1; font-size:14px;">نظام MizanPro ERP & CPA محمي بالكامل — يرجى تسجيل الدخول باسم المستخدم ورمز الدخول السري (PIN)</p>
        </div>
        """, unsafe_allow_html=True)

        bootstrap_pin = get_initial_admin_bootstrap_pin()
        admin_obj = db_auth.query(AppUser).filter(AppUser.username == "admin").first()
        if bootstrap_pin and admin_obj and admin_obj.must_change_pin:
            st.warning(
                f"🛡️ **تنبيه أمني لإعداد النظام لأول مرة (أو بعد تدوير الرموز المكشوفة):**\n\n"
                f"- اسم مستخدم المدير: `admin`\n"
                f"- رمز الدخول العشوائي المؤقت لمرة واحدة: **`{bootstrap_pin}`**\n\n"
                f"*سيُطلب منك إلزامياً تغيير هذا الرمز فور تسجيل الدخول الأول، وسيتم مسح هذا الإشعار نهائياً.*"
            )

        _, login_col, _ = st.columns([1, 1.4, 1])
        with login_col:
            with st.form("mandatory_login_form", clear_on_submit=False):
                st.markdown("#### **🔑 تسجيل الدخول للنظام المالي**")
                in_login_user = st.text_input("اسم المستخدم (Username):", placeholder="أدخل اسم المستخدم الخاص بك")
                in_login_pin = st.text_input("رمز الدخول السري (PIN):", type="password", placeholder="أدخل رمز الـ PIN السري")
                submit_login = st.form_submit_button("🔐 تسجيل الدخول الآمن", type="primary", use_container_width=True)

                if submit_login:
                    try:
                        logged_u = LedgerService.authenticate_user(db_auth, in_login_user, in_login_pin)
                        st.session_state["authenticated_user_id"] = logged_u.id
                        st.success(f"✅ مرحباً بك ({logged_u.full_name_ar})!")
                        st.rerun()
                    except Exception as ex_auth:
                        st.error(f"❌ {ex_auth}")
        st.stop()

    # فرض تغيير رمز الدخول السري عند أول دخول (أو بعد تدوير الرموز) قبل السماح بأي شاشة
    if authenticated_user.must_change_pin:
        st.markdown(f"""
        <div class="main-header" style="text-align:center; background: linear-gradient(135deg, #991B1B 0%, #450A0A 100%);">
            <h2 style="margin:0; color:white;">🔒 تغيير رمز الدخول السري الإلزامي عند أول دخول</h2>
            <p style="margin:6px 0 0 0; color:#FECACA; font-size:14px;">مرحباً ({authenticated_user.full_name_ar}) — لحماية البيانات المالية، يجب تعيين رمز سري جديد خاص بك قبل استخدام النظام</p>
        </div>
        """, unsafe_allow_html=True)

        _, chg_col, _ = st.columns([1, 1.4, 1])
        with chg_col:
            with st.form("mandatory_first_pin_change_form"):
                st.markdown("#### **🔑 تعيين رمز دخول سري جديد (6 أرقام قوية)**")
                curr_pin_in = st.text_input("رمز الدخول الحالي (المؤقت):", type="password")
                new_pin_in = st.text_input("رمز الدخول السري الجديد (6 أرقام غير متكررة):", type="password")
                conf_pin_in = st.text_input("تأكيد رمز الدخول السري الجديد:", type="password")
                sub_chg = st.form_submit_button("💾 حفظ الرمز السري الجديد وتفعيل الحساب", type="primary", use_container_width=True)

                if sub_chg:
                    if new_pin_in != conf_pin_in:
                        st.error("❌ رمز الدخول الجديد وتأكيده غير متطابقين.")
                    else:
                        try:
                            LedgerService.change_user_pin(
                                db=db_auth,
                                user_id=authenticated_user.id,
                                current_pin=curr_pin_in,
                                new_pin=new_pin_in,
                                performed_by=authenticated_user.full_name_ar
                            )
                            st.success("✅ تم تحديث رمز الدخول السري بنجاح وتفعيل حسابك!")
                            st.rerun()
                        except Exception as ex_pin:
                            st.error(f"❌ {ex_pin}")
            if st.button("🚪 تسجيل الخروج", use_container_width=True):
                st.session_state.pop("authenticated_user_id", None)
                st.rerun()
        st.stop()

    active_user_info = {
        "id": authenticated_user.id,
        "username": authenticated_user.username,
        "full_name_ar": authenticated_user.full_name_ar,
        "job_title": authenticated_user.job_title or "مسؤول مالي",
        "role": authenticated_user.role.value,
        "max_discount_pct": float(authenticated_user.max_discount_pct if authenticated_user.max_discount_pct is not None else 100.0),
        "permissions": authenticated_user.get_permissions(),
        "allowed_menus": authenticated_user.get_allowed_menu_options() or [SYSTEM_MODULES["mod_dashboard"]],
    }
    st.session_state["active_user"] = active_user_info["full_name_ar"]
    st.session_state["active_user_info"] = active_user_info
finally:
    db_auth.close()


def has_perm(perm_key: str) -> bool:
    """التحقق السريع من صلاحية المستخدم النشط لأي عملية أو إجراء"""
    u_info = st.session_state.get("active_user_info", {})
    return bool(u_info.get("permissions", {}).get(perm_key, False))


def get_active_user_label() -> str:
    return st.session_state.get("active_user", "مدير النظام (Admin)")


with st.sidebar:
    st.markdown("### ⚖️ **MizanPro ERP & CPA**")
    st.caption(f"**{comp_name_display}**")
    st.caption(f"الرقم الضريبي: `{comp_vat_display}`")

    curr_u = st.session_state["active_user_info"]
    st.success(f"👤 **{curr_u['full_name_ar']}** (`{curr_u['username']}`)")
    enabled_mods_cnt = sum(1 for k in SYSTEM_MODULES if curr_u["permissions"].get(k, False))
    enabled_acts_cnt = sum(1 for k in SYSTEM_ACTIONS if curr_u["permissions"].get(k, False))
    st.caption(
        f"💼 **{curr_u['job_title']}** | الصلاحيات: `{enabled_mods_cnt}/{len(SYSTEM_MODULES)}` شاشة و `{enabled_acts_cnt}/{len(SYSTEM_ACTIONS)}` عملية | سقف الخصم: `{curr_u['max_discount_pct']:.0f}%`"
    )

    sb_c1, sb_c2 = st.columns(2)
    with sb_c1:
        if st.button("🚪 خروج آمن", use_container_width=True):
            st.session_state.pop("authenticated_user_id", None)
            st.session_state.pop("active_user", None)
            st.session_state.pop("active_user_info", None)
            st.rerun()
    with sb_c2:
        with st.popover("🔑 تغيير PIN"):
            old_p = st.text_input("الرمز الحالي:", type="password", key="sb_old_pin")
            new_p = st.text_input("الرمز الجديد (6 أرقام):", type="password", key="sb_new_pin")
            if st.button("تحديث الرمز", type="primary", use_container_width=True):
                _db_p = get_db_session()
                try:
                    LedgerService.change_user_pin(_db_p, curr_u["id"], old_p, new_p, performed_by=curr_u["full_name_ar"])
                    st.success("✅ تم تغيير الرمز!")
                except Exception as e_p:
                    st.error(f"❌ {e_p}")
                finally:
                    _db_p.close()

    st.divider()

    allowed_menu_list = curr_u["allowed_menus"]
    menu_option = st.radio(
        "الوحدات والقوائم المتاحة حسب صلاحياتك:",
        allowed_menu_list,
        index=0
    )

    st.divider()
    can_cloud_backup = has_perm("act_cloud_backup")
    if can_cloud_backup:
        show_global_gdrive = st.checkbox("☁️ فتح مركز Google Drive السحابي في أعلى الشاشة", value=False, key="chk_global_gdrive")
        try:
            sanitized_db_bytes = create_sanitized_backup_bytes()
            if sanitized_db_bytes:
                st.download_button(
                    label="💾 نسخ احتياطي آمن لقاعدة البيانات (.db - مطهر من الرموز)",
                    data=sanitized_db_bytes,
                    file_name=f"mizanpro_sanitized_backup_{date.today()}.db",
                    mime="application/octet-stream",
                    use_container_width=True
                )
        except Exception:
            pass
    else:
        show_global_gdrive = False
        st.caption("🔒 مركز Google Drive والنسخ الاحتياطي لقاعدة البيانات مقيد بصلاحية (`act_cloud_backup`).")
    st.caption(f"السنة المالية: `{comp_year_display}` | IFRS / SOCPA / ZATCA")


def render_google_drive_hub_section(
    db,
    cpa_word_bytes: bytes = b"",
    cpa_word_filename: str = "CPA_Audited_Financial_Statements_2026.doc",
    height: int = 540
) -> None:
    """تجهيز الحزم المالية المشفرة (Base64) وعرض واجهة التكامل السحابي مع Google Drive للمخولين فقط"""
    if not has_perm("act_cloud_backup"):
        st.info("🔒 الوصول لمركز Google Drive السحابي ومزامنة النسخ الاحتياطية يتطلب صلاحية مستقلة (`act_cloud_backup`).")
        return

    try:
        cfg_gd = LedgerService.get_company_settings(db)
        excel_io = ExcelExportService.generate_master_excel_report(db, fiscal_year=cfg_gd.fiscal_year)
        excel_b64 = base64.b64encode(excel_io.getvalue()).decode("utf-8")
        excel_fname = f"MizanPro_Master_Financial_Report_{cfg_gd.fiscal_year}_15_Sheets.xlsx"
    except Exception:
        excel_b64 = ""
        excel_fname = "MizanPro_Executive_Report_2026.xlsx"

    if not cpa_word_bytes:
        try:
            sample_tb_gd = ExternalTBAnalyzerService.get_sample_tasaheel_tb_dataframe()
            c_df_gd = ExternalTBAnalyzerService.normalize_and_classify_tb(sample_tb_gd)
            pkg_gd = ExternalTBAnalyzerService.generate_cpa_full_package(c_df_gd, {"company_name": cfg_gd.company_name_ar})
            cpa_word_bytes = ExternalTBAnalyzerService.generate_cpa_word_doc(pkg_gd)
        except Exception:
            cpa_word_bytes = b""

    word_b64 = base64.b64encode(cpa_word_bytes).decode("utf-8") if cpa_word_bytes else ""

    db_b64 = ""
    try:
        clean_db_bytes = create_sanitized_backup_bytes()
        if clean_db_bytes:
            db_b64 = base64.b64encode(clean_db_bytes).decode("utf-8")
    except Exception:
        db_b64 = ""

    gdrive_html = GoogleDriveService.render_google_drive_workspace_html(
        excel_report_b64=excel_b64,
        excel_filename=excel_fname,
        cpa_word_b64=word_b64,
        cpa_word_filename=cpa_word_filename,
        db_backup_b64=db_b64,
        db_backup_filename=f"MizanPro_Sanitized_Backup_{date.today()}.db"
    )
    components.html(gdrive_html, height=height, scrolling=True)


if show_global_gdrive and menu_option != "📊 لوحة التحكم والمؤشرات":
    _db_gd = get_db_session()
    try:
        render_google_drive_hub_section(_db_gd, height=520)
    finally:
        _db_gd.close()


def render_readonly_zatca_audit_log_module(db, key_prefix: str = "zatca_audit") -> None:
    """
    واجهة سجل الرقابة والتدقيق الإلزامي للقراءة فقط (Read-Only ZATCA Audit Log UI Module)
    تتيح للمستخدمين المخولين فقط (مدير النظام، المراجع القانوني CPA، أو حاملي صلاحية act_view_audit_logs)
    فلترة واستعراض سجلات التدقيق حسب نطاق التاريخ (Date Range)، المستخدم (User)، أو نوع المعاملة (Transaction Type)
    مع التحقق التشفيري الكامل (SHA-256 Chain) ومقارنة القيم قبل وبعد التعديل (Before/After State Diff) بدون أي إمكانية للتعديل أو الحذف.
    """
    u_info = st.session_state.get("active_user_info", {})
    is_authorized = (
        has_perm("act_view_audit_logs")
        or has_perm("mod_audit_log")
        or LedgerService.is_user_authorized_for_audit_logs(db, u_info)
    )
    if not is_authorized:
        st.error(
            "🔒 **وصول مقيد (ZATCA Audit Access Control):** عذراً، وحدة سجل التدقيق الرقابي للقراءة فقط متاحة حصرياً "
            "للمستخدمين المخولين (مدير النظام `ADMIN`، المراجع القانوني `AUDITOR`، أو حاملي صلاحية `act_view_audit_logs`)."
        )
        return

    st.markdown("""
    <div style="background: linear-gradient(135deg, #0F172A 0%, #1E293B 100%); color: white; padding: 18px 22px; border-radius: 12px; border-right: 6px solid #10B981; margin-bottom: 16px;">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
            <div>
                <h4 style="margin:0; color:#F8FAFC;">🛡️ وحدة سجل الرقابة والتدقيق الإلزامي للقراءة فقط (ZATCA Read-Only Audit Trail Module)</h4>
                <p style="margin:5px 0 0 0; color:#CBD5E1; font-size:13px;">
                    سجل رقابي غير قابل للتعديل أو الحذف (Append-Only / Immutable) يوثق كافة المعاملات المالية والتعديلات مع الطابع الزمني العالمي (UTC Timestamp) ومعرف المستخدم (User ID) وسلسلة التشفير المترابطة (SHA-256 Hash Chain).
                </p>
            </div>
            <div style="background:#065F46; color:#D1FAE5; padding:6px 14px; border-radius:20px; font-size:12px; font-weight:700; border:1px solid #34D399;">
                🔒 وضع القراءة فقط مفعل (Read-Only Enforced)
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    integrity_rep = LedgerService.verify_audit_log_integrity(db)
    am1, am2, am3, am4 = st.columns(4)
    am1.metric("إجمالي السجلات الرقابية بالقاعدة", f"{integrity_rep['total_records']}")
    am2.metric(
        "حالة الحماية للقراءة فقط (Read-Only)",
        "مفعل (SQLite Triggers + ORM) 🔒" if integrity_rep["is_read_only_enforced"] else "غير مفعل ⚠️"
    )
    am3.metric(
        "سلامة سلسلة التشفير (SHA-256 Chain)",
        "سليمة 100% ✅" if integrity_rep["is_intact"] else f"خلل ({len(integrity_rep['broken_chain_links'])}) ❌"
    )
    am4.metric(
        "اكتمال الهوية والطابع الزمني",
        "مكتمل 100% ✅" if (integrity_rep["missing_user_ids"] + integrity_rep["missing_timestamps"]) == 0
        else f"نواقص ({integrity_rep['missing_user_ids'] + integrity_rep['missing_timestamps']}) ⚠️"
    )

    st.info(
        f"🔐 **حالة الامتثال الرقابي لهيئة الزكاة والضريبة والجمارك (ZATCA):** {integrity_rep['status_ar']}  \n"
        f"🔗 **آخر بصمة تشفيرية للسجل (`Latest SHA-256 Chain Hash`):** `{integrity_rep['latest_chain_hash']}`"
    )

    # استعلام مبدئي لجلب قوائم الفلترة المتاحة ونطاق التواريخ في قاعدة البيانات
    base_meta = LedgerService.query_audit_logs(db=db, requesting_user=u_info, limit=1000)
    f_opts = base_meta["filter_options"]
    min_db_d: date = f_opts["min_date"]
    max_db_d: date = max(f_opts["max_date"], date.today())

    st.markdown("##### **🔎 محرك الفلترة الرقابية المتقدم (حسب نطاق التاريخ، المستخدم، ونوع المعاملة المالية):**")
    with st.container(border=True):
        r1_c1, r1_c2, r1_c3, r1_c4 = st.columns([1.15, 1.0, 1.0, 1.35])
        with r1_c1:
            date_preset = st.selectbox(
                "📅 النطاق الزمني السريع:",
                [
                    "الكل (جميع التواريخ المسجلة)",
                    "تخصيص نطاق تاريخ محدد (من - إلى)",
                    "اليوم فقط",
                    "آخر 7 أيام",
                    "آخر 30 يوماً",
                    "الشهر الحالي",
                    "السنة الحالية",
                ],
                index=0,
                key=f"{key_prefix}_date_preset",
            )

        today_d = date.today()
        if date_preset == "اليوم فقط":
            default_start, default_end = today_d, today_d
        elif date_preset == "آخر 7 أيام":
            default_start, default_end = today_d - timedelta(days=7), today_d
        elif date_preset == "آخر 30 يوماً":
            default_start, default_end = today_d - timedelta(days=30), today_d
        elif date_preset == "الشهر الحالي":
            default_start, default_end = date(today_d.year, today_d.month, 1), today_d
        elif date_preset == "السنة الحالية":
            default_start, default_end = date(today_d.year, 1, 1), date(today_d.year, 12, 31)
        else:
            default_start, default_end = min_db_d, max_db_d

        with r1_c2:
            sel_start_date = st.date_input(
                "من تاريخ (Start Date):",
                value=default_start,
                key=f"{key_prefix}_start_date",
                disabled=(date_preset == "الكل (جميع التواريخ المسجلة)"),
            )
        with r1_c3:
            sel_end_date = st.date_input(
                "إلى تاريخ (End Date):",
                value=default_end,
                key=f"{key_prefix}_end_date",
                disabled=(date_preset == "الكل (جميع التواريخ المسجلة)"),
            )

        tx_type_map: Dict[str, str] = f_opts["transaction_types"]
        tx_labels_list = list(tx_type_map.values())
        tx_label_to_key = {v: k for k, v in tx_type_map.items()}
        with r1_c4:
            sel_tx_label = st.selectbox(
                "📂 فلترة حسب نوع المعاملة المالية (Transaction Type):",
                tx_labels_list,
                index=0,
                key=f"{key_prefix}_tx_type",
            )
            sel_tx_key = tx_label_to_key.get(sel_tx_label, "ALL")

        r2_c1, r2_c2, r2_c3, r2_c4 = st.columns([1.2, 1.1, 1.1, 1.4])
        with r2_c1:
            sel_user_filter = st.selectbox(
                "👤 فلترة حسب المستخدم (User ID / Username):",
                f_opts["users"],
                index=0,
                key=f"{key_prefix}_user_filter",
            )
        with r2_c2:
            sel_table_filter = st.selectbox(
                "🗃️ فلترة حسب الجدول المالي (Table):",
                f_opts["tables"],
                index=0,
                key=f"{key_prefix}_table_filter",
            )
        with r2_c3:
            sel_action_filter = st.selectbox(
                "⚡ فلترة حسب رمز الإجراء (Action):",
                f_opts["actions"],
                index=0,
                key=f"{key_prefix}_action_filter",
            )
        with r2_c4:
            audit_search_q = st.text_input(
                "🔍 بحث برقم المستند أو البصمة أو التفاصيل:",
                placeholder="مثال: INV-2026 أو JV-2026 أو USR-001 أو SHA-256",
                key=f"{key_prefix}_search_q",
            )

        r3_c1, r3_c2, _ = st.columns([1.2, 1.5, 2.0])
        with r3_c1:
            min_fin_amt = st.number_input(
                "💰 الحد الأدنى للمبلغ المالي (ريال):",
                min_value=0.0,
                value=0.0,
                step=100.0,
                key=f"{key_prefix}_min_amt",
            )
        with r3_c2:
            st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
            only_mods_flag = st.checkbox(
                "🔄 عرض عمليات التعديل وعكس القيود فقط (Modifications & Reversals Only)",
                value=False,
                key=f"{key_prefix}_only_mods",
            )

    effective_start = None if date_preset == "الكل (جميع التواريخ المسجلة)" else sel_start_date
    effective_end = None if date_preset == "الكل (جميع التواريخ المسجلة)" else sel_end_date

    if effective_start and effective_end and effective_start > effective_end:
        st.warning("⚠️ تاريخ البداية أكبر من تاريخ النهاية؛ تم تبديل التواريخ تلقائياً لعرض النطاق الصحيح.")
        effective_start, effective_end = effective_end, effective_start

    query_res = LedgerService.query_audit_logs(
        db=db,
        start_date=effective_start,
        end_date=effective_end,
        user_filter=sel_user_filter,
        transaction_type=sel_tx_key,
        table_name=sel_table_filter,
        action=sel_action_filter,
        search_query=audit_search_q,
        min_amount=min_fin_amt,
        only_modifications=only_mods_flag,
        requesting_user=u_info,
        limit=1000,
    )

    q_summary = query_res["summary"]
    audit_df: pd.DataFrame = query_res["dataframe"]
    matched_records = query_res["records"]

    # بطاقات ملخص نتائج الفلترة
    km1, km2, km3, km4 = st.columns(4)
    km1.metric("عدد السجلات المطابقة للفلترة", f"{q_summary['total_matched']} / {q_summary['total_in_database']}")
    km2.metric("إجمالي القيمة المالية للسجلات المفلترة", f"{q_summary['total_financial_volume']:,.2f} ريال")
    km3.metric("عمليات التعديل وعكس القيود المرصودة", f"{q_summary['modifications_count']}")
    km4.metric("عدد المستخدمين الفاعلين في النطاق", f"{q_summary['unique_users_count']}")

    period_caption = (
        f"من `{effective_start}` إلى `{effective_end}`"
        if (effective_start and effective_end)
        else "جميع التواريخ المسجلة"
    )
    st.caption(
        f"📌 **معايير الفلترة المطبقة (Read-Only View):** النطاق الزمني: {period_caption} | "
        f"نوع المعاملة: `{sel_tx_label}` | المستخدم: `{sel_user_filter}` | الجدول: `{sel_table_filter}` | الإجراء: `{sel_action_filter}`"
    )

    if audit_df.empty:
        st.warning("لا توجد سجلات تدقيق مطابقة لمعايير الفلترة المحددة حالياً.")
        return

    # جدول السجلات الرقابية للقراءة فقط
    st.dataframe(audit_df, use_container_width=True, hide_index=True)

    # إعداد وتصدير تقرير PDF المؤمّن وغير القابل للتعديل لمراجعة المدقق الخارجي ومفتشي ZATCA
    st.markdown("##### **📄 تصدير وتوثيق سجل التدقيق الرقابي للمراجع الخارجي (Immutable PDF, Signed JSON & CSV):**")
    auditor_notes_in = st.text_input(
        "📝 ملاحظات أو توصيات المراجع القانوني الخارجي لتضمينها وختمها داخل وثيقة الـ PDF (اختياري):",
        value="تم فحص ومطابقة سجل التدقيق الرقابي للقراءة فقط والتحقق من سلامة سلسلة التجزئة التشفيرية SHA-256 وفق متطلبات ZATCA.",
        key=f"{key_prefix}_auditor_pdf_notes",
    )

    immutable_pdf_bytes = LedgerService.export_immutable_audit_pdf(
        db=db,
        start_date=effective_start,
        end_date=effective_end,
        user_filter=sel_user_filter,
        transaction_type=sel_tx_key,
        table_name=sel_table_filter,
        action=sel_action_filter,
        search_query=audit_search_q,
        min_amount=min_fin_amt,
        only_modifications=only_mods_flag,
        requesting_user=u_info,
        auditor_notes=auditor_notes_in,
        limit=1000,
    )
    pdf_verification_info = LedgerService.verify_immutable_audit_pdf(immutable_pdf_bytes)

    dl_col1, dl_col2, dl_col3 = st.columns([1.6, 1.3, 1.3])
    with dl_col1:
        st.download_button(
            "📄 تصدير تقرير التدقيق بصيغة PDF غير قابلة للتعديل (Immutable Auditor PDF)",
            data=immutable_pdf_bytes,
            file_name=f"ZATCA_Immutable_Audit_Log_{pdf_verification_info.get('document_id', date.today())}.pdf",
            mime="application/pdf",
            type="primary",
            use_container_width=True,
            key=f"{key_prefix}_dl_immutable_pdf",
        )
    with dl_col2:
        csv_audit_bytes = audit_df.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "📥 تصدير السجل المفلتر (ZATCA Audit CSV)",
            data=csv_audit_bytes,
            file_name=f"ZATCA_ReadOnly_Audit_Log_{date.today()}.csv",
            mime="text/csv",
            use_container_width=True,
            key=f"{key_prefix}_dl_csv",
        )
    with dl_col3:
        json_export_payload = {
            "report_title": "ZATCA Read-Only Cryptographic Audit Trail Export",
            "generated_at_utc": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "integrity_verification": {
                "is_intact": integrity_rep["is_intact"],
                "is_read_only_enforced": integrity_rep["is_read_only_enforced"],
                "latest_chain_hash": integrity_rep["latest_chain_hash"],
            },
            "pdf_document_seal": {
                "document_id": pdf_verification_info.get("document_id"),
                "core_pdf_sha256": pdf_verification_info.get("core_pdf_sha256"),
                "manifest_seal_sha256": pdf_verification_info.get("manifest_seal_sha256"),
                "records_digest_sha256": pdf_verification_info.get("records_digest_sha256"),
            },
            "summary": q_summary,
            "records": matched_records,
        }
        json_audit_bytes = json.dumps(json_export_payload, ensure_ascii=False, indent=2).encode("utf-8")
        st.download_button(
            "🔐 تصدير الحزمة التشفيرية (Signed Audit JSON)",
            data=json_audit_bytes,
            file_name=f"ZATCA_Cryptographic_Audit_Trail_{date.today()}.json",
            mime="application/json",
            use_container_width=True,
            key=f"{key_prefix}_dl_json",
        )

    st.success(
        f"🔒 **بيانات الختم التشفيري لوثيقة PDF المولّدة (`{pdf_verification_info.get('document_id')}`):**  \n"
        f"- **حالة القفل وعدم القابلية للتعديل:** `{pdf_verification_info.get('permissions_mode')}` — {pdf_verification_info.get('status_ar')}  \n"
        f"- **بصمة صفحات الـ PDF (`Core PDF SHA-256`):** `{pdf_verification_info.get('core_pdf_sha256')}`  \n"
        f"- **الختم التشفيري للوثيقة (`Manifest Seal SHA-256`):** `{pdf_verification_info.get('manifest_seal_sha256')}`"
    )

    with st.expander("🖨️ **معاينة النسخة الرسمية القابلة للطباعة والاعتماد للمراجع القانوني الخارجي (Printable External Auditor Report)**", expanded=False):
        printable_audit_html = PrintTemplateService.generate_audit_log_printable_html(
            db=db,
            start_date=effective_start,
            end_date=effective_end,
            user_filter=sel_user_filter,
            transaction_type=sel_tx_key,
            table_name=sel_table_filter,
            action=sel_action_filter,
            search_query=audit_search_q,
            min_amount=min_fin_amt,
            only_modifications=only_mods_flag,
            requesting_user=u_info,
            auditor_notes=auditor_notes_in,
            limit=250,
        )
        components.html(printable_audit_html, height=580, scrolling=True)

    with st.expander("🛡️ **أداة المراجع الخارجي للتحقق الجنائي من سلامة وعدم التلاعب بملف PDF المصدّر (External Auditor PDF Seal Verifier)**", expanded=False):
        st.caption(
            "يمكن للمراجع القانوني الخارجي (CPA) أو فاحص هيئة الزكاة والضريبة والجمارك (ZATCA) رفع أي ملف PDF مصدّر مسبقاً "
            "للتحقق فوراً من عدم تعرض أي بايت في صفحاته أو سجلاته لأي تعديل بعد إصداره."
        )
        up_pdf_file = st.file_uploader(
            "ارفع ملف تقرير التدقيق المصدّر (.pdf) لفحص ختمه التشفيري (أو اتركه فارغاً لفحص الوثيقة الحالية):",
            type=["pdf"],
            key=f"{key_prefix}_verify_pdf_upload",
        )
        target_verify_bytes = up_pdf_file.read() if up_pdf_file is not None else immutable_pdf_bytes
        v_res = LedgerService.verify_immutable_audit_pdf(target_verify_bytes)
        if v_res.get("is_tamper_free"):
            st.success(f"✅ **{v_res.get('status_ar')}**")
        else:
            st.error(f"❌ **{v_res.get('status_ar')}**")

        vc1, vc2, vc3 = st.columns(3)
        vc1.markdown(f"**معرف الوثيقة:** `{v_res.get('document_id', '-')}`")
        vc2.markdown(f"**الرقم الضريبي للمنشأة:** `{v_res.get('company_vat', '-')}`")
        vc3.markdown(f"**عدد السجلات الموثقة بالملف:** `{v_res.get('total_records_exported', 0)}` سجل")
        st.code(
            json.dumps(
                {
                    "document_id": v_res.get("document_id"),
                    "is_valid_pdf": v_res.get("is_valid_pdf"),
                    "is_immutable_sealed": v_res.get("is_immutable_sealed"),
                    "is_tamper_free": v_res.get("is_tamper_free"),
                    "permissions_mode": v_res.get("permissions_mode"),
                    "exported_at_utc": v_res.get("exported_at_utc"),
                    "exported_by": v_res.get("exported_by"),
                    "records_digest_sha256": v_res.get("records_digest_sha256"),
                    "core_pdf_sha256": v_res.get("core_pdf_sha256"),
                    "manifest_seal_sha256": v_res.get("manifest_seal_sha256"),
                },
                ensure_ascii=False,
                indent=2,
            ),
            language="json",
        )

    # ملخصات تحليلية حسب نوع المعاملة وحسب المستخدم
    with st.expander("📊 **التحليل الإحصائي للسجلات المفلترة حسب نوع المعاملة المالية وحسب المستخدم (Transparency Breakdown)**", expanded=False):
        b_col1, b_col2 = st.columns(2)
        with b_col1:
            st.markdown("###### **📂 توزيع العمليات حسب نوع المعاملة المالية:**")
            tx_summary_rows = [
                {
                    "نوع المعاملة المالية": item["transaction_type_ar"],
                    "عدد السجلات": item["count"],
                    "إجمالي المبالغ (ريال)": f"{item['amount']:,.2f}",
                }
                for item in q_summary["by_transaction_type"]
            ]
            if tx_summary_rows:
                st.dataframe(pd.DataFrame(tx_summary_rows), use_container_width=True, hide_index=True)
        with b_col2:
            st.markdown("###### **👤 توزيع العمليات حسب المستخدم المسؤول (User Accountability):**")
            u_summary_rows = [
                {
                    "معرف المستخدم": item["user_id"],
                    "اسم الدخول": item["username"],
                    "الاسم الكامل": item["performed_by"],
                    "عدد العمليات": item["count"],
                    "إجمالي المبالغ (ريال)": f"{item['amount']:,.2f}",
                }
                for item in q_summary["by_user"]
            ]
            if u_summary_rows:
                st.dataframe(pd.DataFrame(u_summary_rows), use_container_width=True, hide_index=True)

    # الفاحص الجنائي التفصيلي للسجل ولقطة القيم قبل وبعد التعديل
    with st.expander("🔍 **الفاحص الجنائي للسجل: مقارنة القيم قبل وبعد التعديل (Before / After Snapshot) والتحقق من بصمة SHA-256**", expanded=True):
        rec_opts = {
            f"#{r['id']} | [{r['timestamp_utc']}] {r['user_id']} ({r['username']}) — {r['action']} | {r['transaction_type_ar']} ({r['reference_number']})": r
            for r in matched_records[:150]
        }
        if rec_opts:
            sel_rec_label = st.selectbox(
                "اختر سجل تدقيق لاستعراض تفاصيله الكاملة ولقطة البيانات:",
                list(rec_opts.keys()),
                key=f"{key_prefix}_inspect_rec",
            )
            sel_rec = rec_opts[sel_rec_label]

            ic1, ic2, ic3, ic4 = st.columns(4)
            ic1.markdown(f"**معرف المستخدم (`User ID`):** `{sel_rec['user_id']}` (`{sel_rec['username']}`)")
            ic2.markdown(f"**الطابع الزمني (`UTC`):** `{sel_rec['timestamp_utc']}`")
            ic3.markdown(f"**نوع المعاملة:** {sel_rec['transaction_type_ar']}")
            ic4.markdown(f"**المبلغ والمرجع:** `{sel_rec['financial_amount']:,.2f} ريال` | `{sel_rec['reference_number']}`")

            if sel_rec["changed_fields"]:
                st.markdown("###### **📋 جدول مقارنة الحقول المعدلة (Field-by-Field Modification Diff):**")
                diff_rows = []
                for fld in sel_rec["changed_fields"]:
                    before_v = sel_rec["old_values"].get(fld, "— (غير موجود / إنشاء)")
                    after_v = sel_rec["new_values"].get(fld, "—")
                    diff_rows.append({
                        "اسم الحقل المالي (Field)": fld,
                        "القيمة السابقة قبل التعديل (Before)": str(before_v),
                        "القيمة الجديدة بعد العملية (After)": str(after_v),
                        "حالة التغيير": "تعديل قيمة 🔄" if fld in sel_rec["old_values"] and fld in sel_rec["new_values"] else "إضافة/تحديث ➕",
                    })
                st.dataframe(pd.DataFrame(diff_rows), use_container_width=True, hide_index=True)

            sc1, sc2 = st.columns(2)
            with sc1:
                st.markdown("**⏪ القيم السابقة قبل التعديل (`old_values_json`):**")
                if sel_rec["old_values"]:
                    st.code(json.dumps(sel_rec["old_values"], ensure_ascii=False, indent=2), language="json")
                else:
                    st.caption("لا توجد قيم سابقة (عملية إنشاء أولية للمستند المالي).")
            with sc2:
                st.markdown("**⏩ القيم الجديدة بعد العملية (`new_values_json`):**")
                if sel_rec["new_values"]:
                    st.code(json.dumps(sel_rec["new_values"], ensure_ascii=False, indent=2), language="json")
                else:
                    st.caption(sel_rec["details"] or "-")

            st.markdown(
                f"🔗 **البصمة السابقة (`Previous Chain Hash`):** `{sel_rec['previous_hash']}`  \n"
                f"🛡️ **بصمة السجل الحالية (`Entry SHA-256 Hash`):** `{sel_rec['entry_hash']}` — "
                f"**{'مطابقة وسليمة تشفيرياً ✅' if sel_rec['is_hash_valid'] else 'تحذير: البصمة غير مطابقة ❌'}**"
            )


# =============================================================================
# 3. الشاشة 1: لوحة التحكم والمؤشرات التنفيذية (Executive Dashboard)
# =============================================================================
if menu_option == "📊 لوحة التحكم والمؤشرات":
    db = get_db_session()
    try:
        settings = LedgerService.get_company_settings(db)
        tb_df = LedgerService.get_live_trial_balance(db, include_zero_balances=True)
        engine = FinancialStatementsEngine(trial_balance_df=tb_df, fiscal_year=settings.fiscal_year, vat_rate=settings.default_vat_rate)
        report = engine.generate_full_financial_report()

        pnl = report["income_statement"]
        bs = report["balance_sheet"]
        vat = report["vat_return"]
        zakat = report["zakat_declaration"]
        cf = report["cash_flow_statement"]

        st.markdown(f"""
        <div class="main-header">
            <h2 style="margin:0; color:white;">لوحة المؤشرات والقيادة المالية التنفيذية - {settings.company_name_ar}</h2>
            <p style="margin:5px 0 0 0; color:#CBD5E1; font-size:14px;">متابعة لحظية للأداء المالي، السيولة، المخزون، الأصول، ضريبة القيمة المضافة، ووعاء الزكاة لعام {settings.fiscal_year}</p>
        </div>
        """, unsafe_allow_html=True)

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(f"""
            <div class="kpi-card" style="border-color:#1E3A8A;">
                <div class="kpi-title">إجمالي الأصول (Total Assets)</div>
                <div class="kpi-value">{bs['total_assets']:,.2f} <small style="font-size:12px;">ريال</small></div>
            </div>
            """, unsafe_allow_html=True)
        with c2:
            st.markdown(f"""
            <div class="kpi-card" style="border-color:#15803D;">
                <div class="kpi-title">صافي الإيرادات (Net Revenue)</div>
                <div class="kpi-value">{pnl['net_revenue']:,.2f} <small style="font-size:12px;">ريال</small></div>
            </div>
            """, unsafe_allow_html=True)
        with c3:
            st.markdown(f"""
            <div class="kpi-card" style="border-color:#0284C7;">
                <div class="kpi-title">صافي ربح الفترة (Net Profit)</div>
                <div class="kpi-value">{pnl['net_profit']:,.2f} <small style="font-size:12px;">ريال</small></div>
            </div>
            """, unsafe_allow_html=True)
        with c4:
            st.markdown(f"""
            <div class="kpi-card" style="border-color:#7C3AED;">
                <div class="kpi-title">صافي ضريبة القيمة المضافة (Net VAT)</div>
                <div class="kpi-value">{vat['net_vat_due']:,.2f} <small style="font-size:12px;">ريال</small></div>
            </div>
            """, unsafe_allow_html=True)

        c5, c6, c7, c8 = st.columns(4)
        with c5:
            st.markdown(f"""
            <div class="kpi-card" style="border-color:#0D9488;">
                <div class="kpi-title">النقدية والبنوك (Cash & Banks)</div>
                <div class="kpi-value">{cf['closing_cash_balance']:,.2f} <small style="font-size:12px;">ريال</small></div>
            </div>
            """, unsafe_allow_html=True)
        with c6:
            st.markdown(f"""
            <div class="kpi-card" style="border-color:#D97706;">
                <div class="kpi-title">قيمة المخزون الدفتري (Inventory)</div>
                <div class="kpi-value">{bs['current_assets']['inventory']:,.2f} <small style="font-size:12px;">ريال</small></div>
            </div>
            """, unsafe_allow_html=True)
        with c7:
            st.markdown(f"""
            <div class="kpi-card" style="border-color:#2563EB;">
                <div class="kpi-title">ذمم العملاء التجارية (Receivables)</div>
                <div class="kpi-value">{bs['current_assets']['net_trade_receivables']:,.2f} <small style="font-size:12px;">ريال</small></div>
            </div>
            """, unsafe_allow_html=True)
        with c8:
            st.markdown(f"""
            <div class="kpi-card" style="border-color:#B91C1C;">
                <div class="kpi-title">الزكاة الشرعية المستحقة (ZATCA)</div>
                <div class="kpi-value">{zakat['zakat_due']:,.2f} <small style="font-size:12px;">ريال</small></div>
            </div>
            """, unsafe_allow_html=True)

        g1, g2 = st.columns(2)
        with g1:
            st.markdown("##### **هيكل الأداء المالي (الإيرادات والتكاليف والربحية)**")
            fig_pnl = go.Figure(data=[
                go.Bar(name='صافي المبيعات', x=['الأداء المالي'], y=[pnl['net_revenue']], marker_color='#1E3A8A'),
                go.Bar(name='تكلفة المبيعات', x=['الأداء المالي'], y=[pnl['cost_of_sales']], marker_color='#E11D48'),
                go.Bar(name='المصاريف التشغيلية', x=['الأداء المالي'], y=[pnl['operating_expenses']['total']], marker_color='#F59E0B'),
                go.Bar(name='صافي الربح', x=['الأداء المالي'], y=[pnl['net_profit']], marker_color='#10B981')
            ])
            fig_pnl.update_layout(barmode='group', height=310, margin=dict(l=20, r=20, t=25, b=20))
            st.plotly_chart(fig_pnl, use_container_width=True)

        with g2:
            st.markdown("##### **توزيع الأصول والسيولة**")
            fig_assets = px.pie(
                values=[
                    max(0.0, bs['current_assets']['cash_and_equivalents']),
                    max(0.0, bs['current_assets']['net_trade_receivables']),
                    max(0.0, bs['current_assets']['inventory']),
                    max(0.0, bs['non_current_assets']['total'])
                ],
                names=['النقد والبنوك', 'العملاء والمدينون', 'المخزون السلعي', 'الأصول الثابتة'],
                color_discrete_sequence=['#10B981', '#3B82F6', '#F59E0B', '#64748B'],
                hole=0.42
            )
            fig_assets.update_layout(height=310, margin=dict(l=20, r=20, t=25, b=20))
            st.plotly_chart(fig_assets, use_container_width=True)

        st.divider()
        col_btn, col_stat = st.columns(2)
        with col_btn:
            if has_perm("act_export_reports"):
                excel_bytes = ExcelExportService.generate_master_excel_report(db, fiscal_year=settings.fiscal_year)
                st.download_button(
                    label="📥 تحميل التقرير المالي والرقابي الشامل للنظام (Excel - 15 صفحة)",
                    data=excel_bytes,
                    file_name=f"MizanPro_Master_Financial_Report_{settings.fiscal_year}_15_Sheets.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True,
                    type="primary"
                )
            else:
                st.info("🔒 صلاحية تصدير التقارير الشاملة (Excel) غير مفعلة لحسابك الحالي.")
        with col_stat:
            if bs['is_balanced']:
                st.markdown('<div class="balanced-badge">✅ الميزانية العمومية وميزان المراجعة متزنان 100%</div>', unsafe_allow_html=True)
            else:
                st.error(f"❌ يوجد فرق في اتزان الميزانية قدره: {bs['balance_difference']:,.2f}")

        st.divider()
        st.markdown("#### **☁️ التكامل السحابي المباشر مع Google Drive (حفظ ومزامنة التقارير والنسخ الاحتياطية):**")
        render_google_drive_hub_section(db, height=540)
    finally:
        db.close()


# =============================================================================
# 4. الشاشة 2: محلل ميزان المراجعة الخارجي وإصدار القوائم وتقرير المراجع والإيضاحات الـ 18
# =============================================================================
elif menu_option == "📑 محلل ميزان المراجعة الخارجي والإيضاحات المعتمدة (CPA)":
    st.markdown("""
    <div class="main-header">
        <h2 style="margin:0; color:white;">محلل ميزان المراجعة الخارجي ومصدر تقرير المراجع والقوائم المقارنة والإيضاحات الـ 18 المعتمدة</h2>
        <p style="margin:5px 0 0 0; color:#CBD5E1; font-size:14px;">ارفع أي ميزان مراجعة ليقوم النظام بتبويبه آلياً وإصدار (تقرير المراجع المستقل + القوائم الأربع المقارنة + الـ 18 إيضاحاً) وتصديرها بصيغ Word و PDF/HTML و Excel</p>
    </div>
    """, unsafe_allow_html=True)

    db = get_db_session()
    try:
        settings_cpa = LedgerService.get_company_settings(db)
        with st.expander("🏢 **بيانات المنشأة وإعدادات تقرير المراجع المستقل (ISA / SOCPA) وأرقام المقارنة**", expanded=False):
            mc1, mc2, mc3 = st.columns(3)
            with mc1:
                ext_comp_name = st.text_input("اسم المؤسسة / الشركة:", value=settings_cpa.company_name_ar)
                ext_legal_form = st.text_input("الكيان القانوني:", value="شركة ذات مسؤولية محدودة / مؤسسة")
                ext_city = st.text_input("المدينة / العنوان:", value=settings_cpa.address_ar or "المملكة العربية السعودية")
                ext_partner = st.text_input("اسم الشريك / المالك (إيضاح 12):", value="الشركاء / المالك")
            with mc2:
                ext_period = st.text_input("الفترة المالية الحالية:", value=f"السنة المالية المنتهية في 31 ديسمبر {settings_cpa.fiscal_year} م")
                ext_comp_period = st.text_input("عنوان فترة المقارنة:", value=f"العام السابق {settings_cpa.fiscal_year - 1} م")
                ext_cr = st.text_input("رقم السجل التجاري:", value=settings_cpa.cr_number or "")
                ext_unified = st.text_input("الرقم الموحد للمنشأة (700):", value="")
            with mc3:
                inc_auditor = st.checkbox("إدراج صفحة (تقرير المراجع المستقل) في التقرير", value=True)
                show_comp_cols = st.checkbox("عرض عمود أرقام سنة المقارنة في القوائم المالية", value=False)
                opinion_labels = {v: k for k, v in AUDIT_OPINION_TYPES.items()}
                sel_op_label = st.selectbox("نوع رأي المراجع القانوني:", list(opinion_labels.keys()), index=1)
                aud_office = st.text_input("اسم مكتب المحاسبة والمراجعة:", value="مكتب ميزان برو محاسبون ومراجعون قانونيون")
                aud_name = st.text_input("اسم المراجع المرخص ورقم الترخيص:", value="تركي بن عبد الله المحيميد - ترخيص (512)")

            ext_activity = st.text_input("نشاط المنشأة (إيضاح 1):", value="تعمل المؤسسة في مجال أنشطة المقاولات وتشييد المباني.")
            custom_aud_para = st.text_input("فقرة مخصصة إضافية في تقرير المراجع (اختياري):", value="")

        cpa_metadata = {
            "company_name": ext_comp_name,
            "legal_form": ext_legal_form,
            "city": ext_city,
            "period_text": ext_period,
            "comp_period_text": ext_comp_period,
            "cr_number": ext_cr,
            "unified_number": ext_unified,
            "partner_name": ext_partner,
            "activity": ext_activity,
            "include_auditor_report": inc_auditor,
            "show_comparative": show_comp_cols,
            "opinion_type": opinion_labels[sel_op_label],
            "auditor_office": aud_office,
            "auditor_name": aud_name,
            "auditor_license": aud_name,
            "custom_auditor_paragraph": custom_aud_para
        }

        up_col1, up_col2, up_col3, up_col4 = st.columns([2, 1.1, 1.1, 1.1])
        with up_col1:
            uploaded_tb_file = st.file_uploader(
                "📂 ارفع ملف ميزان المراجعة هنا (Excel `.xlsx` أو `.csv` بأي تخطيط أعمدة):",
                type=["xlsx", "xls", "csv"]
            )
        with up_col2:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("🧪 تحميل ميزان (مؤسسة تساهيل طيبة)", use_container_width=True, type="primary"):
                sample_raw = ExternalTBAnalyzerService.get_sample_tasaheel_tb_dataframe()
                st.session_state["ext_tb_classified_df"] = ExternalTBAnalyzerService.normalize_and_classify_tb(sample_raw)
                st.session_state["ext_tb_file_sig"] = "SAMPLE_TASAHEEL"
                st.success("✅ تم تحميل وتبويب ميزان مراجعة (مؤسسة تساهيل طيبة التجارية) بنجاح!")
                st.rerun()
        with up_col3:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("🔄 جلب ميزان دفاتر النظام الحية", use_container_width=True):
                live_tb_raw = LedgerService.get_live_trial_balance(db, include_zero_balances=False)
                if not live_tb_raw.empty:
                    live_mapped = pd.DataFrame({
                        "كود الحساب": live_tb_raw["Account Code"],
                        "اسم الحساب": live_tb_raw["Account Name"],
                        "مدين أول المدة": live_tb_raw["Opening Debit"],
                        "دائن أول المدة": live_tb_raw["Opening Credit"],
                        "حركة مدين": live_tb_raw["Period Debit"],
                        "حركة دائن": live_tb_raw["Period Credit"],
                        "مدين آخر المدة": live_tb_raw["Closing Debit"],
                        "دائن آخر المدة": live_tb_raw["Closing Credit"],
                    })
                    st.session_state["ext_tb_classified_df"] = ExternalTBAnalyzerService.normalize_and_classify_tb(live_mapped)
                    st.session_state["ext_tb_file_sig"] = "LIVE_LEDGER"
                    st.success("✅ تم جلب وتبويب ميزان المراجعة الحي من دفاتر النظام!")
                    st.rerun()
                else:
                    st.warning("لا توجد قيود مرحلة في الدفاتر الحية حالياً.")
        with up_col4:
            st.markdown("<br>", unsafe_allow_html=True)
            sample_df_dl = ExternalTBAnalyzerService.get_sample_tasaheel_tb_dataframe()
            sample_buf = io.BytesIO()
            sample_df_dl.to_excel(sample_buf, index=False)
            sample_buf.seek(0)
            st.download_button(
                "📥 تنزيل قالب Excel جاهز",
                data=sample_buf,
                file_name="Template_Trial_Balance_MizanPro.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True
            )

        if uploaded_tb_file is not None:
            file_sig = f"{uploaded_tb_file.name}_{uploaded_tb_file.size}"
            if st.session_state.get("ext_tb_file_sig") != file_sig:
                try:
                    st.session_state["ext_tb_classified_df"] = ExternalTBAnalyzerService.parse_uploaded_trial_balance(uploaded_tb_file)
                    st.session_state["ext_tb_file_sig"] = file_sig
                    st.success(f"✅ تم قراءة وتصنيف ({len(st.session_state['ext_tb_classified_df'])}) حساباً من الملف المرفوع بنجاح!")
                except Exception as e:
                    st.error(f"❌ تعذر قراءة الملف المرفوع: {str(e)}")

        if "ext_tb_classified_df" not in st.session_state:
            live_tb_raw = LedgerService.get_live_trial_balance(db, include_zero_balances=False)
            if not live_tb_raw.empty:
                live_mapped = pd.DataFrame({
                    "كود الحساب": live_tb_raw["Account Code"],
                    "اسم الحساب": live_tb_raw["Account Name"],
                    "مدين أول المدة": live_tb_raw["Opening Debit"],
                    "دائن أول المدة": live_tb_raw["Opening Credit"],
                    "حركة مدين": live_tb_raw["Period Debit"],
                    "حركة دائن": live_tb_raw["Period Credit"],
                    "مدين آخر المدة": live_tb_raw["Closing Debit"],
                    "دائن آخر المدة": live_tb_raw["Closing Credit"],
                })
                st.session_state["ext_tb_classified_df"] = ExternalTBAnalyzerService.normalize_and_classify_tb(live_mapped)
            else:
                sample_raw = ExternalTBAnalyzerService.get_sample_tasaheel_tb_dataframe()
                st.session_state["ext_tb_classified_df"] = ExternalTBAnalyzerService.normalize_and_classify_tb(sample_raw)

        active_tb_df = st.session_state["ext_tb_classified_df"]

        # حفظ واستدعاء قوالب التوجيه (Mapping Profiles) + التعديل التفاعلي
        with st.expander("🔍 **مراجعة توجيه الحسابات وحفظ/استدعاء قوالب التوجيه (Mapping Profiles)**", expanded=False):
            mp1, mp2, mp3 = st.columns([1.5, 1.5, 1])
            existing_profiles = [p.profile_name for p in db.query(TBMappingProfile).all()]
            with mp1:
                new_prof_name = st.text_input("اسم قالب التوجيه لحفظه في قاعدة البيانات:", placeholder="مثال: قالب مؤسسة تساهيل طيبة")
                if st.button("💾 حفظ التوجيه الحالي كقالب دائم"):
                    if new_prof_name.strip():
                        ExternalTBAnalyzerService.save_mapping_profile(db, new_prof_name, ext_comp_name, active_tb_df)
                        st.success(f"✅ تم حفظ القالب ({new_prof_name}) بنجاح!")
                        st.rerun()
            with mp2:
                if existing_profiles:
                    sel_prof = st.selectbox("استدعاء قالب توجيه محفوظ مسبقاً:", existing_profiles)
                    if st.button("📂 تطبيق القالب المحفوظ على الميزان الحالي"):
                        st.session_state["ext_tb_classified_df"] = ExternalTBAnalyzerService.apply_mapping_profile(db, sel_prof, active_tb_df)
                        st.success(f"✅ تم تطبيق القالب ({sel_prof})!")
                        st.rerun()
                else:
                    st.info("لا توجد قوالب محفوظة بعد.")

            editable_cols = [
                "كود الحساب", "اسم الحساب", "مدين أول المدة", "دائن أول المدة",
                "حركة مدين", "حركة دائن", "مدين آخر المدة", "دائن آخر المدة",
                "مدين مقارنة", "دائن مقارنة", "التصنيف في القوائم والإيضاحات"
            ]
            for ec in editable_cols:
                if ec not in active_tb_df.columns:
                    active_tb_df[ec] = 0.0
            edited_df = st.data_editor(
                active_tb_df[editable_cols],
                column_config={
                    "التصنيف في القوائم والإيضاحات": st.column_config.SelectboxColumn(
                        "التصنيف في القوائم والإيضاحات",
                        options=list(CPA_CATEGORIES.values()),
                        required=True,
                        width="large"
                    )
                },
                use_container_width=True,
                hide_index=True,
                num_rows="dynamic",
                key="cpa_interactive_editor"
            )
            st.session_state["ext_tb_classified_df"] = edited_df.copy()
            active_tb_df = st.session_state["ext_tb_classified_df"]

        cpa_pkg = ExternalTBAnalyzerService.generate_cpa_full_package(active_tb_df, cpa_metadata)
        cpa_bs = cpa_pkg["balance_sheet"]
        cpa_pnl = cpa_pkg["income_statement"]
        cpa_eq = cpa_pkg["equity_statement"]
        cpa_cf = cpa_pkg["cash_flow_statement"]
        cpa_nd = cpa_pkg["notes_details"]
        tb_tots = cpa_pkg["trial_balance_totals"]

        k1, k2, k3, k4 = st.columns(4)
        k1.metric("إجمالي ميزان المراجعة (مدين / دائن)", f"{tb_tots['total_debit']:,.0f} ريال", delta="متزن 100% ✅" if abs(tb_tots['difference']) < 1.0 else f"فرق: {tb_tots['difference']:,.2f}")
        k2.metric("إجمالي الأصول (المركز المالي)", f"{cpa_bs['total_assets']:,.0f} ريال", delta="مطابق للالتزامات وحقوق الملكية ✅" if cpa_bs['is_balanced'] else f"فرق: {cpa_bs['difference']:,.2f}")
        k3.metric("صافي أرباح / (خسائر) الفترة", f"{cpa_pnl['net_profit_loss']:,.0f} ريال")
        k4.metric("الوعاء الزكوي / الزكاة المستحقة", f"{cpa_pnl['zakat_expense']:,.0f} ريال", delta=f"الوعاء: {cpa_nd['note_11_zakat']['zakat_base']:,.0f} ريال")

        # أزرار التصدير الثلاثية: HTML/PDF + Word (.doc) + Excel (.xlsx)
        cpa_html_report = ExternalTBAnalyzerService.generate_cpa_printable_html(cpa_pkg)
        cpa_word_bytes = ExternalTBAnalyzerService.generate_cpa_word_doc(cpa_pkg)
        cpa_excel_bytes = ExternalTBAnalyzerService.generate_cpa_excel_workbook(active_tb_df, cpa_pkg)

        dl1, dl2, dl3 = st.columns(3)
        with dl1:
            st.download_button(
                label="🖨️ تحميل التقرير الرسمي للطباعة (PDF / HTML)",
                data=cpa_html_report,
                file_name=f"CPA_Report_{ext_comp_name}.html",
                mime="text/html",
                use_container_width=True,
                type="primary",
                disabled=not has_perm("act_export_reports")
            )
        with dl2:
            st.download_button(
                label="📝 تحميل التقرير كملف Word قابل للتعديل (.doc)",
                data=cpa_word_bytes,
                file_name=f"CPA_Audited_Financial_Statements_{ext_comp_name}.doc",
                mime="application/msword",
                use_container_width=True
            )
        with dl3:
            st.download_button(
                label="📊 تحميل القوائم والإيضاحات بصيغة Excel (.xlsx)",
                data=cpa_excel_bytes,
                file_name=f"CPA_Financial_Statements_{ext_comp_name}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True
            )

        with st.expander("☁️ **حفظ ومزامنة تقرير المراجع القانوني والقوائم المالية مباشرة في Google Drive**", expanded=False):
            render_google_drive_hub_section(
                db,
                cpa_word_bytes=cpa_word_bytes,
                cpa_word_filename=f"CPA_Audited_Financial_Statements_{ext_comp_name}.doc",
                height=520
            )

        st.divider()

        tab_full_preview, tab_bs, tab_pnl_eq, tab_cf, tab_notes_all = st.tabs([
            "📄 المعاينة والطباعة الكاملة (تقرير المراجع + القوائم + 18 إيضاحاً)",
            "🏛️ قائمة المركز المالي",
            "📈 قائمة الدخل والتغير في حقوق الملكية",
            "💵 قائمة التدفقات النقدية",
            "📑 الإيضاحات المتممة التفصيلية (1 إلى 18)"
        ])

        with tab_full_preview:
            components.html(cpa_html_report, height=920, scrolling=True)

        with tab_bs:
            bs_table = [
                {"البيان": "الأصول غير المتداولة: العقارات والآلات والمعدات - بالصافي", "إيضاح": "4", "الفترة الحالية (ريال)": f"{cpa_bs['non_current_assets']['net_ppe']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_bs['non_current_assets']['comp_net_ppe']:,.0f}"},
                {"البيان": "مجموع الأصول غير المتداولة", "إيضاح": "", "الفترة الحالية (ريال)": f"{cpa_bs['non_current_assets']['total']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_bs['non_current_assets']['comp_total']:,.0f}"},
                {"البيان": "الأصول المتداولة: النقدية وما في حكمها", "إيضاح": "5", "الفترة الحالية (ريال)": f"{cpa_bs['current_assets']['cash_and_banks']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_bs['current_assets']['comp_cash']:,.0f}"},
                {"البيان": "الأصول المتداولة: ذمم مدينة تجارية", "إيضاح": "6", "الفترة الحالية (ريال)": f"{cpa_bs['current_assets']['trade_receivables']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_bs['current_assets']['comp_ar']:,.0f}"},
                {"البيان": "الأصول المتداولة: أرصدة مدينة أخرى", "إيضاح": "7", "الفترة الحالية (ريال)": f"{cpa_bs['current_assets']['other_receivables']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_bs['current_assets']['comp_other_ar']:,.0f}"},
                {"البيان": "الأصول المتداولة: المخزون", "إيضاح": "8", "الفترة الحالية (ريال)": f"{cpa_bs['current_assets']['inventory']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_bs['current_assets']['comp_inventory']:,.0f}"},
                {"البيان": "مجموع الأصول المتداولة", "إيضاح": "", "الفترة الحالية (ريال)": f"{cpa_bs['current_assets']['total']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_bs['current_assets']['comp_total']:,.0f}"},
                {"البيان": "🔵 إجمالي الأصول المتداولة وغير المتداولة", "إيضاح": "", "الفترة الحالية (ريال)": f"{cpa_bs['total_assets']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_bs['comp_total_assets']:,.0f}"},
                {"البيان": "حقوق الشركاء: رأس المال", "إيضاح": "", "الفترة الحالية (ريال)": f"{cpa_bs['equity']['capital']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_bs['equity']['capital']:,.0f}"},
                {"البيان": "حقوق الشركاء: أرباح مبقاة / (خسائر متراكمة)", "إيضاح": "", "الفترة الحالية (ريال)": f"{cpa_bs['equity']['closing_retained_earnings']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_bs['equity']['opening_retained_earnings']:,.0f}"},
                {"البيان": "مجموع حقوق الملكية", "إيضاح": "", "الفترة الحالية (ريال)": f"{cpa_bs['equity']['total']:,.0f}", "فترة المقارنة (ريال)": f"{(cpa_bs['equity']['capital'] + cpa_bs['equity']['opening_retained_earnings']):,.0f}"},
                {"البيان": "الالتزامات المتداولة: ذمم دائنة تجارية", "إيضاح": "9", "الفترة الحالية (ريال)": f"{cpa_bs['current_liabilities']['trade_payables']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_bs['current_liabilities']['comp_ap']:,.0f}"},
                {"البيان": "الالتزامات المتداولة: أرصدة دائنة أخرى", "إيضاح": "10", "الفترة الحالية (ريال)": f"{cpa_bs['current_liabilities']['other_payables']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_bs['current_liabilities']['comp_other_ap']:,.0f}"},
                {"البيان": "الالتزامات المتداولة: مخصص الزكاة", "إيضاح": "11", "الفترة الحالية (ريال)": f"{cpa_bs['current_liabilities']['zakat_provision']:,.0f}", "فترة المقارنة (ريال)": "0"},
                {"البيان": "الالتزامات المتداولة: مستحق إلى أطراف ذات علاقة", "إيضاح": "12", "الفترة الحالية (ريال)": f"{cpa_bs['current_liabilities']['due_to_related_parties']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_bs['current_liabilities']['comp_related_parties']:,.0f}"},
                {"البيان": "مجموع الالتزامات المتداولة", "إيضاح": "", "الفترة الحالية (ريال)": f"{cpa_bs['current_liabilities']['total']:,.0f}", "فترة المقارنة (ريال)": f"{(cpa_bs['current_liabilities']['comp_ap'] + cpa_bs['current_liabilities']['comp_other_ap'] + cpa_bs['current_liabilities']['comp_related_parties']):,.0f}"},
                {"البيان": "🟢 مجموع الالتزامات وحقوق الملكية", "إيضاح": "", "الفترة الحالية (ريال)": f"{cpa_bs['total_liabilities_and_equity']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_bs['comp_total_assets']:,.0f}"},
            ]
            st.table(pd.DataFrame(bs_table))

        with tab_pnl_eq:
            pnl_table = [
                {"البيان": "الإيرادات", "إيضاح": "13", "الفترة الحالية (ريال)": f"{cpa_pnl['revenues']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_pnl['comp_revenues']:,.0f}"},
                {"البيان": "يخصم: تكلفة الإيرادات", "إيضاح": "14", "الفترة الحالية (ريال)": f"({cpa_pnl['cost_of_revenues']:,.0f})", "فترة المقارنة (ريال)": f"({cpa_pnl['comp_cost_of_revenues']:,.0f})"},
                {"البيان": "مجمل الربح من الأنشطة الرئيسية", "إيضاح": "", "الفترة الحالية (ريال)": f"{cpa_pnl['gross_profit']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_pnl['comp_gross_profit']:,.0f}"},
                {"البيان": "المصروفات الإدارية والعمومية", "إيضاح": "15", "الفترة الحالية (ريال)": f"({cpa_pnl['ga_expenses']:,.0f})", "فترة المقارنة (ريال)": f"({cpa_pnl['comp_ga_expenses']:,.0f})"},
                {"البيان": "استهلاك العقارات وآلات ومعدات", "إيضاح": "4", "الفترة الحالية (ريال)": f"({cpa_pnl['depreciation_expense']:,.0f})", "فترة المقارنة (ريال)": f"({cpa_pnl['comp_depreciation_expense']:,.0f})"},
                {"البيان": "مجموع المصروفات", "إيضاح": "", "الفترة الحالية (ريال)": f"({cpa_pnl['total_operating_expenses']:,.0f})", "فترة المقارنة (ريال)": f"({(cpa_pnl['comp_ga_expenses'] + cpa_pnl['comp_depreciation_expense']):,.0f})"},
                {"البيان": "صافي الأرباح / (الخسائر) قبل الزكاة الشرعية", "إيضاح": "", "الفترة الحالية (ريال)": f"{cpa_pnl['profit_before_zakat']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_pnl['comp_profit_before_zakat']:,.0f}"},
                {"البيان": "الزكاة الشرعية", "إيضاح": "11", "الفترة الحالية (ريال)": f"({cpa_pnl['zakat_expense']:,.0f})", "فترة المقارنة (ريال)": "0"},
                {"البيان": "صافي أرباح / (خسائر) الفترة (إجمالي الدخل الشامل)", "إيضاح": "", "الفترة الحالية (ريال)": f"{cpa_pnl['net_profit_loss']:,.0f}", "فترة المقارنة (ريال)": f"{cpa_pnl['comp_profit_before_zakat']:,.0f}"},
            ]
            st.table(pd.DataFrame(pnl_table))

        with tab_cf:
            wc = cpa_cf["wc_changes"]
            cf_table = [
                {"البيان": "صافي أرباح / (خسائر) الفترة قبل خصم الزكاة الشرعية", "ريال سعودي": f"{cpa_cf['profit_before_zakat']:,.0f}"},
                {"البيان": "تعديلات البنود غير النقدية: استهلاك العقارات وآلات ومعدات", "ريال سعودي": f"{cpa_cf['depreciation']:,.0f}"},
                {"البيان": "صافي التدفقات قبل التغيرات في رأس المال العامل", "ريال سعودي": f"{cpa_cf['profit_before_wc']:,.0f}"},
                {"البيان": "التغير في الذمم المدينة التجارية", "ريال سعودي": f"{wc['trade_receivables']:,.0f}"},
                {"البيان": "التغير في الأرصدة المدينة الأخرى", "ريال سعودي": f"{wc['other_receivables']:,.0f}"},
                {"البيان": "التغير في المخزون", "ريال سعودي": f"{wc['inventory']:,.0f}"},
                {"البيان": "التغير في الذمم الدائنة التجارية", "ريال سعودي": f"{wc['trade_payables']:,.0f}"},
                {"البيان": "التغير في الأرصدة الدائنة الأخرى", "ريال سعودي": f"{wc['other_payables']:,.0f}"},
                {"البيان": "1️⃣ صافي التدفق النقدي من الأنشطة التشغيلية", "ريال سعودي": f"{cpa_cf['net_operating_cf']:,.0f}"},
                {"البيان": "2️⃣ صافي التدفق النقدي من الأنشطة الاستثمارية (إضافات الأصول الثابتة)", "ريال سعودي": f"{cpa_cf['net_investing_cf']:,.0f}"},
                {"البيان": "3️⃣ صافي التدفق النقدي من الأنشطة التمويلية (أطراف ذات علاقة ورأس المال)", "ريال سعودي": f"{cpa_cf['net_financing_cf']:,.0f}"},
                {"البيان": "صافي التغير في النقد وما في حكمه خلال الفترة", "ريال سعودي": f"{cpa_cf['net_cash_change']:,.0f}"},
                {"البيان": "رصيد النقد وما في حكمه في بداية الفترة", "ريال سعودي": f"{cpa_cf['opening_cash']:,.0f}"},
                {"البيان": "💰 رصيد النقد وما في حكمه في نهاية الفترة", "ريال سعودي": f"{cpa_cf['closing_cash']:,.0f}"},
            ]
            st.table(pd.DataFrame(cf_table))

        with tab_notes_all:
            n_col1, n_col2 = st.columns(2)
            with n_col1:
                st.markdown("##### **إيضاح (11) - مخصص الزكاة الشرعية:**")
                n11 = cpa_nd["note_11_zakat"]
                st.table(pd.DataFrame([
                    {"البيان": "صافي أرباح / (خسائر) الفترة المعدل", "ريال سعودي": f"{n11['adjusted_profit']:,.0f}"},
                    {"البيان": "رأس المال", "ريال سعودي": f"{n11['capital']:,.0f}"},
                    {"البيان": "أطراف ذات علاقة", "ريال سعودي": f"{n11['related_parties']:,.0f}"},
                    {"البيان": "إجمالي العناصر الموجبة", "ريال سعودي": f"{n11['positive_elements_net']:,.0f}"},
                    {"البيان": "يحسم: صافي الأصول الثابتة", "ريال سعودي": f"({n11['net_fixed_assets']:,.0f})"},
                    {"البيان": "الوعاء الزكوي", "ريال سعودي": f"{n11['zakat_base']:,.0f}"},
                    {"البيان": "مخصص الزكاة المستحقة", "ريال سعودي": f"{n11['zakat_due']:,.0f}"},
                ]))
            with n_col2:
                st.markdown("##### **إيضاح (15) - تفصيل المصاريف الإدارية والعمومية:**")
                if cpa_nd["note_15_ga_expenses"]["items"]:
                    st.table(pd.DataFrame([
                        {"البيان": i["name"], "ريال سعودي": f"{i['balance']:,.0f}"}
                        for i in cpa_nd["note_15_ga_expenses"]["items"]
                    ] + [{"البيان": "المجموع الكلي", "ريال سعودي": f"{cpa_nd['note_15_ga_expenses']['total']:,.0f}"}]))
    finally:
        db.close()


# =============================================================================
# 5. الشاشة 3: الأصول الثابتة، الرواتب ونهاية الخدمة، ومراكز التكلفة
# =============================================================================
elif menu_option == "🏗️ الأصول الثابتة، الرواتب، ومراكز التكلفة":
    st.markdown("### **إدارة الأصول الثابتة والإهلاك الآلي، مسير الرواتب ونهاية الخدمة، وربحية المشاريع**")
    t_fa, t_pay, t_cc = st.tabs([
        "🏗️ سجل الأصول الثابتة والإهلاك الآلي (IAS 16)",
        "👥 الموظفون ومسير الرواتب ومكافأة نهاية الخدمة",
        "🎯 ربحية مراكز التكلفة والمشاريع"
    ])

    db = get_db_session()
    try:
        settings = LedgerService.get_company_settings(db)

        with t_fa:
            fa_df = LedgerService.get_fixed_assets_df(db)
            if not fa_df.empty:
                f_m1, f_m2, f_m3 = st.columns(3)
                f_m1.metric("إجمالي التكلفة التاريخية للأصول", f"{fa_df['التكلفة التاريخية'].sum():,.2f} ريال")
                f_m2.metric("مجمع الإهلاك المتراكم", f"{fa_df['مجمع الإهلاك المتراكم'].sum():,.2f} ريال")
                f_m3.metric("صافي القيمة الدفترية (إيضاح 4)", f"{fa_df['صافي القيمة الدفترية'].sum():,.2f} ريال")
                st.dataframe(fa_df, use_container_width=True, hide_index=True)

            st.divider()
            col_dep1, col_dep2 = st.columns([1.25, 1])
            with col_dep1:
                st.markdown("##### **➕ تسجيل أصل ثابت جديد أو تعديل أصل مسجل:**")
                existing_assets = db.query(FixedAsset).order_by(FixedAsset.asset_code).all()
                fa_choices = {"➕ إضافة أصل ثابت جديد": None}
                for a_obj in existing_assets:
                    fa_choices[f"✏️ تعديل الأصل: {a_obj.asset_code} - {a_obj.name_ar}"] = a_obj
                sel_fa_obj = fa_choices[st.selectbox("اختر العملية أو الأصل المراد تعديله:", list(fa_choices.keys()))]

                fa_cats = ["السيارات ووسائل النقل", "الآلات والمعدات والأجهزة", "المباني والإنشاءات", "الأثاث والتركيبات والتجهيزات"]
                cat_idx = fa_cats.index(sel_fa_obj.category) if (sel_fa_obj and sel_fa_obj.category in fa_cats) else 0
                fa_name = st.text_input("اسم ووصف الأصل الثابت:", value=sel_fa_obj.name_ar if sel_fa_obj else "", placeholder="مثال: رافعة شوكية كهربائية للمستودع")
                fa_cat = st.selectbox("فئة الأصل:", fa_cats, index=cat_idx)
                fa_c1, fa_c2, fa_c3 = st.columns(3)
                with fa_c1:
                    fa_cost = st.number_input("تكلفة الشراء (ريال):", min_value=0.0, value=float(sel_fa_obj.purchase_cost) if sel_fa_obj else 0.0, step=1000.0)
                with fa_c2:
                    fa_rate = st.number_input("نسبة الإهلاك السنوي (%):", min_value=1.0, max_value=100.0, value=float(sel_fa_obj.depreciation_rate * 100.0) if sel_fa_obj else 20.0, step=5.0)
                with fa_c3:
                    fa_dt = st.date_input("تاريخ الشراء:", value=sel_fa_obj.purchase_date if sel_fa_obj else date.today())

                fa_accum = st.number_input("مجمع الإهلاك المتراكم السابق (ريال):", min_value=0.0, value=float(sel_fa_obj.accumulated_depreciation) if sel_fa_obj else 0.0, step=500.0)
                fa_active = st.checkbox("الأصل نشط وخاضع للإهلاك الدوري", value=sel_fa_obj.is_active if sel_fa_obj else True)

                fa_post_je = False
                fa_tr_code = "110201"
                if not sel_fa_obj:
                    fa_post_je = st.checkbox("توليد قيد شراء الأصل الثابت آلياً في دفتر اليومية", value=True)
                    if fa_post_je:
                        tr_accs = LedgerService.get_treasury_and_bank_accounts(db)
                        tr_opts = {f"{a.code} - {a.name_ar}": a.code for a in tr_accs}
                        tr_opts["210101 - الموردون التجاريون (شراء بالأجل)"] = "210101"
                        fa_tr_code = tr_opts[st.selectbox("حساب السداد المقابل لقيد شراء الأصل:", list(tr_opts.keys()), key="fa_tr_acc")]

                if st.button("💾 حفظ بيانات الأصل الثابت في السجل", type="primary", disabled=not has_perm("act_manage_assets")):
                    try:
                        LedgerService.create_or_update_fixed_asset(
                            db=db, name_ar=fa_name, category=fa_cat, purchase_date=fa_dt,
                            purchase_cost=fa_cost, depreciation_rate=fa_rate / 100.0,
                            accumulated_depreciation=fa_accum,
                            asset_code=sel_fa_obj.asset_code if sel_fa_obj else None,
                            post_purchase_entry=fa_post_je,
                            treasury_account_code=fa_tr_code,
                            is_active=fa_active,
                            performed_by=get_active_user_label()
                        )
                        st.success("✅ تم حفظ وتحديث سجل الأصل الثابت بنجاح!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ {str(e)}")

            with col_dep2:
                st.markdown("##### **⚙️ تشغيل وترحيل قسط الإهلاك الدوري الآلي:**")
                st.info("يقوم المحرك بحساب قسط الإهلاك لكل أصل نشط وترحيل قيد الإهلاك الآلي من حـ/ مصروف الإهلاك (5207) إلى حـ/ مجمع الإهلاك (1202).")
                dep_months = st.selectbox("فترة الإهلاك المراد حسابها:", [1, 3, 6, 12], index=0, format_func=lambda m: f"{m} شهر (شهري)" if m == 1 else (f"{m} أشهر" if m < 12 else "12 شهراً (سنوي كامل)"))
                dep_run_date = st.date_input("تاريخ قيد الإهلاك:", value=date.today(), key="dep_dt")
                if st.button("🚀 احتساب وترحيل قيد إهلاك الأصول الثابتة الآن", type="primary", use_container_width=True, disabled=not has_perm("act_manage_assets")):
                    try:
                        je_dep = LedgerService.run_period_depreciation(
                            db=db, dep_date=dep_run_date, months=dep_months, performed_by=get_active_user_label()
                        )
                        st.success(f"🎉 تم ترحيل قيد الإهلاك الآلي برقم ({je_dep.entry_number}) بمبلغ إجمالي ({je_dep.total_debit:,.2f} ريال)!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ {str(e)}")

        with t_pay:
            emp_df = LedgerService.get_employees_and_eos_df(db)
            if not emp_df.empty:
                em1, em2, em3 = st.columns(3)
                em1.metric("إجمالي صافي الرواتب الشهرية", f"{emp_df['صافي الراتب الشهري'].sum():,.2f} ريال")
                em2.metric("إجمالي التأمينات الشهرية (موظف + شركة)", f"{(emp_df['حصة الموظف تأمينات'].sum() + emp_df['حصة الشركة تأمينات'].sum()):,.2f} ريال")
                em3.metric("إجمالي مخصص نهاية الخدمة المتراكم", f"{emp_df['رصيد مخصص نهاية الخدمة المتراكم'].sum():,.2f} ريال")
                st.dataframe(emp_df, use_container_width=True, hide_index=True)

            st.divider()
            col_e1, col_e2 = st.columns([1.25, 1])
            with col_e1:
                st.markdown("##### **➕ إضافة موظف جديد أو تعديل بيانات موظف حالي:**")
                all_emps = db.query(Employee).order_by(Employee.emp_code).all()
                emp_choices = {"➕ إضافة موظف جديد": None}
                for emp_o in all_emps:
                    emp_choices[f"✏️ تعديل الموظف: {emp_o.emp_code} - {emp_o.name_ar} ({'نشط' if emp_o.is_active else 'موقوف'})"] = emp_o
                sel_emp_obj = emp_choices[st.selectbox("اختر الموظف للتعديل أو أضف موظفاً جديداً:", list(emp_choices.keys()))]

                e_name = st.text_input("اسم الموظف الكامل:", value=sel_emp_obj.name_ar if sel_emp_obj else "")
                e_job = st.text_input("المسمى الوظيفي:", value=sel_emp_obj.job_title if sel_emp_obj else "محاسب")
                ec1, ec2, ec3 = st.columns(3)
                with ec1:
                    e_nat = st.text_input("الجنسية:", value=sel_emp_obj.nationality if sel_emp_obj else "سعودي")
                with ec2:
                    e_saudi = st.checkbox("خاضع لتأمينات السعوديين (GOSI)", value=sel_emp_obj.is_saudi if sel_emp_obj else True)
                with ec3:
                    e_join = st.date_input("تاريخ المباشرة:", value=sel_emp_obj.join_date if sel_emp_obj else date(2024, 1, 1))
                es1, es2, es3 = st.columns(3)
                with es1:
                    e_basic = st.number_input("الراتب الأساسي:", min_value=0.0, value=float(sel_emp_obj.basic_salary) if sel_emp_obj else 6000.0, step=500.0)
                with es2:
                    e_hous = st.number_input("بدل السكن:", min_value=0.0, value=float(sel_emp_obj.housing_allowance) if sel_emp_obj else 1500.0, step=250.0)
                with es3:
                    e_trans = st.number_input("بدل النقل:", min_value=0.0, value=float(sel_emp_obj.transport_allowance) if sel_emp_obj else 500.0, step=100.0)
                e_active = st.checkbox("الموظف على رأس العمل (نشط في المسير الشهري)", value=sel_emp_obj.is_active if sel_emp_obj else True)

                if st.button("💾 حفظ بيانات الموظف", type="primary", disabled=not has_perm("act_manage_payroll")):
                    try:
                        LedgerService.create_or_update_employee(
                            db=db, name_ar=e_name, job_title=e_job, nationality=e_nat,
                            is_saudi=e_saudi, join_date=e_join, basic_salary=e_basic,
                            housing_allowance=e_hous, transport_allowance=e_trans,
                            emp_code=sel_emp_obj.emp_code if sel_emp_obj else None,
                            is_active=e_active, performed_by=get_active_user_label()
                        )
                        st.success("✅ تم حفظ وتحديث بيانات الموظف بنجاح!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ {str(e)}")

            with col_e2:
                st.markdown("##### **💸 إصدار وترحيل مسير الرواتب الشهري الجماعي:**")
                pr_month = st.text_input("شهر المسير:", value=date.today().strftime("%Y-%m"))
                pr_date = st.date_input("تاريخ صرف الرواتب:", value=date.today(), key="pr_dt")
                tr_accs_pr = LedgerService.get_treasury_and_bank_accounts(db)
                tr_pr_map = {f"{a.code} - {a.name_ar}": a.code for a in tr_accs_pr}
                default_pr_idx = next((idx for idx, c in enumerate(tr_pr_map.values()) if c == "110201"), 0)
                sel_pr_tr_code = tr_pr_map[st.selectbox("حساب البنك / الصندوق للصرف:", list(tr_pr_map.keys()), index=default_pr_idx, key="pr_tr")]
                pr_inc_eos = st.checkbox("إثبات قسط مخصص مكافأة نهاية الخدمة الشهري آلياً في القيد", value=True)
                if st.button("🚀 اعتماد وصرف مسير الرواتب وترحيل القيد المحاسبي", type="primary", use_container_width=True, disabled=not has_perm("act_manage_payroll")):
                    try:
                        pr_pay_m = PaymentMethod.CASH if sel_pr_tr_code.startswith("1101") else PaymentMethod.BANK
                        pr_obj = LedgerService.process_monthly_payroll(
                            db=db, period_month=pr_month, payment_date=pr_date,
                            payment_method=pr_pay_m, treasury_account_code=sel_pr_tr_code,
                            include_eos_accrual=pr_inc_eos, performed_by=get_active_user_label()
                        )
                        st.session_state["latest_payroll_id"] = pr_obj.id
                        st.success(f"🎉 تم اعتماد وصرف مسير الرواتب ({pr_obj.payroll_number}) بنجاح!")
                    except Exception as e:
                        st.error(f"❌ {str(e)}")

            if "latest_payroll_id" in st.session_state:
                pr_latest = db.query(PayrollRun).filter(PayrollRun.id == st.session_state["latest_payroll_id"]).first()
                if pr_latest:
                    pr_html = PrintTemplateService.generate_payroll_html(pr_latest, emp_df, settings)
                    components.html(pr_html, height=480, scrolling=True)

        with t_cc:
            st.markdown("##### **🎯 تقرير ربحية مراكز التكلفة والمشاريع والفروع:**")
            cc_f1, cc_f2, cc_f3 = st.columns([1, 1, 1])
            with cc_f1:
                cc_use_dates = st.checkbox("تصفية ربحية المراكز بفترة زمنية محددة", value=False, key="cc_flt")
            with cc_f2:
                cc_start = st.date_input("من تاريخ:", value=date(settings.fiscal_year, 1, 1), disabled=not cc_use_dates, key="cc_sdt")
            with cc_f3:
                cc_end = st.date_input("إلى تاريخ:", value=date.today(), disabled=not cc_use_dates, key="cc_edt")

            cc_df = LedgerService.get_cost_centers_pnl(
                db,
                start_date=cc_start if cc_use_dates else None,
                end_date=cc_end if cc_use_dates else None
            )
            if not cc_df.empty:
                st.dataframe(cc_df, use_container_width=True, hide_index=True)

            st.divider()
            st.markdown("##### **➕ إضافة مركز تكلفة / مشروع جديد:**")
            cc1, cc2, cc3 = st.columns(3)
            with cc1:
                cc_code = st.text_input("كود مركز التكلفة:", placeholder="مثال: CC-04")
            with cc2:
                cc_name_ar = st.text_input("اسم المشروع / الفرع (عربي):", placeholder="مثال: مشروع توريدات تبوك")
            with cc3:
                cc_name_en = st.text_input("الاسم بالإنجليزي (اختياري):")
            if st.button("💾 إضافة مركز التكلفة", disabled=not has_perm("act_manage_coa")):
                try:
                    LedgerService.create_cost_center(db, cc_code, cc_name_ar, cc_name_en)
                    st.success("✅ تم إنشاء مركز التكلفة بنجاح!")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ {str(e)}")
    finally:
        db.close()


# =============================================================================
# 6. الشاشة 4: الرقابة المالية: أعمار الديون، التسوية البنكية، وإقفال السنة
# =============================================================================
elif menu_option == "🛡️ الرقابة المالية: أعمار الديون، البنوك، وإقفال السنة":
    st.markdown("### **منظومة الرقابة المالية: أعمار الديون، مذكرة التسوية البنكية، إقفال السنة، ومزامنة Google Drive**")
    t_aging, t_bank, t_close, t_gdrive = st.tabs([
        "📊 أعمار ديون العملاء والموردين (Aging & ECL)",
        "🏦 مذكرة التسوية البنكية الآلية",
        "🔒 إقفال السنة المالية وإدارة قاعدة البيانات",
        "☁️ الأرشيف السحابي (Google Drive)"
    ])

    db = get_db_session()
    try:
        with t_aging:
            ag1, ag2 = st.columns(2)
            with ag1:
                st.markdown("##### **👥 أعمار ديون العملاء ومخصص الديون المشكوك فيها (IFRS 9 ECL):**")
                cust_aging_df = LedgerService.get_aging_report(db, party_type="CUSTOMER")
                if not cust_aging_df.empty:
                    st.metric("إجمالي مخصص الديون المشكوك فيها المقترح (ECL)", f"{cust_aging_df['مخصص ECL المقترح'].sum():,.2f} ريال")
                    st.dataframe(cust_aging_df, use_container_width=True, hide_index=True)
                else:
                    st.info("لا توجد ذمم مدينة متأخرة على العملاء حالياً.")

            with ag2:
                st.markdown("##### **🚛 أعمار مستحقات الموردين التجاريين:**")
                supp_aging_df = LedgerService.get_aging_report(db, party_type="SUPPLIER")
                if not supp_aging_df.empty:
                    st.metric("إجمالي مستحقات الموردين القائمة", f"{supp_aging_df['إجمالي المستحق للمورد'].sum():,.2f} ريال")
                    st.dataframe(supp_aging_df, use_container_width=True, hide_index=True)
                else:
                    st.info("لا توجد ذمم دائنة غير مسددة للموردين حالياً.")

        with t_bank:
            st.markdown("##### **🏦 مطابقة كشف الحساب البنكي مع دفتر الأستاذ (Bank Reconciliation):**")
            bank_accs = [a for a in LedgerService.get_treasury_and_bank_accounts(db) if a.code.startswith("1102")]
            if not bank_accs:
                bank_accs = LedgerService.get_treasury_and_bank_accounts(db)
            bank_acc_map = {f"{a.code} - {a.name_ar}": a.code for a in bank_accs} or {"110201 - البنك الرئيسي": "110201"}
            bnk_c1, bnk_c2 = st.columns([1, 1.5])
            with bnk_c1:
                sel_bnk_code = bank_acc_map[st.selectbox("اختر الحساب البنكي للمطابقة:", list(bank_acc_map.keys()), key="bnk_sel_acc")]
            with bnk_c2:
                up_bank = st.file_uploader("ارفع كشف حساب البنك (Excel/CSV) أو اتركه فارغاً لتشغيل المطابقة على الكشف النموذجي:", type=["xlsx", "csv"], key="bnk_up")
            uploaded_bank_df = None
            if up_bank is not None:
                uploaded_bank_df = pd.read_csv(up_bank) if up_bank.name.endswith(".csv") else pd.read_excel(up_bank)

            rec_res = LedgerService.reconcile_bank_statement(db, bank_account_code=sel_bnk_code, bank_df=uploaded_bank_df)
            b1, b2, b3, b4 = st.columns(4)
            b1.metric("رصيد البنك في الدفاتر", f"{rec_res['book_closing_balance']:,.2f} ريال")
            b2.metric("رصيد كشف البنك", f"{rec_res['bank_statement_balance']:,.2f} ريال")
            b3.metric("عمليات بنكية غير مسجلة بالدفاتر", f"{rec_res['unrecorded_bank_total']:,.2f} ريال")
            b4.metric("الرصيد المعدل المطابق", f"{rec_res['adjusted_reconciled_balance']:,.2f} ريال", delta=f"{rec_res['matched_transactions_count']} حركة مطابقة ✅")

            if rec_res["unrecorded_bank_items"]:
                st.warning("⚠️ عمليات ظهرت في كشف البنك ولم تسجل بعد في دفتر اليومية:")
                st.table(pd.DataFrame(rec_res["unrecorded_bank_items"]))
                if st.button("⚡ تسجيل قيد تسوية الفروق البنكية غير المسجلة تلقائياً", disabled=not has_perm("act_create_journal")):
                    net_unrec = float(rec_res["unrecorded_bank_total"])
                    amt_abs = abs(net_unrec)
                    if amt_abs > 0:
                        if net_unrec < 0:
                            adj_lines = [
                                {"account_code": "5301", "debit": amt_abs, "credit": 0.0, "description": "عمولات ومصاريف بنكية"},
                                {"account_code": sel_bnk_code, "debit": 0.0, "credit": amt_abs, "description": "خصم من الحساب البنكي الجاري"}
                            ]
                            adj_desc = "إثبات رسوم وعمولات خدمات مصرفية من مذكرة التسوية البنكية"
                        else:
                            adj_lines = [
                                {"account_code": sel_bnk_code, "debit": amt_abs, "credit": 0.0, "description": "إيداع بنكي من مذكرة التسوية"},
                                {"account_code": "4201", "debit": 0.0, "credit": amt_abs, "description": "إيرادات/تحصيلات بنكية مسواة"}
                            ]
                            adj_desc = "إثبات إيداعات بنكية غير مسجلة من مذكرة التسوية البنكية"
                        LedgerService.create_journal_entry(
                            db=db,
                            description=adj_desc,
                            lines_data=adj_lines,
                            performed_by=get_active_user_label()
                        )
                        st.success("✅ تم تسجيل قيد التسوية البنكية ومطابقة الرصيد 100%!")
                        st.rerun()

        with t_close:
            col_cl1, col_cl2 = st.columns(2)
            with col_cl1:
                cfg_close = LedgerService.get_company_settings(db)
                st.markdown("##### **🔒 معالج إقفال السنة المالية الآلي (Year-End Closing):**")
                st.write("يقوم المعالج بإقفال كافة حسابات الإيرادات (`4xxx`) والمصروفات (`5xxx`) في حساب الأرباح المبقاة (`3103`) بقيد إقفال رسمي متزن.")
                cl_year = st.number_input("السنة المالية المراد إقفالها:", value=int(cfg_close.fiscal_year), step=1)
                cl_lock = st.checkbox("قفل الفترة المالية نهائياً بعد توليد قيد الإقفال (منع الترحيل إليها)", value=False)
                if st.button("🚀 توليد وترحيل قيد إقفال السنة المالية الآن", type="primary", disabled=not has_perm("act_close_year")):
                    try:
                        close_je = LedgerService.close_fiscal_year(
                            db=db, fiscal_year=int(cl_year), lock_period=cl_lock, performed_by=get_active_user_label()
                        )
                        st.success(f"🎉 تم إقفال حسابات قائمة الدخل بنجاح بموجب القيد رقم ({close_je.entry_number})!")
                    except Exception as e:
                        st.error(f"❌ {str(e)}")

            with col_cl2:
                st.markdown("##### **🧹 تصفير البيانات التجريبية للبدء بشركة جديدة:**")
                st.write("يحذف الفواتير والسندات والقيود التجريبية، مع **الحفاظ الكامل على شجرة الحسابات (77 حساباً) وإعدادات المنشأة وسجل التدقيق**.")
                clear_demo_cards = st.checkbox("حذف البطاقات التجريبية أيضاً (الأصناف، الأصول، الموظفين، العملاء، والموردين التجريبيين)", value=True)
                confirm_reset = st.checkbox("أؤكد رغبتي في تصفير البيانات التجريبية للبدء على بياض")
                if st.button("🗑️ تصفير البيانات التجريبية والبدء بنظام نظيف", disabled=(not confirm_reset or not has_perm("act_reset_db"))):
                    LedgerService.reset_transactions_keep_coa(
                        db,
                        performed_by=get_active_user_label(),
                        clear_master_data=clear_demo_cards
                    )
                    st.success("✅ تم تصفير البيانات التجريبية بنجاح! النظام جاهز لتسجيل بيانات شركتك الفعلية من الصفر.")
                    st.rerun()

                st.divider()
                st.markdown("##### **📤 استعادة نسخة احتياطية لقاعدة البيانات (.db):**")
                up_db_file = st.file_uploader("ارفع ملف قاعدة البيانات الاحتياطي (.db):", type=["db", "sqlite", "sqlite3"], key="restore_db_up")
                if up_db_file is not None:
                    can_restore_db = has_perm("act_reset_db") and has_perm("act_cloud_backup")
                    if not can_restore_db:
                        st.warning("🔒 استعادة قاعدة البيانات تتطلب صلاحية إعادة تهيئة النظام (`act_reset_db`) وصلاحية النسخ الاحتياطي (`act_cloud_backup`).")
                    if st.button("🔄 استبدال واستعادة النسخة الاحتياطية الآن", type="primary", disabled=not can_restore_db):
                        raw_bytes = up_db_file.getvalue()
                        if not raw_bytes.startswith(b"SQLite format 3\x00"):
                            st.error("❌ الملف المرفوع ليس ملف قاعدة بيانات SQLite صالحاً!")
                        else:
                            with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tmp_f:
                                tmp_f.write(raw_bytes)
                                tmp_path = tmp_f.name
                            try:
                                chk_conn = sqlite3.connect(tmp_path)
                                chk_res = chk_conn.execute("PRAGMA integrity_check;").fetchone()
                                chk_conn.close()
                                if not chk_res or chk_res[0] != "ok":
                                    raise ValueError("فشل فحص سلامة قاعدة البيانات المرفوعة (Integrity Check Failed).")
                                db.close()
                                target_db_p = os.path.join(BASE_DIR, "mizanpro_ledger.db")
                                if os.path.exists(target_db_p):
                                    shutil.copy2(target_db_p, os.path.join(BASE_DIR, "mizanpro_pre_restore_backup.db"))
                                shutil.move(tmp_path, target_db_p)
                                init_database_and_seed(seed_demo_data=False)
                                st.success("✅ تم التحقق من سلامة النسخة الاحتياطية واستعادتها وتدوير أي رموز دخول مكشوفة بأمان!")
                                st.rerun()
                            except Exception as ex_db:
                                if os.path.exists(tmp_path):
                                    os.remove(tmp_path)
                                st.error(f"❌ تعذر استعادة النسخة الاحتياطية: {ex_db}")

        with t_gdrive:
            render_google_drive_hub_section(db, height=560)
    finally:
        db.close()


# =============================================================================
# 7. الشاشة 5: إدارة المخزون، الأصناف، العملاء، والموردين
# =============================================================================
elif menu_option == "📦 المخزون والعملاء والموردون":
    st.markdown("### **إدارة المخزون (WAC)، بطاقات الأصناف، العملاء، والموردين**")
    t_inv, t_wh, t_tx, t_cust, t_supp = st.tabs([
        "📦 بطاقات الأصناف وتقييم المخزون",
        "🏢 تعدد المستودعات والتحويل المخزني",
        "⚖️ كارت حركة الصنف والتسوية الجردية",
        "👥 العملاء وكشوف حساباتهم",
        "🚛 الموردون وكشوف حساباتهم"
    ])

    db = get_db_session()
    try:
        with t_inv:
            inv_df = LedgerService.get_inventory_valuation_df(db)
            total_inv_val = float(inv_df["إجمالي قيمة المخزون"].sum()) if not inv_df.empty else 0.0
            st.metric("إجمالي تقييم المخزون الفعلي (بطريقة المتوسط المرجح WAC)", f"{total_inv_val:,.2f} ريال")
            if not inv_df.empty:
                st.dataframe(inv_df, use_container_width=True, hide_index=True)

            st.divider()
            st.markdown("##### **➕ إضافة بطاقة صنف جديد أو تعديل صنف مسجل:**")
            all_prods = db.query(Product).order_by(Product.code).all()
            prod_edit_choices = {"➕ إنشاء بطاقة صنف / خدمة جديدة": None}
            for pr_o in all_prods:
                prod_edit_choices[f"✏️ تعديل الصنف: {pr_o.code} - {pr_o.name_ar} ({'نشط' if pr_o.is_active else 'موقوف'})"] = pr_o
            sel_prod_edit = prod_edit_choices[st.selectbox("اختر الصنف للتعديل أو أضف صنفاً جديداً:", list(prod_edit_choices.keys()))]

            p1, p2, p3, p4 = st.columns(4)
            with p1:
                p_code = st.text_input("كود الصنف (اتركه فارغاً للتوليد الآلي):", value=sel_prod_edit.code if sel_prod_edit else "", placeholder="مثال: PRD-005", disabled=bool(sel_prod_edit))
            with p2:
                p_name = st.text_input("اسم الصنف / الخدمة (عربي):", value=sel_prod_edit.name_ar if sel_prod_edit else "")
            with p3:
                p_cat = st.text_input("التصنيف:", value=(sel_prod_edit.category or "قطع غيار") if sel_prod_edit else "قطع غيار")
            with p4:
                units_list = ["حبة", "طقم", "كرتون", "لتر", "خدمة"]
                u_idx = units_list.index(sel_prod_edit.unit) if (sel_prod_edit and sel_prod_edit.unit in units_list) else 0
                p_unit = st.selectbox("الوحدة:", units_list, index=u_idx)

            p5, p6, p7, p8 = st.columns(4)
            with p5:
                p_cost = st.number_input("التكلفة الافتراضية / المرجحة:", min_value=0.0, value=float(sel_prod_edit.cost_price) if sel_prod_edit else 0.0, step=10.0)
            with p6:
                p_sale = st.number_input("سعر البيع الافتراضي (بدون ضريبة):", min_value=0.0, value=float(sel_prod_edit.sale_price) if sel_prod_edit else 0.0, step=10.0)
            with p7:
                p_stock = st.number_input("رصيد أول المدة بالمخزن:", min_value=0.0, value=float(sel_prod_edit.stock_quantity) if sel_prod_edit else 0.0, step=1.0, disabled=bool(sel_prod_edit))
            with p8:
                p_is_srv = st.checkbox("صنف خدمي (غير مخزني)", value=bool(sel_prod_edit.is_service) if sel_prod_edit else False)
                p_active = st.checkbox("الصنف نشط ومتاح للتعامل", value=bool(sel_prod_edit.is_active) if sel_prod_edit else True)

            if st.button("💾 حفظ بطاقة الصنف", type="primary", disabled=not has_perm("act_manage_inventory")):
                try:
                    prod = LedgerService.create_or_update_product(
                        db=db, name_ar=p_name, code=(sel_prod_edit.code if sel_prod_edit else (p_code.strip() or None)),
                        category=p_cat, unit=p_unit, cost_price=p_cost,
                        sale_price=p_sale, stock_quantity=p_stock, is_service=p_is_srv,
                        is_active=p_active, performed_by=get_active_user_label()
                    )
                    st.success(f"✅ تم حفظ وتحديث الصنف بنجاح برقم كود: {prod.code}")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ خطأ: {str(e)}")

        with t_wh:
            st.markdown("##### **🏢 توزيع أرصدة المخزون عبر المستودعات والفروع:**")
            wh_df = LedgerService.get_warehouses_stock_df(db)
            if not wh_df.empty:
                st.dataframe(wh_df, use_container_width=True, hide_index=True)

            st.divider()
            wh_col1, wh_col2 = st.columns(2)
            with wh_col1:
                st.markdown("##### **🔄 أمر تحويل مخزني بين المستودعات:**")
                warehouses_list = db.query(Warehouse).filter(Warehouse.is_active == True).all()
                stock_prods = db.query(Product).filter(Product.is_service == False, Product.is_active == True).all()
                if len(warehouses_list) >= 2 and stock_prods:
                    wh_opts = {f"{w.code} - {w.name_ar}": w.id for w in warehouses_list}
                    sp_opts = {f"{p.code} - {p.name_ar} (الإجمالي: {p.stock_quantity:,.2f})": p.id for p in stock_prods}
                    tr_from = wh_opts[st.selectbox("من المستودع المصدر:", list(wh_opts.keys()), index=0, key="tr_f")]
                    tr_to = wh_opts[st.selectbox("إلى المستودع المستلم:", list(wh_opts.keys()), index=1, key="tr_t")]
                    tr_prod = sp_opts[st.selectbox("الصنف المراد تحويله:", list(sp_opts.keys()), key="tr_p")]
                    tr_qty = st.number_input("الكمية المحولة:", min_value=1.0, value=1.0, step=1.0, key="tr_q")
                    tr_notes = st.text_input("بيان / سبب التحويل:", value="تغذية مستودع الفرع بالبضاعة", key="tr_n")
                    if st.button("🚀 تنفيذ التحويل المخزني بين المستودعين", type="primary", use_container_width=True, disabled=not has_perm("act_inventory_adjust")):
                        try:
                            LedgerService.transfer_warehouse_stock(
                                db=db, from_warehouse_id=tr_from, to_warehouse_id=tr_to,
                                product_id=tr_prod, quantity=tr_qty, notes=tr_notes,
                                performed_by=get_active_user_label()
                            )
                            st.success("✅ تم تنفيذ أمر التحويل المخزني بين المستودعات بنجاح!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ {str(e)}")

            with wh_col2:
                st.markdown("##### **➕ إضافة مستودع / فرع تخزين جديد:**")
                nw_code = st.text_input("كود المستودع:", placeholder="مثال: WH-04")
                nw_name = st.text_input("اسم المستودع:", placeholder="مثال: مستودع فرع الدمام")
                nw_loc = st.text_input("المدينة / الموقع:", value="الدمام")
                nw_mgr = st.text_input("أمين المستودع المسؤول:")
                if st.button("💾 إنشاء المستودع الجديد", disabled=not has_perm("act_manage_inventory")):
                    try:
                        LedgerService.create_warehouse(db=db, code=nw_code, name_ar=nw_name, location=nw_loc, manager_name=nw_mgr)
                        st.success("✅ تم إنشاء المستودع الجديد بنجاح!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ {str(e)}")

        with t_tx:
            products = db.query(Product).order_by(Product.code).all()
            if not products:
                st.info("لا توجد أصناف مسجلة.")
            else:
                prod_map = {f"{p.code} - {p.name_ar} (الرصيد الحالي: {p.stock_quantity:,.2f} {p.unit} | تكلفة WAC: {p.cost_price:,.2f})": p for p in products}
                sel_prod_label = st.selectbox("اختر الصنف لعرض حركاته أو تسوية جرده:", list(prod_map.keys()))
                sel_prod = prod_map[sel_prod_label]

                txs = db.query(InventoryTransaction).filter(InventoryTransaction.product_id == sel_prod.id).order_by(InventoryTransaction.id.desc()).all()
                if txs:
                    tx_rows = [{
                        "التاريخ": t.tx_date.strftime("%Y-%m-%d"),
                        "نوع الحركة": t.tx_type.value,
                        "رقم المستند": t.reference_number,
                        "كمية واردة (+)": t.quantity_in,
                        "كمية منصرفة (-)": t.quantity_out,
                        "الرصيد بعد الحركة": t.balance_after,
                        "تكلفة الوحدة": f"{t.unit_cost:,.2f}",
                        "إجمالي التكلفة": f"{t.total_cost:,.2f}",
                        "ملاحظات": t.notes or ""
                    } for t in txs]
                    st.dataframe(pd.DataFrame(tx_rows), use_container_width=True, hide_index=True)
                else:
                    st.info("لا توجد حركات مسجلة على هذا الصنف حتى الآن.")

                if not sel_prod.is_service:
                    st.divider()
                    st.markdown("##### **⚖️ إجراء تسوية جردية فعلية للصنف:**")
                    adj1, adj2, adj3 = st.columns(3)
                    with adj1:
                        actual_qty = st.number_input("الكمية الفعلية بعد الجرد:", min_value=0.0, value=float(sel_prod.stock_quantity), step=1.0)
                    with adj2:
                        adj_date = st.date_input("تاريخ الجرد:", value=date.today())
                    with adj3:
                        adj_reason = st.text_input("سبب التسوية الجردية:", value="جرد دوري للمستودع")

                    if st.button("🚀 اعتماد التسوية الجردية وترحيل القيد المحاسبي", disabled=not has_perm("act_inventory_adjust")):
                        try:
                            LedgerService.create_inventory_adjustment(
                                db=db, product_id=sel_prod.id,
                                new_actual_quantity=actual_qty, adjustment_date=adj_date, reason=adj_reason,
                                performed_by=get_active_user_label()
                            )
                            st.success("✅ تمت التسوية الجردية وترحيل القيد المحاسبي بنجاح!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ خطأ: {str(e)}")

        with t_cust:
            col_c1, col_c2 = st.columns([1, 1.2])
            customers = db.query(Customer).order_by(Customer.id).all()
            with col_c1:
                st.markdown("##### **➕ إضافة عميل جديد أو تعديل عميل مسجل:**")
                cust_edit_opts = {"➕ تسجيل عميل جديد": None}
                for co in customers:
                    cust_edit_opts[f"✏️ تعديل: {co.code} - {co.name_ar} ({'نشط' if co.is_active else 'موقوف'})"] = co
                sel_c_edit = cust_edit_opts[st.selectbox("اختر العميل للتعديل أو أضف جديداً:", list(cust_edit_opts.keys()))]

                c_name = st.text_input("اسم العميل / الشركة:", value=sel_c_edit.name_ar if sel_c_edit else "")
                c_vat = st.text_input("الرقم الضريبي للعميل (15 رقماً للشركات):", value=(sel_c_edit.vat_number or "") if sel_c_edit else "")
                c_phone = st.text_input("رقم الجوال / الهاتف:", value=(sel_c_edit.phone or "") if sel_c_edit else "")
                c_addr = st.text_input("العنوان:", value=(sel_c_edit.address or "") if sel_c_edit else "")
                c_lim = st.number_input("الحد الائتماني المسموح (ريال):", min_value=0.0, value=float(sel_c_edit.credit_limit or 0.0) if sel_c_edit else 0.0, step=5000.0)
                c_active = st.checkbox("حساب العميل نشط", value=bool(sel_c_edit.is_active) if sel_c_edit else True)
                if st.button("💾 حفظ بيانات العميل", type="primary", disabled=not has_perm("act_manage_inventory")):
                    try:
                        c_obj = LedgerService.create_or_update_customer(
                            db=db, name_ar=c_name, code=sel_c_edit.code if sel_c_edit else None,
                            vat_number=c_vat, phone=c_phone, address=c_addr, credit_limit=c_lim,
                            is_active=c_active, performed_by=get_active_user_label()
                        )
                        st.success(f"✅ تم حفظ وتحديث بيانات العميل برقم: {c_obj.code}")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ {str(e)}")

            with col_c2:
                st.markdown("##### **📑 كشف حساب عميل تفصيلي:**")
                if customers:
                    c_map = {f"{c.code} - {c.name_ar}": c.id for c in customers}
                    sel_c = st.selectbox("اختر العميل لعرض كشف حسابه:", list(c_map.keys()))
                    cf_c1, cf_c2, cf_c3 = st.columns([1, 1, 1])
                    with cf_c1:
                        c_use_dt = st.checkbox("تصفية بالتاريخ", value=False, key="c_stmt_flt")
                    with cf_c2:
                        c_sdt = st.date_input("من تاريخ:", value=date(date.today().year, 1, 1), disabled=not c_use_dt, key="c_sdt")
                    with cf_c3:
                        c_edt = st.date_input("إلى تاريخ:", value=date.today(), disabled=not c_use_dt, key="c_edt")
                    c_stmt = LedgerService.get_party_statement(
                        db, "CUSTOMER", c_map[sel_c],
                        start_date=c_sdt if c_use_dt else None,
                        end_date=c_edt if c_use_dt else None
                    )
                    st.metric("الرصيد المستحق على العميل", f"{c_stmt['net_balance']:,.2f} ريال")
                    if c_stmt["statement"]:
                        st.dataframe(pd.DataFrame(c_stmt["statement"]), use_container_width=True, hide_index=True)

        with t_supp:
            col_s1, col_s2 = st.columns([1, 1.2])
            suppliers = db.query(Supplier).order_by(Supplier.id).all()
            with col_s1:
                st.markdown("##### **➕ إضافة مورد جديد أو تعديل مورد مسجل:**")
                supp_edit_opts = {"➕ تسجيل مورد جديد": None}
                for so in suppliers:
                    supp_edit_opts[f"✏️ تعديل: {so.code} - {so.name_ar} ({'نشط' if so.is_active else 'موقوف'})"] = so
                sel_s_edit = supp_edit_opts[st.selectbox("اختر المورد للتعديل أو أضف جديداً:", list(supp_edit_opts.keys()))]

                s_name = st.text_input("اسم المورد / الشركة الموردة:", value=sel_s_edit.name_ar if sel_s_edit else "")
                s_vat = st.text_input("الرقم الضريبي للمورد:", value=(sel_s_edit.vat_number or "") if sel_s_edit else "")
                s_phone = st.text_input("هاتف المورد:", value=(sel_s_edit.phone or "") if sel_s_edit else "")
                s_addr = st.text_input("عنوان المورد:", value=(sel_s_edit.address or "") if sel_s_edit else "")
                s_active = st.checkbox("حساب المورد نشط", value=bool(sel_s_edit.is_active) if sel_s_edit else True)
                if st.button("💾 حفظ بيانات المورد", type="primary", disabled=not has_perm("act_manage_inventory")):
                    try:
                        s_obj = LedgerService.create_or_update_supplier(
                            db=db, name_ar=s_name, code=sel_s_edit.code if sel_s_edit else None,
                            vat_number=s_vat, phone=s_phone, address=s_addr,
                            is_active=s_active, performed_by=get_active_user_label()
                        )
                        st.success(f"✅ تم حفظ وتحديث بيانات المورد برقم: {s_obj.code}")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ {str(e)}")

            with col_s2:
                st.markdown("##### **📑 كشف حساب مورد تفصيلي:**")
                if suppliers:
                    s_map = {f"{s.code} - {s.name_ar}": s.id for s in suppliers}
                    sel_s = st.selectbox("اختر المورد لعرض كشف حسابه:", list(s_map.keys()))
                    sf_c1, sf_c2, sf_c3 = st.columns([1, 1, 1])
                    with sf_c1:
                        s_use_dt = st.checkbox("تصفية بالتاريخ", value=False, key="s_stmt_flt")
                    with sf_c2:
                        s_sdt = st.date_input("من تاريخ:", value=date(date.today().year, 1, 1), disabled=not s_use_dt, key="s_sdt")
                    with sf_c3:
                        s_edt = st.date_input("إلى تاريخ:", value=date.today(), disabled=not s_use_dt, key="s_edt")
                    s_stmt = LedgerService.get_party_statement(
                        db, "SUPPLIER", s_map[sel_s],
                        start_date=s_sdt if s_use_dt else None,
                        end_date=s_edt if s_use_dt else None
                    )
                    st.metric("الرصيد المستحق للمورد", f"{s_stmt['net_balance']:,.2f} ريال")
                    if s_stmt["statement"]:
                        st.dataframe(pd.DataFrame(s_stmt["statement"]), use_container_width=True, hide_index=True)
    finally:
        db.close()


# =============================================================================
# 8. الشاشة 6: دورة المبيعات وإشعارات الدائن (Sales & Credit Notes)
# =============================================================================
elif menu_option == "🧾 المبيعات وإشعارات الدائن":
    st.markdown("### **دورة المبيعات الضريبية وإشعارات الدائن (ZATCA E-Invoicing)**")
    tab_create, tab_return, tab_history, tab_zatca_p2 = st.tabs([
        "📝 إصدار فاتورة مبيعات ضريبية",
        "↩️ إصدار إشعار دائن (مرتجع مبيعات)",
        "📂 أرشيف الفواتير والإشعارات والطباعة",
        "🛡️ فاحص المرحلة الثانية والختم التشفيري 3D (ZATCA Phase 2)"
    ])

    db = get_db_session()
    try:
        settings = LedgerService.get_company_settings(db)
        customers = db.query(Customer).filter(Customer.is_active == True).all()
        products = db.query(Product).filter(Product.is_active == True).all()
        cost_centers = db.query(CostCenter).all()
        cc_choices = {"-- بدون مركز تكلفة محدد --": None}
        for cc in cost_centers:
            cc_choices[f"{cc.code} - {cc.name_ar}"] = cc.id

        tr_accounts = LedgerService.get_treasury_and_bank_accounts(db)
        pay_method_map = {}
        pay_treasury_code_map = {}
        for tr_a in tr_accounts:
            if tr_a.code.startswith("1101"):
                lbl = f"نقداً ({tr_a.name_ar} - {tr_a.code})"
                pay_method_map[lbl] = PaymentMethod.CASH
                pay_treasury_code_map[lbl] = tr_a.code
            else:
                lbl = f"تحويل بنكي / شبكة ({tr_a.name_ar} - {tr_a.code})"
                pay_method_map[lbl] = PaymentMethod.BANK
                pay_treasury_code_map[lbl] = tr_a.code
        if not pay_method_map:
            pay_method_map = {
                "نقداً (الصندوق الرئيسي)": PaymentMethod.CASH,
                "تحويل بنكي / شبكة (POS)": PaymentMethod.BANK,
            }
            pay_treasury_code_map = {
                "نقداً (الصندوق الرئيسي)": "110101",
                "تحويل بنكي / شبكة (POS)": "110201",
            }
        pay_method_map["بالأجل (على حساب العميل)"] = PaymentMethod.CREDIT
        pay_treasury_code_map["بالأجل (على حساب العميل)"] = None

        inv_type_map = {
            "فاتورة ضريبية مبسطة (B2C)": InvoiceType.SIMPLIFIED,
            "فاتورة ضريبية قياسية (B2B)": InvoiceType.STANDARD
        }

        prod_choices = {"-- صنف حر / يدوي --": None}
        for p in products:
            prod_choices[f"{p.code} - {p.name_ar} (متاح: {p.stock_quantity:,.0f})"] = p

        with tab_create:
            cust_choices = {"-- إدخال عميل يدوي --": None}
            for c in customers:
                cust_choices[f"{c.code} - {c.name_ar}"] = c

            f0, f1, f2, f3 = st.columns(4)
            with f0:
                sel_cust_key = st.selectbox("اختيار من سجل العملاء:", list(cust_choices.keys()))
                sel_cust_obj = cust_choices[sel_cust_key]
            with f1:
                cust_name = st.text_input("اسم العميل:", value=sel_cust_obj.name_ar if sel_cust_obj else "عميل نقدي")
            with f2:
                cust_vat = st.text_input("الرقم الضريبي للعميل:", value=(sel_cust_obj.vat_number or "") if sel_cust_obj else "")
            with f3:
                inv_date = st.date_input("تاريخ الفاتورة:", value=date.today())

            f4, f5, f6 = st.columns(3)
            with f4:
                selected_pay_label = st.selectbox("طريقة السداد وحساب التحصيل:", list(pay_method_map.keys()))
                pay_method = pay_method_map[selected_pay_label]
                sel_tr_code_sales = pay_treasury_code_map[selected_pay_label]
            with f5:
                selected_inv_label = st.selectbox("نوع الفاتورة الضريبية:", list(inv_type_map.keys()))
                inv_type = inv_type_map[selected_inv_label]
            with f6:
                sel_cc_s = cc_choices[st.selectbox("مركز التكلفة / المشروع:", list(cc_choices.keys()), key="s_cc")]

            # فحص حي فوري للمعرفات الضريبية قبل الإصدار (ZATCA Phase 2 Real-time Tax ID Check)
            seller_vat_chk = ZATCAPhase2Validator.validate_saudi_vat_number(settings.vat_number, party_role="SELLER", required=True)
            buyer_vat_req = (inv_type == InvoiceType.STANDARD)
            buyer_vat_chk = ZATCAPhase2Validator.validate_saudi_vat_number(cust_vat, party_role="BUYER", required=buyer_vat_req)
            if not seller_vat_chk["is_valid"]:
                st.warning(f"⚠️ تنبيه ZATCA (الرقم الضريبي للمنشأة): {seller_vat_chk['message_ar']}")
            if not buyer_vat_chk["is_valid"]:
                st.warning(f"⚠️ تنبيه ZATCA (الرقم الضريبي للعميل): {buyer_vat_chk['message_ar']}")
            elif cust_vat and str(cust_vat).strip():
                st.caption(f"✅ المعرف الضريبي للعميل مطابق لمعيار ZATCA Phase 2 (`{buyer_vat_chk['clean_vat']}` — {buyer_vat_chk['registration_type_ar']})")

            if "invoice_items_count" not in st.session_state:
                st.session_state.invoice_items_count = 1

            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                if st.button("➕ إضافة سطر صنف"):
                    st.session_state.invoice_items_count += 1
                    st.rerun()
            with col_btn2:
                if st.session_state.invoice_items_count > 1 and st.button("➖ حذف آخر سطر"):
                    st.session_state.invoice_items_count -= 1
                    st.rerun()

            invoice_items_list = []
            calc_subtotal = 0.0
            calc_vat = 0.0

            for i in range(st.session_state.invoice_items_count):
                it0, it1, it2, it3, it4, it5 = st.columns([2, 2, 1, 1.2, 1.2, 1])
                with it0:
                    p_key = st.selectbox("الصنف من المخزون:", list(prod_choices.keys()), key=f"s_pk_{i}")
                    p_obj = prod_choices[p_key]
                with it1:
                    i_name = st.text_input("الاسم بالطباعة:", value=p_obj.name_ar if p_obj else "", key=f"it_name_{i}")
                with it2:
                    i_qty = st.number_input("الكمية:", min_value=1.0, value=1.0, step=1.0, key=f"it_qty_{i}")
                with it3:
                    i_price = st.number_input("سعر البيع:", min_value=0.0, value=float(p_obj.sale_price) if p_obj else 0.0, step=10.0, key=f"it_pr_{i}")
                with it4:
                    i_cost = st.number_input("تكلفة الوحدة (WAC):", min_value=0.0, value=float(p_obj.cost_price) if p_obj else 0.0, step=10.0, key=f"it_cst_{i}")
                with it5:
                    i_disc = st.number_input("الخصم:", min_value=0.0, value=0.0, step=5.0, key=f"it_dsc_{i}")

                item_vat_rate = float(p_obj.tax_rate) if p_obj else float(settings.default_vat_rate)
                taxable = max(0.0, (i_qty * i_price) - i_disc)
                vat_val = taxable * item_vat_rate
                calc_subtotal += taxable
                calc_vat += vat_val

                if i_price > 0:
                    invoice_items_list.append({
                        "product_id": p_obj.id if p_obj else None,
                        "item_name": i_name or (p_obj.name_ar if p_obj else f"صنف مبيعات #{i+1}"),
                        "quantity": i_qty,
                        "unit_price": i_price,
                        "cost_price": i_cost,
                        "discount": i_disc,
                        "tax_rate": item_vat_rate
                    })

            st.divider()
            tot1, tot2, tot3 = st.columns(3)
            tot1.metric("الصافي الخاضع للضريبة", f"{calc_subtotal:,.2f} ريال")
            tot2.metric("ضريبة القيمة المضافة (15%)", f"{calc_vat:,.2f} ريال")
            tot3.metric("الإجمالي النهائي المستحق", f"{(calc_subtotal + calc_vat):,.2f} ريال")

            inv_notes = st.text_input("ملاحظات الفاتورة:")
            allow_neg_sale = st.checkbox("السماح بالبيع بالسالب استثنائياً (تجاوز الرصيد المخزني)", value=False, disabled=not has_perm("act_inventory_adjust"))

            if st.button("🚀 إصدار وترحيل الفاتورة الضريبية وخصم المخزون", type="primary", use_container_width=True, disabled=not has_perm("act_create_sales")):
                try:
                    max_disc_allowed = float(st.session_state.get("active_user_info", {}).get("max_discount_pct", 100.0))
                    for idx_it, it_check in enumerate(invoice_items_list, start=1):
                        gross_line = it_check["quantity"] * it_check["unit_price"]
                        disc_pct = (it_check["discount"] / gross_line * 100.0) if gross_line > 0 else 0.0
                        if disc_pct > max_disc_allowed + 0.01:
                            raise LedgerValidationError(
                                f"السطر رقم ({idx_it}): نسبة الخصم الممنوحة ({disc_pct:.1f}%) تتجاوز سقف الخصم المسموح لصلاحياتك ({max_disc_allowed:.1f}%)."
                            )
                    new_inv = LedgerService.create_sales_invoice(
                        db=db, customer_name=cust_name,
                        customer_id=sel_cust_obj.id if sel_cust_obj else None,
                        cost_center_id=sel_cc_s, items_data=invoice_items_list,
                        invoice_date=inv_date, payment_method=pay_method,
                        invoice_type=inv_type, customer_vat_number=cust_vat, notes=inv_notes,
                        allow_negative_stock=allow_neg_sale,
                        treasury_account_code=sel_tr_code_sales,
                        performed_by=get_active_user_label()
                    )
                    st.session_state["latest_invoice_id"] = new_inv.id
                    st.success(f"🎉 تم إصدار الفاتورة الضريبية بنجاح برقم: {new_inv.invoice_number}")
                except Exception as e:
                    st.error(f"❌ خطأ: {str(e)}")

            if "latest_invoice_id" in st.session_state:
                latest_inv = db.query(SalesInvoice).filter(SalesInvoice.id == st.session_state["latest_invoice_id"]).first()
                if latest_inv:
                    inv_html = PrintTemplateService.generate_sales_invoice_html(latest_inv, settings)
                    components.html(inv_html, height=700, scrolling=True)

        with tab_return:
            invs = db.query(SalesInvoice).order_by(SalesInvoice.id.desc()).all()
            inv_map = {"-- بدون ربط بفاتورة محددة --": None}
            for iv in invs:
                inv_map[f"{iv.invoice_number} | {iv.customer_name} ({iv.grand_total:,.2f} ريال)"] = iv

            cn1, cn2, cn3 = st.columns(3)
            with cn1:
                orig_inv = inv_map[st.selectbox("الفاتورة الأصلية:", list(inv_map.keys()))]
            with cn2:
                cn_party = st.text_input("اسم العميل في الإشعار:", value=orig_inv.customer_name if orig_inv else "")
            with cn3:
                cn_reason = st.text_input("سبب إصدار الإشعار الدائن:", value="مرتجع بضاعة طبقاً للاتفاق")

            if "cn_items_count" not in st.session_state:
                st.session_state.cn_items_count = 1

            cn_b1, cn_b2, cn_b3 = st.columns(3)
            with cn_b1:
                if st.button("➕ إضافة سطر صنف مرتجع مبيعات"):
                    st.session_state.cn_items_count += 1
                    st.rerun()
            with cn_b2:
                if st.session_state.cn_items_count > 1 and st.button("➖ حذف آخر سطر مرتجع مبيعات"):
                    st.session_state.cn_items_count -= 1
                    st.rerun()
            with cn_b3:
                if orig_inv and orig_inv.items and st.button("📥 جلب كافة أصناف الفاتورة الأصلية تلقائياً"):
                    st.session_state.cn_items_count = len(orig_inv.items)
                    st.session_state["cn_prefill_inv_id"] = orig_inv.id
                    st.rerun()

            cn_items_list = []
            orig_items_list = list(orig_inv.items) if (orig_inv and orig_inv.items) else []
            prod_by_id = {p.id: p for p in products}
            prod_key_by_id = {p.id: k for k, p in prod_choices.items() if p is not None}

            for idx_cn in range(st.session_state.cn_items_count):
                prefill_it = orig_items_list[idx_cn] if idx_cn < len(orig_items_list) else None
                default_pk_idx = 0
                if prefill_it and prefill_it.product_id in prod_key_by_id:
                    default_pk_idx = list(prod_choices.keys()).index(prod_key_by_id[prefill_it.product_id])

                cn4, cn5, cn6, cn7 = st.columns([2, 2, 1, 1.2])
                with cn4:
                    cn_prod = prod_choices[st.selectbox(f"الصنف المرتجع #{idx_cn+1}:", list(prod_choices.keys()), index=default_pk_idx, key=f"cn_pk_{idx_cn}")]
                with cn5:
                    default_iname = prefill_it.item_name if prefill_it else (cn_prod.name_ar if cn_prod else f"بند مرتجع مبيعات #{idx_cn+1}")
                    cn_item_name = st.text_input("وصف البند المرتجع:", value=default_iname, key=f"cn_inm_{idx_cn}")
                with cn6:
                    default_qty = float(prefill_it.quantity) if prefill_it else 1.0
                    cn_qty = st.number_input("الكمية المرتجعة:", min_value=1.0, value=default_qty, step=1.0, key=f"cn_qty_{idx_cn}")
                with cn7:
                    default_pr = float(prefill_it.unit_price) if prefill_it else (float(cn_prod.sale_price) if cn_prod else 100.0)
                    cn_price = st.number_input("سعر الوحدة المرتجعة:", min_value=0.0, value=default_pr, step=10.0, key=f"cn_pr_{idx_cn}")

                if cn_price > 0:
                    cn_items_list.append({
                        "product_id": cn_prod.id if cn_prod else (prefill_it.product_id if prefill_it else None),
                        "item_name": cn_item_name,
                        "quantity": cn_qty,
                        "unit_price": cn_price,
                        "cost_price": float(cn_prod.cost_price) if cn_prod else (float(prefill_it.cost_price) if prefill_it else 0.0),
                        "tax_rate": float(cn_prod.tax_rate) if cn_prod else float(settings.default_vat_rate)
                    })

            cn_pay_label = st.selectbox("طريقة تسوية الإشعار الدائن:", list(pay_method_map.keys()), key="cn_pay")

            if st.button("🚀 إصدار وترحيل الإشعار الدائن", type="primary", disabled=not has_perm("act_create_sales")):
                try:
                    cn_obj = LedgerService.create_credit_debit_note(
                        db=db, note_type=NoteType.CREDIT_NOTE, party_name=cn_party or "عميل عام",
                        party_vat_number=orig_inv.customer_vat_number if orig_inv else None,
                        original_invoice_number=orig_inv.invoice_number if orig_inv else None,
                        sales_invoice_id=orig_inv.id if orig_inv else None,
                        customer_id=orig_inv.customer_id if orig_inv else None,
                        payment_method=pay_method_map[cn_pay_label],
                        treasury_account_code=pay_treasury_code_map[cn_pay_label],
                        reason=cn_reason,
                        items_data=cn_items_list,
                        performed_by=get_active_user_label()
                    )
                    st.session_state["latest_cn_id"] = cn_obj.id
                    st.success(f"✅ تم إصدار الإشعار الدائن برقم: {cn_obj.note_number}")
                except Exception as e:
                    st.error(f"❌ خطأ: {str(e)}")

            if "latest_cn_id" in st.session_state:
                cn_latest = db.query(CreditDebitNote).filter(CreditDebitNote.id == st.session_state["latest_cn_id"]).first()
                if cn_latest:
                    cn_html = PrintTemplateService.generate_credit_debit_note_html(cn_latest, settings)
                    components.html(cn_html, height=620, scrolling=True)

        with tab_history:
            invoices = db.query(SalesInvoice).order_by(SalesInvoice.id.desc()).all()
            if invoices:
                inv_opts = {f"فاتورة {i.invoice_number} | {i.customer_name} ({i.grand_total:,.2f} ريال)": i for i in invoices}
                sel_i_obj = inv_opts[st.selectbox("اختر فاتورة مبيعات لطباعتها:", list(inv_opts.keys()))]
                html_doc = PrintTemplateService.generate_sales_invoice_html(sel_i_obj, settings)
                components.html(html_doc, height=680, scrolling=True)

        with tab_zatca_p2:
            st.markdown("#### **🛡️ محرك التحقق من الفوترة الإلكترونية للمرحلة الثانية (ZATCA Fatoora Phase 2 — الربط والتكامل)**")
            st.caption(
                "يفحص هذا المحرك كافة المستندات المالية (فواتير المبيعات، فواتير المشتريات، الإشعارات الدائنة والمدينة، وسندات الخزينة) "
                "وفق قواعد هيئة الزكاة والضريبة والجمارك للمرحلة الثانية (`BR-KSA-39`, `BR-KSA-40`, `BR-KSA-68`, `KSA-1 UUID`, `KSA-13 PIH`, `KSA-16 ICV`, `TLV Tags 1..9`, `UBL 2.1 XML`)."
            )
            audit_summary = ZATCAPhase2Validator.audit_all_database_documents(db, auto_upgrade_phase2=True)
            zm1, zm2, zm3, zm4 = st.columns(4)
            zm1.metric("إجمالي المستندات المالية المفحوصة", f"{audit_summary['total_documents']}")
            zm2.metric("المستندات المتوافقة 100% (Phase 2)", f"{audit_summary['compliant_documents']}")
            zm3.metric("نسبة امتثال ZATCA Phase 2", f"{audit_summary['overall_compliance_pct']:.1f}%")
            zm4.metric("مستندات تم ترقية ختمها التشفيري", f"{audit_summary['upgraded_count']}")

            if audit_summary["reports"]:
                doc_choices_p2 = {
                    f"[{r['doc_title_ar']}] {r['doc_number']} | {r['counterparty_name']} ({r['grand_total']:,.2f} ريال) — {'✅ متوافق' if r['phase2_compliant'] else '❌ غير متوافق'}": r
                    for r in audit_summary["reports"]
                }
                sel_rep_lbl = st.selectbox("🔍 اختر مستنداً مالياً لفحص قواعد ZATCA Phase 2 والـ QR TLV (Tags 1–9) والمجسم التشفيري 3D:", list(doc_choices_p2.keys()))
                sel_rep = doc_choices_p2[sel_rep_lbl]

                # عرض المشهد التفاعلي ثلاثي الأبعاد (Three.js 3D Cryptographic & QR Voxel Inspector)
                st.markdown("##### **🌐 المعاين التفاعلي ثلاثي الأبعاد للختم التشفيري وباركود المرحلة الثانية (3D ZATCA Cryptographic & QR Voxel Inspector):**")
                three_html = ZATCAPhase2Validator.render_zatca_3d_inspector_html(sel_rep)
                components.html(three_html, height=540, scrolling=False)

                z_col1, z_col2 = st.columns([1.25, 1])
                with z_col1:
                    st.markdown("##### **📋 نتائج فحص قواعد الأعمال السعودية (`BR-KSA-*` & `BR-CO-*`):**")
                    rules_df = pd.DataFrame([
                        {
                            "كود القاعدة": rc["rule_id"],
                            "اسم القاعدة": rc["title_ar"],
                            "الحالة": "✅ مطابق" if rc["passed"] else "❌ مخالف",
                            "التفاصيل الفنية": rc["details_ar"]
                        }
                        for rc in sel_rep["checks"]
                    ])
                    st.dataframe(rules_df, use_container_width=True, hide_index=True)

                with z_col2:
                    st.markdown("##### **🔐 تفكيك حقول باركود TLV للمرحلة الثانية (Tags 1–9):**")
                    qr_tags = sel_rep.get("decoded_qr", {}).get("tags", {})
                    tlv_rows = []
                    for t_id in range(1, 10):
                        t_info = qr_tags.get(t_id, {})
                        spec_info = ZATCA_TLV_TAG_SPECS.get(t_id, {})
                        val_disp = str(t_info.get("value", "غير موجود"))
                        if len(val_disp) > 42:
                            val_disp = val_disp[:39] + "..."
                        tlv_rows.append({
                            "Tag": f"Tag {t_id}",
                            "البيان (ZATCA Spec)": spec_info.get("name_ar", f"Tag {t_id}"),
                            "الطول (Bytes)": t_info.get("byte_length", 0),
                            "القيمة المفككة": val_disp,
                        })
                    st.dataframe(pd.DataFrame(tlv_rows), use_container_width=True, hide_index=True)

                with st.expander("📄 استعراض وتحميل ملف الفاتورة الإلكترونية القياسي (ZATCA UBL 2.1 XML & TLV Base64)"):
                    st.text_area("TLV Base64 QR Payload (Tags 1–9):", value=sel_rep["qr_code_base64"], height=68)
                    st.code(sel_rep["ubl_xml"], language="xml")
                    st.download_button(
                        "📥 تحميل ملف الفاتورة الإلكترونية (ZATCA UBL 2.1 XML)",
                        data=sel_rep["ubl_xml"].encode("utf-8"),
                        file_name=f"ZATCA_Phase2_{sel_rep['doc_number']}.xml",
                        mime="application/xml",
                        key=f"dl_xml_{sel_rep['doc_number']}"
                    )

            st.divider()
            st.markdown("#### **📲 أداة توليد وفك تشفير باركود الفاتورة الإلكترونية (ZATCA Phase 2 TLV Base64 QR Generator & Decoder)**")
            st.caption(
                "توليد وفك تشفير رموز الاستجابة السريعة (`TLV Base64`) المتوافقة مع المرحلة الثانية لهيئة الزكاة والضريبة والجمارك "
                "شاملةً: اسم البائع (`Tag 1`)، الرقم الضريبي 15 رقماً (`Tag 2`)، الطابع الزمني القياسي `ISO-8601` (`Tag 3`)، "
                "إجمالي الفاتورة مع الضريبة (`Tag 4`)، مبلغ الضريبة (`Tag 5`)، وأختام التشفير الرقمية للمرحلة الثانية (`Tags 6–9`)."
            )

            qr_u_col1, qr_u_col2 = st.columns([1.15, 1])
            with qr_u_col1:
                u_seller = st.text_input("1️⃣ اسم البائع (Seller Name — Tag 1 UTF-8):", value=settings.company_name_ar, key="z_qr_u_seller")
                u_vat_no = st.text_input("2️⃣ الرقم الضريبي للبائع (VAT Number — Tag 2, 15 digits):", value=settings.vat_number, key="z_qr_u_vat")
                u_ts_iso = st.text_input("3️⃣ الطابع الزمني للفاتورة (ISO-8601 Timestamp — Tag 3):", value=format_zatca_timestamp(), key="z_qr_u_ts")
                u_c1, u_c2 = st.columns(2)
                with u_c1:
                    u_inv_total = st.number_input("4️⃣ إجمالي الفاتورة شامل الضريبة (Tag 4):", min_value=0.0, value=1150.00, step=50.0, format="%.2f", key="z_qr_u_tot")
                with u_c2:
                    default_u_vat = round(u_inv_total - (u_inv_total / 1.15), 2)
                    u_vat_total = st.number_input("5️⃣ مبلغ ضريبة القيمة المضافة 15% (Tag 5):", min_value=0.0, value=default_u_vat, step=7.5, format="%.2f", key="z_qr_u_vtot")
                u_phase2_chk = st.checkbox("تضمين أختام المرحلة الثانية التشفيرية (Phase 2 Cryptographic Tags 6–9: SHA-256 XML Hash + ECDSA + Public Key + CSID)", value=True, key="z_qr_u_p2")

            with qr_u_col2:
                try:
                    gen_b64 = generate_zatca_tlv_qr_base64(
                        seller_name=u_seller,
                        vat_number=u_vat_no,
                        timestamp=u_ts_iso,
                        invoice_total=u_inv_total,
                        vat_total=u_vat_total,
                        phase2=u_phase2_chk,
                    )
                    dec_info = decode_zatca_tlv_qr_base64(gen_b64)
                    svg_uri = LedgerService.generate_qr_svg_data_uri(gen_b64, size=150)
                    st.markdown(
                        f"""
                        <div style="background:#FFFFFF; border:1px solid #CBD5E1; border-radius:10px; padding:14px; text-align:center;">
                            <img src="{svg_uri}" width="145" height="145" style="border:1px solid #E2E8F0; padding:4px; border-radius:8px;" />
                            <div style="font-size:12px; font-weight:700; color:#0F172A; margin-top:6px;">
                                ZATCA TLV Base64 QR ({dec_info['raw_byte_length']} Bytes | {'Phase 2 Tags 1–9' if dec_info['has_phase2_tags'] else 'Phase 1 Tags 1–5'}) ✅
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    st.text_area("📦 سلسلة الباركود المشفرة (Base64 TLV Output):", value=gen_b64, height=86, key="z_qr_u_b64_out")
                except Exception as qr_err:
                    gen_b64 = ""
                    st.error(f"❌ خطأ في التحقق من بيانات الباركود: {qr_err}")

            if gen_b64:
                seg_rows = ZATCATLVQRGenerator.inspect_tlv_binary_segments(gen_b64)
                if seg_rows:
                    with st.expander("🔬 تشريح البنية الثنائية لحقول TLV بايت ببايت (Binary TLV Tag-Length-Value Breakdown)", expanded=False):
                        st.dataframe(
                            pd.DataFrame([
                                {
                                    "رقم الحقل (Tag)": f"Tag {r['tag_number']} ({r['tag_hex']})",
                                    "الكود القياسي": r["code"],
                                    "المرحلة": r["phase"],
                                    "البيان": r["name_ar"],
                                    "الطول (Bytes)": f"{r['length_bytes']} ({r['length_hex']})",
                                    "القيمة المفككة (UTF-8 / Base64)": r["value"][:56] + ("..." if len(r["value"]) > 56 else ""),
                                    "أول 16 بايت (Hex)": r["hex_preview"],
                                }
                                for r in seg_rows
                            ]),
                            use_container_width=True,
                            hide_index=True,
                        )

            # سجل موحد لرموز QR TLV Base64 لكافة الفواتير والإشعارات في النظام
            if audit_summary["reports"]:
                with st.expander("📋 سجل رموز الاستجابة السريعة (ZATCA Base64 TLV QR Registry) لكافة الفواتير والإشعارات المسجلة", expanded=False):
                    inv_qr_rows = []
                    for r in audit_summary["reports"]:
                        d_qr = decode_zatca_tlv_qr_base64(r.get("qr_code_base64", ""))
                        inv_qr_rows.append({
                            "رقم المستند": r["doc_number"],
                            "نوع المستند": r["doc_title_ar"],
                            "اسم البائع (Tag 1)": d_qr.get("seller_name", r["seller_name"]),
                            "الرقم الضريبي (Tag 2)": d_qr.get("vat_number", r["seller_vat"]),
                            "الطابع الزمني ISO-8601 (Tag 3)": d_qr.get("timestamp", "-"),
                            "إجمالي الفاتورة (Tag 4)": d_qr.get("invoice_total", f"{r['grand_total']:.2f}"),
                            "إجمالي الضريبة (Tag 5)": d_qr.get("vat_total", f"{r['vat_amount']:.2f}"),
                            "حجم TLV (Bytes)": d_qr.get("raw_byte_length", 0),
                            "حالة Phase 2 (Tags 1–9)": "مكتمل ✅" if d_qr.get("has_phase2_tags") else "جزئي ⚠️",
                            "Base64 TLV Payload": (r.get("qr_code_base64") or "")[:44] + "...",
                        })
                    st.dataframe(pd.DataFrame(inv_qr_rows), use_container_width=True, hide_index=True)
    finally:
        db.close()


# =============================================================================
# 9. الشاشة 7: دورة المشتريات وإشعارات المدين (Purchases & Debit Notes)
# =============================================================================
elif menu_option == "📥 المشتريات وإشعارات المدين":
    st.markdown("### **دورة المشتريات وتوريد المخزون وإشعارات المدين**")
    tab_pur_create, tab_pur_return, tab_pur_history = st.tabs([
        "📝 تسجيل فاتورة مشتريات جديدة",
        "↩️ إصدار إشعار مدين (مرتجع مشتريات)",
        "📂 أرشيف فواتير المشتريات"
    ])

    db = get_db_session()
    try:
        settings = LedgerService.get_company_settings(db)
        suppliers = db.query(Supplier).filter(Supplier.is_active == True).all()
        products = db.query(Product).filter(Product.is_active == True, Product.is_service == False).all()
        cost_centers = db.query(CostCenter).all()
        cc_choices = {"-- بدون مركز تكلفة محدد --": None}
        for cc in cost_centers:
            cc_choices[f"{cc.code} - {cc.name_ar}"] = cc.id

        tr_accounts_p = LedgerService.get_treasury_and_bank_accounts(db)
        pay_method_map = {"بالأجل (على حساب المورد)": PaymentMethod.CREDIT}
        pay_treasury_code_map_p = {"بالأجل (على حساب المورد)": None}
        for tr_a in tr_accounts_p:
            if tr_a.code.startswith("1101"):
                lbl = f"نقداً ({tr_a.name_ar} - {tr_a.code})"
                pay_method_map[lbl] = PaymentMethod.CASH
                pay_treasury_code_map_p[lbl] = tr_a.code
            else:
                lbl = f"تحويل بنكي ({tr_a.name_ar} - {tr_a.code})"
                pay_method_map[lbl] = PaymentMethod.BANK
                pay_treasury_code_map_p[lbl] = tr_a.code

        prod_choices = {"-- صنف حر / يدوي --": None}
        for p in products:
            prod_choices[f"{p.code} - {p.name_ar} (الرصيد: {p.stock_quantity:,.0f} | WAC: {p.cost_price:,.2f})"] = p

        with tab_pur_create:
            supp_choices = {"-- إدخال مورد يدوي --": None}
            for s in suppliers:
                supp_choices[f"{s.code} - {s.name_ar}"] = s

            p0, p1, p2, p3 = st.columns(4)
            with p0:
                sel_supp = supp_choices[st.selectbox("اختيار من سجل الموردين:", list(supp_choices.keys()))]
            with p1:
                supp_name = st.text_input("اسم المورد:", value=sel_supp.name_ar if sel_supp else "")
            with p2:
                supp_vat = st.text_input("الرقم الضريبي للمورد:", value=(sel_supp.vat_number or "") if sel_supp else "")
            with p3:
                supp_inv_no = st.text_input("رقم فاتورة المورد الأصلية:")

            p4, p5, p6 = st.columns(3)
            with p4:
                pur_date = st.date_input("تاريخ فاتورة الشراء:", value=date.today())
            with p5:
                sel_pur_pay_lbl = st.selectbox("طريقة السداد للمورد:", list(pay_method_map.keys()))
                pur_pay_method = pay_method_map[sel_pur_pay_lbl]
                sel_tr_code_pur = pay_treasury_code_map_p[sel_pur_pay_lbl]
            with p6:
                sel_cc_p = cc_choices[st.selectbox("مركز التكلفة / المشروع:", list(cc_choices.keys()), key="p_cc")]

            if "purchase_items_count" not in st.session_state:
                st.session_state.purchase_items_count = 1

            p_btn1, p_btn2 = st.columns(2)
            with p_btn1:
                if st.button("➕ إضافة سطر صنف مشتريات"):
                    st.session_state.purchase_items_count += 1
                    st.rerun()
            with p_btn2:
                if st.session_state.purchase_items_count > 1 and st.button("➖ حذف آخر سطر مشتريات"):
                    st.session_state.purchase_items_count -= 1
                    st.rerun()

            purchase_items_list = []
            for i in range(st.session_state.purchase_items_count):
                pi0, pi1, pi2, pi3, pi4 = st.columns([2.2, 2, 1, 1.2, 1])
                with pi0:
                    p_obj = prod_choices[st.selectbox("الصنف المخزني:", list(prod_choices.keys()), key=f"p_pk_{i}")]
                with pi1:
                    p_name = st.text_input("وصف البند:", value=p_obj.name_ar if p_obj else "", key=f"pi_name_{i}")
                with pi2:
                    p_qty = st.number_input("الكمية المشتراة:", min_value=1.0, value=1.0, step=1.0, key=f"pi_qty_{i}")
                with pi3:
                    p_price = st.number_input("سعر الشراء للوحدة:", min_value=0.0, value=float(p_obj.cost_price) if p_obj else 0.0, step=10.0, key=f"pi_pr_{i}")
                with pi4:
                    p_disc = st.number_input("الخصم المكتسب:", min_value=0.0, value=0.0, step=5.0, key=f"pi_dsc_{i}")

                if p_price > 0:
                    purchase_items_list.append({
                        "product_id": p_obj.id if p_obj else None,
                        "item_name": p_name or (p_obj.name_ar if p_obj else f"صنف مشتريات #{i+1}"),
                        "quantity": p_qty, "unit_price": p_price, "discount": p_disc, "tax_rate": float(p_obj.tax_rate) if p_obj else float(settings.default_vat_rate)
                    })

            if st.button("🚀 تسجيل فاتورة المشتريات وتحديث المخزون ومتوسط التكلفة (WAC)", type="primary", use_container_width=True, disabled=not has_perm("act_create_purchases")):
                try:
                    new_pur = LedgerService.create_purchase_invoice(
                        db=db, supplier_name=supp_name, supplier_id=sel_supp.id if sel_supp else None,
                        cost_center_id=sel_cc_p, items_data=purchase_items_list, invoice_date=pur_date,
                        payment_method=pur_pay_method, supplier_vat_number=supp_vat,
                        supplier_invoice_number=supp_inv_no, treasury_account_code=sel_tr_code_pur,
                        performed_by=get_active_user_label()
                    )
                    st.session_state["latest_purchase_id"] = new_pur.id
                    st.success(f"🎉 تم تسجيل فاتورة المشتريات برقم: {new_pur.invoice_number} وتوليد رمز ZATCA TLV QR تلقائياً")
                except Exception as e:
                    st.error(f"❌ {str(e)}")

            if "latest_purchase_id" in st.session_state:
                latest_pur = db.query(PurchaseInvoice).filter(PurchaseInvoice.id == st.session_state["latest_purchase_id"]).first()
                if latest_pur:
                    pur_html = PrintTemplateService.generate_purchase_invoice_html(latest_pur, settings)
                    components.html(pur_html, height=680, scrolling=True)

        with tab_pur_return:
            pinvs = db.query(PurchaseInvoice).order_by(PurchaseInvoice.id.desc()).all()
            pinv_map = {"-- بدون ربط بفاتورة شراء محددة --": None}
            for piv in pinvs:
                pinv_map[f"{piv.invoice_number} | {piv.supplier_name} ({piv.grand_total:,.2f} ريال)"] = piv

            dn1, dn2, dn3 = st.columns(3)
            with dn1:
                orig_pinv = pinv_map[st.selectbox("فاتورة الشراء الأصلية:", list(pinv_map.keys()))]
            with dn2:
                dn_party = st.text_input("اسم المورد في الإشعار المدين:", value=orig_pinv.supplier_name if orig_pinv else "")
            with dn3:
                dn_reason = st.text_input("سبب إصدار الإشعار المدين:", value="رد بضاعة غير مطابقة للمواصفات للمورد")

            if "dn_items_count" not in st.session_state:
                st.session_state.dn_items_count = 1

            dn_b1, dn_b2, dn_b3 = st.columns(3)
            with dn_b1:
                if st.button("➕ إضافة سطر صنف مرتجع مشتريات"):
                    st.session_state.dn_items_count += 1
                    st.rerun()
            with dn_b2:
                if st.session_state.dn_items_count > 1 and st.button("➖ حذف آخر سطر مرتجع مشتريات"):
                    st.session_state.dn_items_count -= 1
                    st.rerun()
            with dn_b3:
                if orig_pinv and orig_pinv.items and st.button("📥 جلب كافة أصناف فاتورة الشراء الأصلية تلقائياً"):
                    st.session_state.dn_items_count = len(orig_pinv.items)
                    st.rerun()

            dn_items_list = []
            orig_pitems_list = list(orig_pinv.items) if (orig_pinv and orig_pinv.items) else []
            prod_key_by_id_p = {p.id: k for k, p in prod_choices.items() if p is not None}

            for idx_dn in range(st.session_state.dn_items_count):
                prefill_pit = orig_pitems_list[idx_dn] if idx_dn < len(orig_pitems_list) else None
                default_dpk_idx = 0
                if prefill_pit and prefill_pit.product_id in prod_key_by_id_p:
                    default_dpk_idx = list(prod_choices.keys()).index(prod_key_by_id_p[prefill_pit.product_id])

                dn4, dn5, dn6, dn7 = st.columns([2, 2, 1, 1.2])
                with dn4:
                    dn_prod = prod_choices[st.selectbox(f"الصنف المرتجع للمورد #{idx_dn+1}:", list(prod_choices.keys()), index=default_dpk_idx, key=f"dn_pk_{idx_dn}")]
                with dn5:
                    def_dname = prefill_pit.item_name if prefill_pit else (dn_prod.name_ar if dn_prod else f"بند مرتجع مشتريات #{idx_dn+1}")
                    dn_item_name = st.text_input("وصف البند المرتجع:", value=def_dname, key=f"dn_iname_{idx_dn}")
                with dn6:
                    def_dqty = float(prefill_pit.quantity) if prefill_pit else 1.0
                    dn_qty = st.number_input("الكمية المرتجعة للمورد:", min_value=1.0, value=def_dqty, step=1.0, key=f"dn_qty_{idx_dn}")
                with dn7:
                    def_dpr = float(prefill_pit.unit_price) if prefill_pit else (float(dn_prod.cost_price) if dn_prod else 100.0)
                    dn_price = st.number_input("سعر الشراء للوحدة المرتجعة:", min_value=0.0, value=def_dpr, step=10.0, key=f"dn_pr_{idx_dn}")

                if dn_price > 0:
                    dn_items_list.append({
                        "product_id": dn_prod.id if dn_prod else (prefill_pit.product_id if prefill_pit else None),
                        "item_name": dn_item_name,
                        "quantity": dn_qty,
                        "unit_price": dn_price,
                        "cost_price": float(dn_prod.cost_price) if dn_prod else dn_price,
                        "tax_rate": float(dn_prod.tax_rate) if dn_prod else float(settings.default_vat_rate)
                    })

            dn_pay_label = st.selectbox("طريقة تسوية الإشعار المدين مع المورد:", list(pay_method_map.keys()), key="dn_pay")

            if st.button("🚀 إصدار وترحيل الإشعار المدين وخصم المخزون", type="primary", disabled=not has_perm("act_create_purchases")):
                try:
                    dn_obj = LedgerService.create_credit_debit_note(
                        db=db, note_type=NoteType.DEBIT_NOTE, party_name=dn_party or "مورد عام",
                        party_vat_number=orig_pinv.supplier_vat_number if orig_pinv else None,
                        original_invoice_number=orig_pinv.invoice_number if orig_pinv else None,
                        purchase_invoice_id=orig_pinv.id if orig_pinv else None,
                        supplier_id=orig_pinv.supplier_id if orig_pinv else None,
                        payment_method=pay_method_map[dn_pay_label],
                        treasury_account_code=pay_treasury_code_map_p[dn_pay_label],
                        reason=dn_reason,
                        items_data=dn_items_list,
                        performed_by=get_active_user_label()
                    )
                    st.session_state["latest_dn_id"] = dn_obj.id
                    st.success(f"✅ تم إصدار الإشعار المدين (مرتجع المشتريات) برقم: {dn_obj.note_number}")
                except Exception as e:
                    st.error(f"❌ خطأ: {str(e)}")

            if "latest_dn_id" in st.session_state:
                dn_latest = db.query(CreditDebitNote).filter(CreditDebitNote.id == st.session_state["latest_dn_id"]).first()
                if dn_latest:
                    dn_html = PrintTemplateService.generate_credit_debit_note_html(dn_latest, settings)
                    components.html(dn_html, height=620, scrolling=True)

        with tab_pur_history:
            purchases = db.query(PurchaseInvoice).order_by(PurchaseInvoice.id.desc()).all()
            if purchases:
                pur_options = {f"{p.invoice_number} | المورد: {p.supplier_name} | بمبلغ: {p.grand_total:,.2f} ريال": p for p in purchases}
                selected_purchase = pur_options[st.selectbox("اختر فاتورة المشتريات:", list(pur_options.keys()))]
                pur_render_html = PrintTemplateService.generate_purchase_invoice_html(selected_purchase, settings)
                components.html(pur_render_html, height=680, scrolling=True)
    finally:
        db.close()


# =============================================================================
# 10. الشاشة 8: سندات القبض والصرف (Treasury & Cash/Bank Vouchers)
# =============================================================================
elif menu_option == "💸 سندات القبض والصرف (الخزينة)":
    st.markdown("### **إدارة الخزينة والبنوك: سندات القبض وسندات الصرف**")
    t_rv, t_pv, t_vhist = st.tabs([
        "🟢 إصدار سند قبض (مقبوضات)",
        "🟠 إصدار سند صرف (مدفوعات ومصروفات)",
        "📂 سجل وطباعة السندات"
    ])

    db = get_db_session()
    try:
        settings = LedgerService.get_company_settings(db)
        customers = db.query(Customer).all()
        suppliers = db.query(Supplier).all()
        leaf_accounts = db.query(Account).filter(Account.is_leaf == True, Account.is_active == True).order_by(Account.code).all()
        acc_map = {f"{a.code} - {a.name_ar}": a.code for a in leaf_accounts}
        cost_centers = db.query(CostCenter).all()
        cc_choices = {"-- بدون مركز تكلفة محدد --": None}
        for cc in cost_centers:
            cc_choices[f"{cc.code} - {cc.name_ar}"] = cc.id

        tr_accounts_v = LedgerService.get_treasury_and_bank_accounts(db)
        pay_map = {}
        pay_tr_code_map = {}
        for tr_a in tr_accounts_v:
            if tr_a.code.startswith("1101"):
                lbl = f"نقداً ({tr_a.name_ar} - {tr_a.code})"
                pay_map[lbl] = PaymentMethod.CASH
                pay_tr_code_map[lbl] = tr_a.code
            else:
                lbl = f"تحويل بنكي / شبكة ({tr_a.name_ar} - {tr_a.code})"
                pay_map[lbl] = PaymentMethod.BANK
                pay_tr_code_map[lbl] = tr_a.code
        if not pay_map:
            pay_map = {
                "نقداً (الصندوق الرئيسي - 110101)": PaymentMethod.CASH,
                "تحويل بنكي / شبكة (البنك الرئيسي - 110201)": PaymentMethod.BANK
            }
            pay_tr_code_map = {
                "نقداً (الصندوق الرئيسي - 110101)": "110101",
                "تحويل بنكي / شبكة (البنك الرئيسي - 110201)": "110201"
            }

        with t_rv:
            r1, r2, r3 = st.columns(3)
            with r1:
                rv_party_type_lbl = st.selectbox("نوع جهة السداد:", ["عميل تجاري (حساب العملاء)", "حساب أستاذ عام آخر"])
                rv_party_type = VoucherPartyType.CUSTOMER if "عميل" in rv_party_type_lbl else VoucherPartyType.OTHER
            with r2:
                rv_pay_lbl = st.selectbox("حساب الصندوق / البنك المستلم:", list(pay_map.keys()), key="rv_pay")
            with r3:
                rv_date = st.date_input("تاريخ سند القبض:", value=date.today(), key="rv_dt")

            if rv_party_type == VoucherPartyType.CUSTOMER and customers:
                c_opts = {f"{c.code} - {c.name_ar}": c for c in customers}
                sel_c_rv = c_opts[st.selectbox("اختر العميل:", list(c_opts.keys()), key="rv_cust")]
                rv_party_name = sel_c_rv.name_ar
                rv_cust_id = sel_c_rv.id
                rv_target_acc = "110301"
            else:
                rv_party_name = st.text_input("اسم الدافع / الجهة:", key="rv_pname")
                rv_cust_id = None
                rv_target_acc = acc_map[st.selectbox("الحساب الدائن المقابل:", list(acc_map.keys()), key="rv_acc")]

            r4, r5, r6 = st.columns([1, 2, 1])
            with r4:
                rv_amount = st.number_input("المبلغ المحصل (ريال):", min_value=0.0, step=100.0, key="rv_amt")
            with r5:
                rv_desc = st.text_input("البيان:", placeholder="تحصيل دفعة من حساب العميل", key="rv_desc")
            with r6:
                rv_cc = cc_choices[st.selectbox("مركز التكلفة:", list(cc_choices.keys()), key="rv_cc")]

            if st.button("🚀 حفظ وترحيل سند القبض", type="primary", use_container_width=True, disabled=not has_perm("act_create_vouchers")):
                try:
                    v_obj = LedgerService.create_cash_voucher(
                        db=db, voucher_type=VoucherType.RECEIPT, party_type=rv_party_type,
                        party_name=rv_party_name or "عميل", amount=rv_amount,
                        description=rv_desc or "تحصيل دفعة", voucher_date=rv_date,
                        payment_method=pay_map[rv_pay_lbl],
                        treasury_account_code=pay_tr_code_map[rv_pay_lbl],
                        target_account_code=rv_target_acc,
                        customer_id=rv_cust_id, cost_center_id=rv_cc,
                        performed_by=get_active_user_label()
                    )
                    st.success(f"✅ تم إصدار سند القبض برقم: {v_obj.voucher_number}")
                except Exception as e:
                    st.error(f"❌ {str(e)}")

        with t_pv:
            p1, p2, p3 = st.columns(3)
            with p1:
                pv_party_type_lbl = st.selectbox("نوع المستفيد:", ["مورد تجاري (سداد موردين)", "مصروف تشغيلي / حساب أستاذ عام"])
                pv_party_type = VoucherPartyType.SUPPLIER if "مورد" in pv_party_type_lbl else VoucherPartyType.EXPENSE
            with p2:
                pv_pay_lbl = st.selectbox("حساب الصندوق / البنك الدافع:", list(pay_map.keys()), key="pv_pay")
            with p3:
                pv_date = st.date_input("تاريخ سند الصرف:", value=date.today(), key="pv_dt")

            if pv_party_type == VoucherPartyType.SUPPLIER and suppliers:
                s_opts = {f"{s.code} - {s.name_ar}": s for s in suppliers}
                sel_s_pv = s_opts[st.selectbox("اختر المورد المستفيد:", list(s_opts.keys()), key="pv_supp")]
                pv_party_name = sel_s_pv.name_ar
                pv_supp_id = sel_s_pv.id
                pv_target_acc = "210101"
                pv_inc_vat = False
            else:
                pv_party_name = st.text_input("اسم المستفيد / الجهة:", key="pv_pname")
                pv_supp_id = None
                pv_target_acc = acc_map[st.selectbox("حساب المصروف / الحساب المدين:", list(acc_map.keys()), key="pv_acc")]
                pv_inc_vat = st.checkbox("المبلغ شامل ضريبة القيمة المضافة 15% (فصل ضريبة المدخلات آلياً)", value=False)

            p4, p5, p6 = st.columns([1, 2, 1])
            with p4:
                pv_amount = st.number_input("المبلغ المنصرف (ريال):", min_value=0.0, step=100.0, key="pv_amt")
            with p5:
                pv_desc = st.text_input("البيان:", placeholder="سداد دفعة للمورد أو مصروفات تشغيلية", key="pv_desc")
            with p6:
                pv_cc = cc_choices[st.selectbox("مركز التكلفة:", list(cc_choices.keys()), key="pv_cc")]

            if st.button("🚀 حفظ وترحيل سند الصرف", type="primary", use_container_width=True, disabled=not has_perm("act_create_vouchers")):
                try:
                    v_obj = LedgerService.create_cash_voucher(
                        db=db, voucher_type=VoucherType.PAYMENT, party_type=pv_party_type,
                        party_name=pv_party_name or "مستفيد", amount=pv_amount,
                        description=pv_desc or "سداد مستحقات", voucher_date=pv_date,
                        payment_method=pay_map[pv_pay_lbl],
                        treasury_account_code=pay_tr_code_map[pv_pay_lbl],
                        target_account_code=pv_target_acc,
                        supplier_id=pv_supp_id, cost_center_id=pv_cc, include_input_vat=pv_inc_vat,
                        performed_by=get_active_user_label()
                    )
                    st.success(f"✅ تم إصدار سند الصرف برقم: {v_obj.voucher_number}")
                except Exception as e:
                    st.error(f"❌ {str(e)}")

        with t_vhist:
            vouchers = db.query(CashVoucher).order_by(CashVoucher.id.desc()).all()
            if vouchers:
                v_opts = {f"{v.voucher_number} | {v.party_name} | {v.total_amount:,.2f} ريال": v for v in vouchers}
                sel_v = v_opts[st.selectbox("اختر السند لعرضه وطباعته:", list(v_opts.keys()))]
                v_html = PrintTemplateService.generate_cash_voucher_html(sel_v, settings)
                components.html(v_html, height=500, scrolling=True)
    finally:
        db.close()


# =============================================================================
# 11. الشاشة 9: القيود اليومية ودفتر اليومية العامة
# =============================================================================
elif menu_option == "✍️ القيود اليومية ودفتر اليومية":
    st.markdown("### **تسجيل القيود اليومية وسجل دفتر اليومية العامة**")
    t_new_je, t_log_je = st.tabs(["✍️ تسجيل سند قيد يومية جديد", "📖 دفتر اليومية العامة وعكس القيود"])

    db = get_db_session()
    try:
        with t_new_je:
            leaf_accounts = db.query(Account).filter(Account.is_leaf == True, Account.is_active == True).order_by(Account.code).all()
            account_options = {f"{acc.code} - {acc.name_ar}": acc.code for acc in leaf_accounts}
            cost_centers = db.query(CostCenter).all()
            cc_choices = {"-- عام --": None}
            for cc in cost_centers:
                cc_choices[f"{cc.code} - {cc.name_ar}"] = cc.id

            c1, c2 = st.columns(2)
            with c1:
                entry_date_val = st.date_input("تاريخ القيد:", value=date.today())
            with c2:
                ref_val = st.text_input("رقم المرجع (اختياري):")
            desc_val = st.text_input("شرح وبيان القيد العام:")

            if "journal_rows_count" not in st.session_state:
                st.session_state.journal_rows_count = 2

            jb1, jb2 = st.columns(2)
            with jb1:
                if st.button("➕ إضافة سطر للقيد المركب"):
                    st.session_state.journal_rows_count += 1
                    st.rerun()
            with jb2:
                if st.session_state.journal_rows_count > 2 and st.button("➖ حذف آخر سطر من القيد"):
                    st.session_state.journal_rows_count -= 1
                    st.rerun()

            lines_to_submit = []
            total_d = total_c = 0.0
            for i in range(st.session_state.journal_rows_count):
                r1, r2, r3, r4 = st.columns([2.2, 1, 1, 1.5])
                with r1:
                    selected_acc = st.selectbox(f"حساب السطر ({i+1}):", list(account_options.keys()), key=f"acc_{i}")
                with r2:
                    d_val = st.number_input("مدين:", min_value=0.0, step=100.0, key=f"deb_{i}")
                with r3:
                    c_val = st.number_input("دائن:", min_value=0.0, step=100.0, key=f"crd_{i}")
                with r4:
                    sel_cc_l = cc_choices[st.selectbox("مركز التكلفة:", list(cc_choices.keys()), key=f"jcc_{i}")]

                total_d += d_val
                total_c += c_val
                if d_val > 0 or c_val > 0:
                    lines_to_submit.append({
                        "account_code": account_options[selected_acc],
                        "debit": d_val, "credit": c_val,
                        "cost_center_id": sel_cc_l, "description": desc_val
                    })

            jm1, jm2, jm3 = st.columns(3)
            jm1.metric("إجمالي المدين", f"{total_d:,.2f} ريال")
            jm2.metric("إجمالي الدائن", f"{total_c:,.2f} ريال")
            diff_je = round(total_d - total_c, 2)
            jm3.metric("حالة الاتزان", "متزن ✅" if abs(diff_je) < 0.01 and total_d > 0 else f"فرق: {diff_je:,.2f} ريال")

            doc_type_choice = st.radio(
                "نوع القيد:",
                ["قيد يومية عادي / تسوية (JOURNAL_VOUCHER)", "قيد أرصدة افتتاحية أول المدة (OPENING_BALANCE)"],
                horizontal=True
            )
            chosen_doc_type = DocumentType.OPENING_BALANCE if "OPENING_BALANCE" in doc_type_choice else DocumentType.JOURNAL_VOUCHER

            post_col1, post_col2 = st.columns(2)
            with post_col1:
                if st.button("💾 ترحيل فوري لدفتر الأستاذ (Posted)", type="primary", use_container_width=True, disabled=not (has_perm("act_create_journal") and has_perm("act_approve_journal"))):
                    try:
                        entry = LedgerService.create_journal_entry(
                            db=db, description=desc_val or "قيد يومية", lines_data=lines_to_submit,
                            entry_date=entry_date_val, reference=ref_val, doc_type=chosen_doc_type,
                            auto_post=True, performed_by=get_active_user_label()
                        )
                        st.session_state["latest_jv_id"] = entry.id
                        st.success(f"🎉 تم اعتماد وترحيل القيد المحاسبي بنجاح برقم: {entry.entry_number}")
                    except Exception as e:
                        st.error(f"❌ {str(e)}")
            with post_col2:
                if st.button("⏳ حفظ كمسودة بانتظار اعتماد المدير (Draft - Maker/Checker)", use_container_width=True, disabled=not has_perm("act_create_journal")):
                    try:
                        entry = LedgerService.create_journal_entry(
                            db=db, description=desc_val or "مسودة قيد يومية", lines_data=lines_to_submit,
                            entry_date=entry_date_val, reference=ref_val, doc_type=chosen_doc_type,
                            auto_post=False, performed_by=get_active_user_label()
                        )
                        st.session_state["latest_jv_id"] = entry.id
                        st.info(f"⏳ تم حفظ القيد كمسودة برقم ({entry.entry_number}) بانتظار المراجعة والاعتماد.")
                    except Exception as e:
                        st.error(f"❌ {str(e)}")

        with t_log_je:
            entries = db.query(JournalEntry).order_by(JournalEntry.id.desc()).all()
            if entries:
                summary_list = [{
                    "رقم القيد": e.entry_number,
                    "التاريخ": e.entry_date.strftime("%Y-%m-%d"),
                    "نوع المستند": e.doc_type.value,
                    "المرجع": e.reference or "-",
                    "البيان العام": e.description,
                    "إجمالي المبلغ (ريال)": f"{e.total_debit:,.2f}",
                    "الحالة": "مرحل ✅" if e.status == EntryStatus.POSTED else ("مسودة ⏳" if e.status == EntryStatus.DRAFT else "معكوس 🔄")
                } for e in entries]
                st.dataframe(pd.DataFrame(summary_list), use_container_width=True, hide_index=True)

                st.divider()
                st.markdown("##### **🔍 استعراض تفاصيل أسطر القيد أو إجراء قيد عكسي (Reversal):**")
                je_map = {f"{e.entry_number} | {e.entry_date} | {e.description} ({e.total_debit:,.2f} ريال)": e for e in entries}
                sel_je_obj = je_map[st.selectbox("اختر القيد المحاسبي:", list(je_map.keys()))]
                je_lines_rows = [{
                    "رقم السطر": jl.line_number,
                    "كود الحساب": jl.account.code if jl.account else "",
                    "اسم الحساب": jl.account.name_ar if jl.account else "",
                    "مدين": f"{jl.debit:,.2f}",
                    "دائن": f"{jl.credit:,.2f}",
                    "البيان": jl.description or ""
                } for jl in sel_je_obj.lines]
                st.table(pd.DataFrame(je_lines_rows))

                if sel_je_obj.status == EntryStatus.DRAFT:
                    st.warning("⏳ هذا القيد محفوظ حالياً كمسودة (غير مرحل لدفتر الأستاذ) وبانتظار الاعتماد:")
                    ap_c1, ap_c2 = st.columns(2)
                    with ap_c1:
                        if st.button("✅ اعتماد وترحيل المسودة لدفتر الأستاذ الآن", type="primary", use_container_width=True, disabled=not has_perm("act_approve_journal")):
                            try:
                                LedgerService.post_draft_journal_entry(db, sel_je_obj.id, performed_by=get_active_user_label())
                                st.success(f"🎉 تم اعتماد وترحيل القيد ({sel_je_obj.entry_number}) بنجاح!")
                                st.rerun()
                            except Exception as e:
                                st.error(f"❌ {str(e)}")
                    with ap_c2:
                        if st.button("🗑️ رفض وحذف المسودة", use_container_width=True, disabled=not has_perm("act_approve_journal")):
                            try:
                                LedgerService.delete_draft_journal_entry(db, sel_je_obj.id, performed_by=get_active_user_label())
                                st.success("✅ تم حذف المسودة.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"❌ {str(e)}")

                rev_col1, rev_col2 = st.columns([2, 1])
                with rev_col1:
                    rev_reason = st.text_input("سبب عكس / إلغاء القيد المحاسبي:", value="قيد عكسي لتصحيح توجيه محاسبي")
                with rev_col2:
                    st.markdown("<br>", unsafe_allow_html=True)
                    can_rev = has_perm("act_reverse_journal") and sel_je_obj.status == EntryStatus.POSTED
                    if st.button("🔄 عكس القيد المحاسبي المحدد الآن", type="primary", use_container_width=True, disabled=not can_rev):
                        try:
                            rev_e = LedgerService.reverse_journal_entry(
                                db=db, entry_id=sel_je_obj.id, reason=rev_reason,
                                performed_by=get_active_user_label()
                            )
                            st.success(f"✅ تم توليد وترحيل القيد العكسي بنجاح برقم: {rev_e.entry_number}")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ {str(e)}")

                with st.expander("🖨️ **معاينة وطباعة سند القيد اليومي الرسمي (Journal Voucher):**", expanded=False):
                    settings_jv = LedgerService.get_company_settings(db)
                    jv_html = PrintTemplateService.generate_journal_voucher_html(sel_je_obj, settings_jv)
                    components.html(jv_html, height=580, scrolling=True)
    finally:
        db.close()


# =============================================================================
# 12. الشاشة 10: كشف حساب الأستاذ وميزان المراجعة اللحظي
# =============================================================================
elif menu_option == "📖 كشف الحساب وميزان المراجعة":
    st.markdown("### **كشف حساب الأستاذ العام وميزان المراجعة اللحظي**")
    t_stmt, t_tb = st.tabs(["📑 كشف حساب الأستاذ التفصيلي", "⚖️ ميزان المراجعة بالمجاميع والأرصدة"])

    db = get_db_session()
    try:
        settings_gl = LedgerService.get_company_settings(db)
        with t_stmt:
            leaf_accounts = db.query(Account).filter(Account.is_leaf == True).order_by(Account.code).all()
            account_map = {f"{acc.code} - {acc.name_ar}": acc.code for acc in leaf_accounts}
            gl_c1, gl_c2, gl_c3, gl_c4 = st.columns([2, 1, 1, 1])
            with gl_c1:
                selected_acc_label = st.selectbox("اختر الحساب:", list(account_map.keys()))
            with gl_c2:
                gl_use_dt = st.checkbox("تصفية بفترة زمنية", value=False, key="gl_flt")
            with gl_c3:
                gl_sdt = st.date_input("من تاريخ:", value=date(settings_gl.fiscal_year, 1, 1), disabled=not gl_use_dt, key="gl_sdt")
            with gl_c4:
                gl_edt = st.date_input("إلى تاريخ:", value=date.today(), disabled=not gl_use_dt, key="gl_edt")

            if selected_acc_label:
                stmt_data = LedgerService.get_account_statement(
                    db=db, account_code=account_map[selected_acc_label],
                    start_date=gl_sdt if gl_use_dt else None,
                    end_date=gl_edt if gl_use_dt else None
                )
                b1, b2 = st.columns(2)
                b1.metric("رصيد أول المدة:", f"{stmt_data['opening_balance']:,.2f} ريال")
                b2.metric("رصيد نهاية الفترة:", f"{stmt_data['closing_balance']:,.2f} ريال")
                if stmt_data["statement"]:
                    st.dataframe(pd.DataFrame(stmt_data["statement"]), use_container_width=True, hide_index=True)
                else:
                    st.info("لا توجد حركات مسجلة على هذا الحساب خلال الفترة المحددة.")

        with t_tb:
            tb_c1, tb_c2, tb_c3, tb_c4 = st.columns([1.2, 1, 1, 1])
            with tb_c1:
                inc_zero = st.checkbox("عرض الحسابات ذات الأرصدة الصفرية", value=False)
            with tb_c2:
                tb_use_dt = st.checkbox("تصفية بفترة زمنية", value=False, key="tb_flt")
            with tb_c3:
                tb_sdt = st.date_input("من تاريخ:", value=date(settings_gl.fiscal_year, 1, 1), disabled=not tb_use_dt, key="tb_sdt")
            with tb_c4:
                tb_edt = st.date_input("إلى تاريخ:", value=date.today(), disabled=not tb_use_dt, key="tb_edt")

            tb_df = LedgerService.get_live_trial_balance(
                db,
                start_date=tb_sdt if tb_use_dt else None,
                end_date=tb_edt if tb_use_dt else None,
                include_zero_balances=inc_zero
            )
            if not tb_df.empty:
                tm1, tm2, tm3 = st.columns(3)
                tot_cl_d = float(tb_df["Closing Debit"].sum())
                tot_cl_c = float(tb_df["Closing Credit"].sum())
                tm1.metric("إجمالي الأرصدة الختامية المدينة", f"{tot_cl_d:,.2f} ريال")
                tm2.metric("إجمالي الأرصدة الختامية الدائنة", f"{tot_cl_c:,.2f} ريال")
                tm3.metric("مطابقة اتزان الميزان", "متزن 100% ✅" if abs(tot_cl_d - tot_cl_c) < 0.01 else f"فرق: {(tot_cl_d - tot_cl_c):,.2f}")
                st.dataframe(tb_df, use_container_width=True, hide_index=True)
    finally:
        db.close()


# =============================================================================
# 13. الشاشة 11: القوائم المالية، التدفقات، الزكاة، وإقرار القيمة المضافة (VAT)
# =============================================================================
elif menu_option == "🏛️ القوائم المالية والزكاة والضريبة":
    st.markdown("### **القوائم المالية الختامية، التدفقات النقدية، الزكاة، وإقرار القيمة المضافة (VAT)**")
    db = get_db_session()
    try:
        settings = LedgerService.get_company_settings(db)
        fs_c1, fs_c2, fs_c3, fs_c4 = st.columns([1.2, 1, 1, 1.5])
        with fs_c1:
            fs_use_dt = st.checkbox("تحديد فترة مالية مخصصة للقوائم", value=True, key="fs_flt")
        with fs_c2:
            fs_sdt = st.date_input("من تاريخ:", value=date(settings.fiscal_year, 1, 1), disabled=not fs_use_dt, key="fs_sdt")
        with fs_c3:
            fs_edt = st.date_input("إلى تاريخ:", value=date(settings.fiscal_year, 12, 31), disabled=not fs_use_dt, key="fs_edt")

        eff_sdt = fs_sdt if fs_use_dt else date(settings.fiscal_year, 1, 1)
        eff_edt = fs_edt if fs_use_dt else date(settings.fiscal_year, 12, 31)

        tb_df = LedgerService.get_live_trial_balance(
            db,
            start_date=eff_sdt,
            end_date=eff_edt,
            include_zero_balances=True
        )
        engine = FinancialStatementsEngine(
            trial_balance_df=tb_df,
            fiscal_year=settings.fiscal_year,
            vat_rate=settings.default_vat_rate,
            start_date=eff_sdt,
            end_date=eff_edt
        )
        report = engine.generate_full_financial_report()
        subledger_rec = LedgerService.reconcile_subledgers_with_gl(db, end_date=eff_edt)

        pnl = report["income_statement"]
        bs = report["balance_sheet"]
        cf = report["cash_flow_statement"]
        vat = report["vat_return"]
        zakat = report["zakat_declaration"]
        ratios = report["financial_ratios"]
        pre_audit = report["pre_approval_audit"]

        all_reconciled_ready = bool(pre_audit["is_approved_ready"] and subledger_rec["all_reconciled"])
        official_signoff = st.checkbox(
            "✅ اعتماد المخرجات رسمياً بعد مراجعة مطابقات القوائم المالية وVAT والزكاة والأستاذ المساعد (Official Sign-off)",
            value=False,
            disabled=not (all_reconciled_ready and has_perm("act_approve_journal")),
            key="chk_official_report_approval"
        )
        approval_badge_text = (
            "معتمد رسمياً للإقرار (Officially Approved) ✅"
            if (official_signoff and all_reconciled_ready)
            else "مسودة قيد المراجعة — غير معتمدة للإقرار الرسمي قبل إتمام المراجعة ⚠️"
        )

        st.info(
            f"📅 **نطاق الفترة المالية للتقارير:** قائمة الدخل والتدفقات وإقرار الضريبة **{report['period_label_ar']}** | "
            f"قائمة المركز المالي **{report['as_of_label_ar']}**  \n"
            f"🛡️ **حالة الاعتماد الرسمي:** `{approval_badge_text}`"
        )

        with fs_c4:
            st.markdown("<br>", unsafe_allow_html=True)
            xl_bytes = ExportService.generate_excel_workbook(tb_df, report, company_name=settings.company_name_ar)
            st.download_button(
                "📊 تصدير القوائم المالية والزكاة والضريبة (Excel)",
                data=xl_bytes,
                file_name=f"MizanPro_Financial_Package_{eff_sdt}_{eff_edt}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True,
                type="primary",
                disabled=not has_perm("act_export_reports")
            )

        t1, t2, t3, t4, t5, t6, t7, t8 = st.tabs([
            "📈 قائمة الدخل", "🏛️ المركز المالي", "💵 التدفقات النقدية",
            "🧾 إقرار القيمة المضافة (VAT)", "🕌 إقرار الزكاة (ZATCA)",
            "📊 المؤشرات والنسب المالية", "🛡️ فحص المطابقة قبل الاعتماد",
            "📲 امتثال الفوترة الإلكترونية (ZATCA Phase 2)"
        ])
        with t1:
            st.caption(f"📌 **قائمة الدخل {pnl['period_label_ar']}** — تعتمد حصرياً على حركات الفترة الواقعة بين `{pnl['start_date']}` و `{pnl['end_date']}` | الحالة: **{approval_badge_text}**")
            st.table(pd.DataFrame([
                {"البند": "إجمالي إيرادات المبيعات والخدمات (حركة الفترة)", "المبلغ (ريال)": f"{pnl['gross_sales']:,.2f}"},
                {"البند": "يخصم: مردودات المبيعات والخصم المسموح به (حركة الفترة)", "المبلغ (ريال)": f"({(pnl['sales_returns'] + pnl['sales_discounts']):,.2f})"},
                {"البند": "صافي الإيرادات التشغيلية للفترة", "المبلغ (ريال)": f"{pnl['net_revenue']:,.2f}"},
                {"البند": "يخصم: صافي تكلفة البضاعة المباعة (COGS)", "المبلغ (ريال)": f"({pnl['cost_of_sales']:,.2f})"},
                {"البند": "مجمل الربح التشغيلي (Gross Profit)", "المبلغ (ريال)": f"{pnl['gross_profit']:,.2f} ({pnl['gross_margin_pct']:.1f}%)"},
                {"البند": "يخصم: إجمالي المصروفات التشغيلية والإدارية والعمومية للفترة", "المبلغ (ريال)": f"({pnl['operating_expenses']['total']:,.2f})"},
                {"البند": "صافي الربح التشغيلي (Operating Profit - EBIT)", "المبلغ (ريال)": f"{pnl['operating_profit']:,.2f}"},
                {"البند": "الإيرادات الأخرى - (المصروفات التمويلية والبنكية)", "المبلغ (ريال)": f"{(pnl['other_income'] - pnl['financial_charges']):,.2f}"},
                {"البند": "صافي الربح قبل الزكاة الشرعية", "المبلغ (ريال)": f"{pnl['profit_before_zakat']:,.2f}"},
                {"البند": "يخصم: مخصص الزكاة الشرعية التقديري", "المبلغ (ريال)": f"({pnl['zakat_expense']:,.2f})"},
                {"البند": "💰 صافي ربح / (خسارة) الفترة النهائي", "المبلغ (ريال)": f"{pnl['net_profit']:,.2f} ({pnl['net_margin_pct']:.1f}%)"},
            ]))
            if pnl["operating_expenses"]["breakdown"]:
                with st.expander("🔍 استعراض تفصيل بنود المصروفات التشغيلية والإدارية خلال الفترة"):
                    st.table(pd.DataFrame([
                        {"كود الحساب": x["code"], "اسم حساب المصروف": x["name"], "المبلغ (ريال)": f"{x['amount']:,.2f}"}
                        for x in pnl["operating_expenses"]["breakdown"]
                    ]))

        with t2:
            st.caption(f"📌 **قائمة المركز المالي {bs['as_of_label_ar']}** | الحالة: **{approval_badge_text}**")
            bs_m1, bs_m2, bs_m3 = st.columns(3)
            bs_m1.metric("إجمالي الأصول", f"{bs['total_assets']:,.2f} ريال")
            bs_m2.metric("إجمالي الالتزامات وحقوق الملكية", f"{bs['total_liabilities_and_equity']:,.2f} ريال")
            bs_m3.metric("حالة معادلة الميزانية", "متزنة 100% ✅" if bs["is_balanced"] else f"فرق: {bs['balance_difference']:,.2f}")

            bs_rows = [
                {"القسم": "الأصول المتداولة", "البند": "النقدية بالصندوق والحسابات البنكية", "المبلغ (ريال)": f"{bs['assets']['current_assets']['cash_and_banks']:,.2f}"},
                {"القسم": "الأصول المتداولة", "البند": "صافي الذمم المدينة التجارية (العملاء بعد المخصص)", "المبلغ (ريال)": f"{bs['assets']['current_assets']['net_receivables']:,.2f}"},
                {"القسم": "الأصول المتداولة", "البند": "المخزون السلعي (بتكلفة المتوسط المرجح WAC)", "المبلغ (ريال)": f"{bs['assets']['current_assets']['inventory']:,.2f}"},
                {"القسم": "الأصول المتداولة", "البند": "المصروفات المدفوعة مقدماً والأرصدة المدينة الأخرى", "المبلغ (ريال)": f"{bs['assets']['current_assets']['prepaid_and_other']:,.2f}"},
                {"القسم": "الأصول المتداولة", "البند": "🔹 إجمالي الأصول المتداولة", "المبلغ (ريال)": f"{bs['assets']['current_assets']['total']:,.2f}"},
                {"القسم": "الأصول غير المتداولة", "البند": "إجمالي التكلفة التاريخية للأصول الثابتة", "المبلغ (ريال)": f"{bs['assets']['non_current_assets']['gross_fixed_assets']:,.2f}"},
                {"القسم": "الأصول غير المتداولة", "البند": "يخصم: مجمع إهلاك الأصول الثابتة", "المبلغ (ريال)": f"({bs['assets']['non_current_assets']['accumulated_depreciation']:,.2f})"},
                {"القسم": "الأصول غير المتداولة", "البند": "الأصول غير الملموسة", "المبلغ (ريال)": f"{bs['assets']['non_current_assets']['intangible_assets']:,.2f}"},
                {"القسم": "الأصول غير المتداولة", "البند": "🔹 صافي الأصول غير المتداولة", "المبلغ (ريال)": f"{bs['assets']['non_current_assets']['total']:,.2f}"},
                {"القسم": "إجمالي الأصول", "البند": "🔵 إجمالي الأصول", "المبلغ (ريال)": f"{bs['total_assets']:,.2f}"},
                {"القسم": "الالتزامات المتداولة", "البند": "الموردون والذمم الدائنة التجارية", "المبلغ (ريال)": f"{bs['liabilities']['current_liabilities']['accounts_payable']:,.2f}"},
                {"القسم": "الالتزامات المتداولة", "البند": "المصروفات المستحقة والأرصدة الدائنة الأخرى", "المبلغ (ريال)": f"{bs['liabilities']['current_liabilities']['accrued_expenses']:,.2f}"},
                {"القسم": "الالتزامات المتداولة", "البند": "صافي ضريبة القيمة المضافة المستحقة للهيئة", "المبلغ (ريال)": f"{bs['liabilities']['current_liabilities']['net_vat_payable']:,.2f}"},
                {"القسم": "الالتزامات المتداولة", "البند": "مخصص الزكاة الشرعية المستحقة", "المبلغ (ريال)": f"{bs['liabilities']['current_liabilities']['zakat_provision']:,.2f}"},
                {"القسم": "الالتزامات المتداولة", "البند": "🔸 إجمالي الالتزامات المتداولة", "المبلغ (ريال)": f"{bs['liabilities']['current_liabilities']['total']:,.2f}"},
                {"القسم": "الالتزامات غير المتداولة", "البند": "القروض طويلة الأجل ومخصص مكافأة نهاية الخدمة", "المبلغ (ريال)": f"{bs['liabilities']['non_current_liabilities']['total']:,.2f}"},
                {"القسم": "حقوق الملكية", "البند": "رأس المال والاحتياطي النظامي وجاري الشركاء", "المبلغ (ريال)": f"{(bs['equity']['capital'] + bs['equity']['statutory_reserve'] + bs['equity']['partners_current_account']):,.2f}"},
                {"القسم": "حقوق الملكية", "البند": "الأرباح المبقاة وصافي ربح الفترة الحالية", "المبلغ (ريال)": f"{(bs['equity']['retained_earnings_prior'] + bs['equity']['current_year_net_profit']):,.2f}"},
                {"القسم": "حقوق الملكية", "البند": "🔸 صافي حقوق الملكية", "المبلغ (ريال)": f"{bs['equity']['total']:,.2f}"},
                {"القسم": "إجمالي الالتزامات وحقوق الملكية", "البند": "🟢 إجمالي الالتزامات وحقوق الملكية", "المبلغ (ريال)": f"{bs['total_liabilities_and_equity']:,.2f}"},
            ]
            st.table(pd.DataFrame(bs_rows))

        with t3:
            st.caption(f"📌 **قائمة التدفقات النقدية (IAS 7) {cf['period_label_ar']}** | الحالة: **{approval_badge_text}**")
            op_cf = cf["operating_activities"]
            wc_cf = op_cf["working_capital_changes"]
            inv_cf = cf["investing_activities"]
            fin_cf = cf["financing_activities"]
            cf_rows = [
                {"القسم": "الأنشطة التشغيلية", "البيان": "صافي الربح قبل الزكاة الشرعية", "المبلغ (ريال)": f"{op_cf['profit_before_zakat']:,.2f}"},
                {"القسم": "الأنشطة التشغيلية", "البيان": "يضاف: مصروف الإهلاك والبنود غير النقدية", "المبلغ (ريال)": f"{op_cf['depreciation_add_back']:,.2f}"},
                {"القسم": "الأنشطة التشغيلية", "البيان": "التغير في الذمم المدينة والأرصدة المدينة", "المبلغ (ريال)": f"{(wc_cf['receivables_change'] + wc_cf['prepaid_and_other_change']):,.2f}"},
                {"القسم": "الأنشطة التشغيلية", "البيان": "التغير في المخزون السلعي", "المبلغ (ريال)": f"{wc_cf['inventory_change']:,.2f}"},
                {"القسم": "الأنشطة التشغيلية", "البيان": "التغير في الموردين والمستحقات والضرائب", "المبلغ (ريال)": f"{(wc_cf['payables_change'] + wc_cf['accruals_and_vat_change']):,.2f}"},
                {"القسم": "الأنشطة التشغيلية", "البيان": "1️⃣ صافي النقد الناتج من الأنشطة التشغيلية", "المبلغ (ريال)": f"{op_cf['net_cash_from_operating']:,.2f}"},
                {"القسم": "الأنشطة الاستثمارية", "البيان": "حيازة وإضافات الأصول الثابتة وغير الملموسة", "المبلغ (ريال)": f"{inv_cf['net_cash_from_investing']:,.2f}"},
                {"القسم": "الأنشطة التمويلية", "البيان": "التغير في القروض وحقوق الملكية وجاري الشركاء", "المبلغ (ريال)": f"{fin_cf['net_cash_from_financing']:,.2f}"},
                {"القسم": "ملخص النقدية", "البيان": "صافي التغير في النقدية وما في حكمها خلال الفترة", "المبلغ (ريال)": f"{cf['net_change_in_cash']:,.2f}"},
                {"القسم": "ملخص النقدية", "البيان": "رصيد النقدية والبنوك في بداية الفترة", "المبلغ (ريال)": f"{cf['opening_cash_balance']:,.2f}"},
                {"القسم": "ملخص النقدية", "البيان": "💰 رصيد النقدية والبنوك في نهاية الفترة (مطابق للمركز المالي)", "المبلغ (ريال)": f"{cf['closing_cash_balance']:,.2f}"},
            ]
            st.table(pd.DataFrame(cf_rows))

        with t4:
            st.caption(f"📌 **إقرار ضريبة القيمة المضافة (ZATCA VAT Return) {vat['period_label_ar']}** — محسوب حصرياً من حركات الفترة (`{vat['start_date']}` إلى `{vat['end_date']}`) بتقريب `ROUND_HALF_UP` | الحالة: **{approval_badge_text}**")
            v1, v2, v3 = st.columns(3)
            v1.metric("إجمالي ضريبة المخرجات للفترة (المبيعات)", f"{vat['box_1_std_sales']['vat_amount']:,.2f} ريال")
            v2.metric("إجمالي ضريبة المدخلات القابلة للخصم للفترة", f"{vat['box_7_std_purchases']['recoverable_vat']:,.2f} ريال")
            v3.metric("صافي الضريبة المستحقة / (المستردة) للفترة", f"{vat['net_vat_due']:,.2f} ريال", delta=vat["settlement_status"])
            st.table(pd.DataFrame([
                {"رقم الحقل في نموذج ZATCA": "1", "البيان": vat["box_1_std_sales"]["label"], "المبلغ الخاضع للفترة (ريال)": f"{vat['box_1_std_sales']['taxable_amount']:,.2f}", "مبلغ الضريبة (15%)": f"{vat['box_1_std_sales']['vat_amount']:,.2f}"},
                {"رقم الحقل في نموذج ZATCA": "7", "البيان": vat["box_7_std_purchases"]["label"], "المبلغ الخاضع للفترة (ريال)": f"{vat['box_7_std_purchases']['taxable_amount']:,.2f}", "مبلغ الضريبة (15%)": f"({vat['box_7_std_purchases']['recoverable_vat']:,.2f})"},
                {"رقم الحقل في نموذج ZATCA": "14", "البيان": f"صافي ضريبة القيمة المضافة عن الفترة ({vat['settlement_status']})", "المبلغ الخاضع للفترة (ريال)": f"{vat['period_label_ar']}", "مبلغ الضريبة (15%)": f"{vat['net_vat_due']:,.2f}"},
            ]))

        with t5:
            st.caption(f"📌 **إقرار الزكاة الشرعية (ZATCA) {zakat['period_label_ar']}** | الحالة: **{approval_badge_text}**")
            z1, z2, z3 = st.columns(3)
            z1.metric("إجمالي الإضافات للوعاء الزكوي", f"{zakat['additions_to_zakat_base']['total_additions']:,.2f} ريال")
            z2.metric("إجمالي الحسميات من الوعاء", f"{zakat['deductions_from_zakat_base']['total_deductions']:,.2f} ريال")
            z3.metric("الزكاة الشرعية المستحقة (2.5%)", f"{zakat['zakat_due']:,.2f} ريال", delta=f"الوعاء: {zakat['zakat_base']:,.2f} ريال")
            ad = zakat["additions_to_zakat_base"]
            dd = zakat["deductions_from_zakat_base"]
            st.table(pd.DataFrame([
                {"القسم": "أولاً: عناصر الوعاء الموجبة", "البيان": "رأس المال المدفوع والاحتياطي النظامي والأرباح المبقاة", "المبلغ (ريال)": f"{(ad['capital'] + ad['statutory_reserve'] + ad['retained_earnings']):,.2f}"},
                {"القسم": "أولاً: عناصر الوعاء الموجبة", "البيان": "صافي الربح المعدل للعام قبل الزكاة", "المبلغ (ريال)": f"{ad['adjusted_net_profit']:,.2f}"},
                {"القسم": "أولاً: عناصر الوعاء الموجبة", "البيان": "القروض طويلة الأجل ومخصص نهاية الخدمة وجاري الشركاء الدائن", "المبلغ (ريال)": f"{(ad['long_term_loans'] + ad['eos_provision'] + ad['partners_credit_balance']):,.2f}"},
                {"القسم": "أولاً: عناصر الوعاء الموجبة", "البيان": "➕ إجمالي الإضافات للوعاء الزكوي", "المبلغ (ريال)": f"{ad['total_additions']:,.2f}"},
                {"القسم": "ثانياً: الحسميات من الوعاء", "البيان": "صافي القيمة الدفترية للأصول الثابتة والأصول غير الملموسة", "المبلغ (ريال)": f"({(dd['net_fixed_assets'] + dd['intangible_assets']):,.2f})"},
                {"القسم": "ثالثاً: الوعاء ومقدار الزكاة", "البيان": "⚖️ صافي الوعاء الزكوي الخاضع للزكاة", "المبلغ (ريال)": f"{zakat['zakat_base']:,.2f}"},
                {"القسم": "ثالثاً: الوعاء ومقدار الزكاة", "البيان": "🕌 مقدار الزكاة الشرعية المستحقة للهيئة (2.5%)", "المبلغ (ريال)": f"{zakat['zakat_due']:,.2f}"},
            ]))

        with t6:
            r_c1, r_c2, r_c3, r_c4 = st.columns(4)
            r_c1.metric("نسبة التداول (Current Ratio)", f"{ratios['current_ratio']:.2f} مرة")
            r_c2.metric("نسبة السيولة السريعة (Quick Ratio)", f"{ratios['quick_ratio']:.2f} مرة")
            r_c3.metric("العائد على الأصول (ROA)", f"{ratios['return_on_assets_pct']:.2f}%")
            r_c4.metric("العائد على حقوق الملكية (ROE)", f"{ratios['return_on_equity_pct']:.2f}%")
            st.table(pd.DataFrame([
                {"المجموعة": "مؤشرات السيولة", "المؤشر المالي": "صافي رأس المال العامل (Working Capital)", "القيمة": f"{bs['working_capital']:,.2f} ريال"},
                {"المجموعة": "مؤشرات السيولة", "المؤشر المالي": "نسبة التداول (الأصول المتداولة ÷ الالتزامات المتداولة)", "القيمة": f"{ratios['current_ratio']:.2f} مرة"},
                {"المجموعة": "مؤشرات السيولة", "المؤشر المالي": "نسبة السيولة السريعة ((الأصول المتداولة - المخزون) ÷ الالتزامات المتداولة)", "القيمة": f"{ratios['quick_ratio']:.2f} مرة"},
                {"المجموعة": "مؤشرات الربحية", "المؤشر المالي": "هامش مجمل الربح (Gross Margin %)", "القيمة": f"{ratios['gross_margin_pct']:.2f}%"},
                {"المجموعة": "مؤشرات الربحية", "المؤشر المالي": "هامش الربح التشغيلي (Operating Margin %)", "القيمة": f"{ratios['operating_margin_pct']:.2f}%"},
                {"المجموعة": "مؤشرات الربحية", "المؤشر المالي": "هامش صافي الربح النهائي (Net Profit Margin %)", "القيمة": f"{ratios['net_margin_pct']:.2f}%"},
                {"المجموعة": "مؤشرات الكفاءة والرفع المالي", "المؤشر المالي": "العائد على إجمالي الأصول (ROA %)", "القيمة": f"{ratios['return_on_assets_pct']:.2f}%"},
                {"المجموعة": "مؤشرات الكفاءة والرفع المالي", "المؤشر المالي": "العائد على حقوق الملكية (ROE %)", "القيمة": f"{ratios['return_on_equity_pct']:.2f}%"},
                {"المجموعة": "مؤشرات الكفاءة والرفع المالي", "المؤشر المالي": "نسبة المديونية إلى الأصول (Debt to Assets %)", "القيمة": f"{ratios['debt_to_assets_pct']:.2f}%"},
            ]))

        with t7:
            st.markdown("##### **🛡️ مصفوفة المراجعة والمطابقة المحاسبية والزكوية والضريبية قبل الاعتماد الرسمي:**")
            st.caption("تُعامل كافة المخرجات والتقارير كـ **(مسودة قيد المراجعة)** ولا تُعتمد رسمياً إلا بعد اجتياز كافة فحوصات المطابقة أدناه:")
            chk_rows = []
            for c_item in pre_audit["checks"]:
                chk_rows.append({
                    "بند الفحص والمطابقة": c_item["check_name"],
                    "القيمة المتوقعة / الدفترية": f"{c_item['expected']:,.2f}",
                    "القيمة الفعلية بالتقرير": f"{c_item['actual']:,.2f}",
                    "الفرق": f"{c_item['difference']:,.2f}",
                    "النتيجة": "مطابق ✅" if c_item["passed"] else "غير مطابق ❌"
                })
            for s_item in subledger_rec["checks"]:
                chk_rows.append({
                    "بند الفحص والمطابقة": s_item["check_name"],
                    "القيمة المتوقعة / الدفترية": f"{s_item['gl_balance']:,.2f}",
                    "القيمة الفعلية بالتقرير": f"{s_item['subledger_balance']:,.2f}",
                    "الفرق": f"{s_item['difference']:,.2f}",
                    "النتيجة": "مطابق ✅" if s_item["passed"] else "غير مطابق ❌"
                })
            st.table(pd.DataFrame(chk_rows))

        with t8:
            st.markdown("##### **📲 تقرير امتثال كافة المستندات المالية لمتطلبات المرحلة الثانية (ZATCA Phase 2 — Fatoora Integration):**")
            p2_audit = ZATCAPhase2Validator.audit_all_database_documents(db, auto_upgrade_phase2=True)
            za1, za2, za3, za4 = st.columns(4)
            za1.metric("إجمالي المستندات المالية", f"{p2_audit['total_documents']}")
            za2.metric("المستندات المتوافقة (Tags 1–9)", f"{p2_audit['compliant_documents']}")
            za3.metric("المستندات غير المتوافقة", f"{p2_audit['non_compliant_documents']}")
            za4.metric("نسبة الامتثال الكلية", f"{p2_audit['overall_compliance_pct']:.1f}%")

            if p2_audit["reports"]:
                summary_rows = []
                for r in p2_audit["reports"]:
                    summary_rows.append({
                        "نوع المستند": r["doc_title_ar"],
                        "رقم المستند": r["doc_number"],
                        "الطرف": r["counterparty_name"],
                        "الرقم الضريبي للمنشأة": r["seller_vat"] or "❌",
                        "الرقم الضريبي للطرف": r["counterparty_vat"] or "مبسطة/نقدي",
                        "عدد حقول QR TLV": len(r["decoded_qr"].get("tags", {})),
                        "UUID (KSA-1)": r["uuid"][:18] + "...",
                        "الإجمالي (ريال)": f"{r['grand_total']:,.2f}",
                        "حالة ZATCA Phase 2": "متوافق 100% ✅" if r["phase2_compliant"] else "يحتاج مراجعة ❌"
                    })
                st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True)
    finally:
        db.close()


# =============================================================================
# 13.ب الشاشة المستقلة: سجل التدقيق الرقابي للقراءة فقط (ZATCA Read-Only Audit Log)
# =============================================================================
elif menu_option == "🔍 سجل التدقيق الرقابي للقراءة فقط (ZATCA Audit Log)":
    db = get_db_session()
    try:
        render_readonly_zatca_audit_log_module(db, key_prefix="standalone_zatca_audit")
    finally:
        db.close()


# =============================================================================
# 14. الشاشة 12: شجرة الحسابات، إعدادات المنشأة، التخصيص الحر للصلاحيات، وسجل الرقابة
# =============================================================================
elif menu_option == "🌳 شجرة الحسابات، الإعدادات، وصلاحيات المستخدمين":
    st.markdown("### **دليل الحسابات الشجري، إعدادات المنشأة، التخصيص الحر لصلاحيات المستخدمين، وسجل التدقيق**")
    t_users, t_coa, t_cfg, t_audit = st.tabs([
        "👥 إدارة المستخدمين والتخصيص الحر للصلاحيات",
        "🌳 شجرة الحسابات (COA)",
        "⚙️ إعدادات المنشأة والضريبة",
        "🛡️ سجل الرقابة والتدقيق الإلزامي للقراءة فقط (ZATCA Read-Only Audit Log)"
    ])

    db = get_db_session()
    try:
        with t_users:
            st.markdown("##### **🔐 منظومة إدارة المستخدمين والتخصيص الحر للصلاحيات (Granular RBAC & Custom Permissions Matrix)**")
            st.caption("يمكنك تخصيص صلاحيات كل مستخدم بحرية كاملة على مستوى كل شاشة (12 شاشة) وكل عملية دقيقة (16 إجراءً رقابياً)، بالإضافة إلى تحديد سقف الخصم المسموح وحفظ قوالب أدوار مخصصة.")

            all_users = db.query(AppUser).order_by(AppUser.id).all()
            users_summary = []
            for u in all_users:
                u_perms = u.get_permissions()
                m_cnt = sum(1 for k in SYSTEM_MODULES if u_perms.get(k, False))
                a_cnt = sum(1 for k in SYSTEM_ACTIONS if u_perms.get(k, False))
                users_summary.append({
                    "المعرف": u.id,
                    "اسم الدخول": u.username,
                    "الاسم الكامل": u.full_name_ar,
                    "المسمى الوظيفي": u.job_title or "مسؤول مالي",
                    "الدور الأساسي": u.role.value,
                    "الشاشات المتاحة": f"{m_cnt} / {len(SYSTEM_MODULES)}",
                    "العمليات المسموحة": f"{a_cnt} / {len(SYSTEM_ACTIONS)}",
                    "سقف الخصم (%)": f"{float(u.max_discount_pct or 0.0):.0f}%",
                    "الحالة": "نشط ✅" if u.is_active else "موقوف ⛔"
                })
            if users_summary:
                st.dataframe(pd.DataFrame(users_summary), use_container_width=True, hide_index=True)

            st.divider()
            user_choices = {"➕ إنشاء مستخدم جديد بصلاحيات مخصصة": None}
            for u in all_users:
                user_choices[f"✏️ تعديل وتخصيص صلاحيات: {u.full_name_ar} ({u.username} - {u.role.value})"] = u

            sel_u_label = st.selectbox("اختر المستخدم للتعديل أو أنشئ مستخدماً جديداً:", list(user_choices.keys()))
            target_u = user_choices[sel_u_label]

            role_options_map = {
                "مدير النظام / المدير المالي (ADMIN - كامل الصلاحيات)": UserRole.ADMIN,
                "تخصيص حر للصلاحيات (CUSTOM - مصفوفة حرة مخصصة)": UserRole.CUSTOM,
                "محاسب عام (ACCOUNTANT)": UserRole.ACCOUNTANT,
                "مراجع قانوني (AUDITOR - CPA)": UserRole.AUDITOR,
                "مسؤول مبيعات ومخازن (SALES)": UserRole.SALES,
            }
            rev_role_map = {v: k for k, v in role_options_map.items()}

            u_col1, u_col2, u_col3 = st.columns(3)
            with u_col1:
                in_uname = st.text_input("اسم الدخول (Username):", value=target_u.username if target_u else "", placeholder="مثال: branch_acc")
                in_fname = st.text_input("الاسم الكامل (عربي):", value=target_u.full_name_ar if target_u else "", placeholder="مثال: خالد العتيبي")
            with u_col2:
                in_jtitle = st.text_input("المسمى الوظيفي:", value=(target_u.job_title or "مسؤول مالي") if target_u else "محاسب مخصص")
                default_r_idx = list(role_options_map.keys()).index(rev_role_map.get(target_u.role, "تخصيص حر للصلاحيات (CUSTOM - مصفوفة حرة مخصصة)")) if target_u else 1
                sel_r_label = st.selectbox("نوع الدور الأساسي:", list(role_options_map.keys()), index=default_r_idx)
                in_role = role_options_map[sel_r_label]
            with u_col3:
                in_pin = st.text_input("رمز الدخول السري الجديد (PIN - اتركه فارغاً لتوليد رمز عشوائي أو للإبقاء على الحالي):", value="", type="password")
                in_max_disc = st.number_input("سقف نسبة الخصم المسموح بها في المبيعات (%):", min_value=0.0, max_value=100.0, value=float(target_u.max_discount_pct if target_u and target_u.max_discount_pct is not None else 15.0), step=5.0)
                in_active = st.checkbox("الحساب نشط ومفعل للدخول", value=target_u.is_active if target_u else True)
                in_must_chg = st.checkbox("إلزام المستخدم بتغيير الرمز عند أول دخول", value=bool(target_u.must_change_pin) if target_u else True)

            state_key_prefix = f"perm_state_{target_u.id if target_u else 'new'}"
            if state_key_prefix not in st.session_state:
                st.session_state[state_key_prefix] = target_u.get_permissions() if target_u else get_default_permissions_for_role(in_role)

            active_perm_dict = st.session_state[state_key_prefix]

            # شريط التعبئة السريعة واستدعاء قوالب الصلاحيات المخصصة
            st.markdown("###### **⚡ أدوات التعبئة السريعة وقوالب الأدوار المخصصة (قبل التخصيص اليدوي الحر):**")
            qb1, qb2, qb3, qb4 = st.columns([1, 1, 1, 1.5])
            with qb1:
                if st.button("✅ تحديد الكل (كامل الصلاحيات)", use_container_width=True):
                    st.session_state[state_key_prefix] = {k: True for k in ALL_PERMISSION_KEYS}
                    st.rerun()
            with qb2:
                if st.button("🔄 افتراضي الدور المختار", use_container_width=True):
                    st.session_state[state_key_prefix] = get_default_permissions_for_role(in_role)
                    st.rerun()
            with qb3:
                if st.button("👁️ عرض وقراءة فقط (بدون تعديل)", use_container_width=True):
                    ro_perms = {k: False for k in ALL_PERMISSION_KEYS}
                    for mk in ["mod_dashboard", "mod_ledger", "mod_statements"]:
                        ro_perms[mk] = True
                    st.session_state[state_key_prefix] = ro_perms
                    st.rerun()
            with qb4:
                saved_templates = db.query(CustomRoleTemplate).order_by(CustomRoleTemplate.id).all()
                tpl_map = {t.template_name: t for t in saved_templates}
                if tpl_map:
                    sel_tpl_name = st.selectbox("استدعاء قالب دور وظيفي محفوظ:", list(tpl_map.keys()), label_visibility="collapsed")
                    if st.button("📂 تطبيق القالب المحفوظ على المصفوفة", use_container_width=True):
                        try:
                            loaded_p = json.loads(tpl_map[sel_tpl_name].permissions_json)
                            st.session_state[state_key_prefix] = {k: bool(loaded_p.get(k, False)) for k in ALL_PERMISSION_KEYS}
                            st.rerun()
                        except Exception:
                            pass

            st.markdown("###### **1️⃣ تخصيص صلاحيات ظهور ودخول الشاشات والوحدات الرئيسية (12 وحدة):**")
            mod_cols = st.columns(3)
            updated_perms: Dict[str, bool] = {}
            for idx_m, (m_key, m_label) in enumerate(SYSTEM_MODULES.items()):
                with mod_cols[idx_m % 3]:
                    updated_perms[m_key] = st.checkbox(
                        m_label,
                        value=bool(active_perm_dict.get(m_key, False)),
                        key=f"chk_{state_key_prefix}_{m_key}"
                    )

            st.markdown(f"###### **2️⃣ تخصيص صلاحيات العمليات والإجراءات الدقيقة داخل النظام ({len(SYSTEM_ACTIONS)} عملية رقابية):**")
            act_cols = st.columns(2)
            for idx_a, (a_key, a_label) in enumerate(SYSTEM_ACTIONS.items()):
                with act_cols[idx_a % 2]:
                    updated_perms[a_key] = st.checkbox(
                        f"🔹 {a_label}",
                        value=bool(active_perm_dict.get(a_key, False)),
                        key=f"chk_{state_key_prefix}_{a_key}"
                    )

            st.session_state[state_key_prefix] = updated_perms

            if st.button("💾 حفظ بيانات المستخدم واعتماد مصفوفة الصلاحيات الحرة", type="primary", use_container_width=True, disabled=not has_perm("act_manage_users")):
                try:
                    saved_u = LedgerService.create_or_update_user(
                        db=db,
                        username=in_uname,
                        full_name_ar=in_fname,
                        role=in_role,
                        pin_code=in_pin,
                        job_title=in_jtitle,
                        permissions_dict=updated_perms,
                        max_discount_pct=in_max_disc,
                        is_active=in_active,
                        must_change_pin=in_must_chg,
                        performed_by=get_active_user_label()
                    )
                    st.success(f"🎉 تم حفظ المستخدم ({saved_u.full_name_ar}) واعتماد صلاحياته المخصصة بنجاح!")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ {str(e)}")

            with st.expander("🗂️ **حفظ التخصيص الحالي كقالب دور وظيفي جديد (لإعادة استخدامه مع مستخدمين آخرين)**"):
                tc1, tc2, tc3 = st.columns([1.2, 1.8, 1])
                with tc1:
                    new_tpl_name = st.text_input("اسم القالب الوظيفي الجديد:", placeholder="مثال: محاسب مبيعات وصندوق فرعي")
                with tc2:
                    new_tpl_desc = st.text_input("وصف مختصر للقالب:", placeholder="مثال: يسمح بإصدار الفواتير وسندات القبض فقط")
                with tc3:
                    st.markdown("<br>", unsafe_allow_html=True)
                    if st.button("💾 حفظ كقالب صلاحيات دائم", use_container_width=True, disabled=not has_perm("act_manage_users")):
                        try:
                            LedgerService.save_custom_role_template(
                                db=db, template_name=new_tpl_name, description=new_tpl_desc,
                                permissions_dict=updated_perms, performed_by=get_active_user_label()
                            )
                            st.success(f"✅ تم حفظ القالب ({new_tpl_name}) بنجاح!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ {str(e)}")

        with t_coa:
            accounts = db.query(Account).order_by(Account.code).all()
            coa_data = [{
                "كود الحساب": acc.code,
                "اسم الحساب (عربي)": acc.name_ar,
                "النوع الرئيسي": acc.type.value,
                "التبويب الفرعي": acc.sub_type.value,
                "طبيعة الحساب": acc.natural_balance.value,
                "يقبل الحركة (فرعي)": "نعم ✅" if acc.is_leaf else "رئيسي 📁"
            } for acc in accounts]
            st.dataframe(pd.DataFrame(coa_data), use_container_width=True, hide_index=True)

            st.divider()
            st.markdown("##### **➕ إضافة حساب فرعي جديد في شجرة الحسابات:**")
            parent_opts = {f"{a.code} - {a.name_ar} ({'رئيسي 📁' if not a.is_leaf else 'فرعي قابل للتفرع'})": a.code for a in accounts}
            ca1, ca2, ca3, ca4 = st.columns(4)
            with ca1:
                sel_parent_code = parent_opts[st.selectbox("الحساب الأب:", list(parent_opts.keys()))]
            with ca2:
                new_acc_code = st.text_input("كود الحساب الجديد:", placeholder=f"مثال: {sel_parent_code}01")
            with ca3:
                new_acc_name_ar = st.text_input("اسم الحساب الجديد (عربي):", placeholder="مثال: بنك الراجحي - حساب جاري")
            with ca4:
                new_acc_name_en = st.text_input("الاسم بالإنجليزي (اختياري):")

            if st.button("💾 إضافة الحساب في الشجرة", type="primary", disabled=not has_perm("act_manage_coa")):
                try:
                    created_acc = LedgerService.create_sub_account(
                        db=db, parent_code=sel_parent_code, new_code=new_acc_code,
                        name_ar=new_acc_name_ar, name_en=new_acc_name_en
                    )
                    st.success(f"✅ تم إنشاء الحساب [{created_acc.code} - {created_acc.name_ar}] بنجاح!")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ {str(e)}")

        with t_cfg:
            settings = LedgerService.get_company_settings(db)
            s1, s2, s3 = st.columns(3)
            with s1:
                c_ar = st.text_input("اسم المنشأة (عربي):", value=settings.company_name_ar)
                c_vat = st.text_input("الرقم الضريبي (15 رقماً):", value=settings.vat_number)
                c_cr = st.text_input("رقم السجل التجاري:", value=settings.cr_number or "")
            with s2:
                c_en = st.text_input("اسم المنشأة (إنجليزي):", value=settings.company_name_en or "")
                c_addr = st.text_input("العنوان الوطني:", value=settings.address_ar or "")
                c_phone = st.text_input("رقم الهاتف:", value=settings.phone or "")
            with s3:
                c_vat_pct = st.number_input("نسبة ضريبة القيمة المضافة الافتراضية (%):", min_value=0.0, max_value=100.0, value=round(float(settings.default_vat_rate) * 100.0, 2), step=1.0)
                c_fyear = st.number_input("السنة المالية النشطة:", min_value=2000, max_value=2100, value=int(settings.fiscal_year), step=1)
                c_curr = st.text_input("العملة الوظيفية:", value=settings.currency or "ريال")

            if st.button("💾 حفظ وتحديث إعدادات المنشأة", type="primary", disabled=not has_perm("act_manage_settings")):
                try:
                    LedgerService.update_company_settings(
                        db=db, performed_by=get_active_user_label(),
                        company_name_ar=c_ar, company_name_en=c_en,
                        vat_number=c_vat, cr_number=c_cr, address_ar=c_addr, phone=c_phone,
                        default_vat_rate=round(c_vat_pct / 100.0, 4),
                        fiscal_year=int(c_fyear), currency=c_curr.strip() or "ريال"
                    )
                    st.success("✅ تم تحديث إعدادات المنشأة والضريبة والسنة المالية بنجاح!")
                    st.rerun()
                except Exception as ex_cfg:
                    st.error(f"❌ {ex_cfg}")

        with t_audit:
            render_readonly_zatca_audit_log_module(db, key_prefix="settings_tab_audit")
    finally:
        db.close()