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


def _ensure_dependencies_installed() -> None:
    """Ensure required packages from requirements.txt are installed even after a fresh container cold start."""
    if importlib.util.find_spec("streamlit") is not None and importlib.util.find_spec("openpyxl") is not None:
        return
    if importlib.util.find_spec("pip") is None:
        get_pip_path = "/tmp/get-pip.py"
        urllib.request.urlretrieve("https://bootstrap.pypa.io/get-pip.py", get_pip_path)
        subprocess.run([sys.executable, get_pip_path], check=False)
    req_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    if os.path.exists(req_file):
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-r", req_file], check=False)


def _run_streamlit_server_with_proxy() -> None:
    """Bind port 3000 immediately and proxy HTTP/WebSocket traffic to the local Streamlit worker."""
    port = int(os.environ.get("PORT", "3000"))
    internal_port = int(os.environ.get("STREAMLIT_INTERNAL_PORT", "8501"))

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", port))
    server_sock.listen(128)

    _ensure_dependencies_installed()

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
from datetime import date
import plotly.express as px
import plotly.graph_objects as go

from database import SessionLocal, BASE_DIR
from models import (
    Account, JournalEntry, EntryStatus, DocumentType,
    Customer, Supplier, Product, InventoryTransaction,
    SalesInvoice, PurchaseInvoice, CreditDebitNote,
    CashVoucher, PaymentMethod, InvoiceType, NoteType,
    VoucherType, VoucherPartyType, CostCenter, FixedAsset,
    Employee, PayrollRun, AppUser, UserRole, TBMappingProfile, AuditLog,
    CustomRoleTemplate, Warehouse, WarehouseStock, SYSTEM_MODULES, MODULE_LABEL_TO_KEY, SYSTEM_ACTIONS,
    ALL_PERMISSION_KEYS, get_default_permissions_for_role, verify_pin_code
)
import sqlite3
import shutil
import tempfile
import json
from seed_coa import init_database_and_seed
from ledger_service import LedgerService, LedgerValidationError
from financial_engine import FinancialStatementsEngine
from export_service import ExcelExportService, PrintTemplateService
from tb_analyzer_service import ExternalTBAnalyzerService, CPA_CATEGORIES, AUDIT_OPINION_TYPES


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

    [data-testid="stIconMaterial"], [class*="material-symbols"], [class*="material-icons"], .stExpander svg {
        font-family: inherit !important;
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
    """الحصول على جلسة قاعدة بيانات آمنة"""
    return SessionLocal()


# =============================================================================
# 2. القائمة الجانبية والتنقل وإدارة المستخدمين (Sidebar Navigation)
# =============================================================================
db_side = get_db_session()
try:
    company_cfg = LedgerService.get_company_settings(db_side)
    comp_name_display = company_cfg.company_name_ar
    comp_vat_display = company_cfg.vat_number
    comp_year_display = company_cfg.fiscal_year
    users_list = db_side.query(AppUser).filter(AppUser.is_active == True).order_by(AppUser.id).all()
    user_map = {}
    for u in users_list:
        label = f"👤 {u.full_name_ar} ({u.role.value})"
        user_map[label] = {
            "id": u.id,
            "username": u.username,
            "full_name_ar": u.full_name_ar,
            "job_title": u.job_title or "مسؤول مالي",
            "role": u.role.value,
            "pin_code": u.pin_code,
            "max_discount_pct": float(u.max_discount_pct if u.max_discount_pct is not None else 100.0),
            "permissions": u.get_permissions(),
            "allowed_menus": u.get_allowed_menu_options()
        }
    if not user_map:
        default_admin_perms = get_default_permissions_for_role(UserRole.ADMIN)
        user_map["👤 المدير المالي (ADMIN)"] = {
            "id": 1,
            "username": "admin",
            "full_name_ar": "المدير المالي",
            "job_title": "المدير المالي التنفيذي",
            "role": "ADMIN",
            "pin_code": "1234",
            "max_discount_pct": 100.0,
            "permissions": default_admin_perms,
            "allowed_menus": list(SYSTEM_MODULES.values())
        }
finally:
    db_side.close()

with st.sidebar:
    st.markdown("### ⚖️ **MizanPro ERP & CPA**")
    st.caption(f"**{comp_name_display}**")
    st.caption(f"الرقم الضريبي: `{comp_vat_display}`")

    selected_user_label = st.selectbox("المستخدم النشط:", list(user_map.keys()))
    active_user_info = user_map[selected_user_label]

    enforce_pin = st.checkbox("🔐 طلب رمز الدخول السري (PIN) للمستخدم", value=True)
    pin_verified = True
    if enforce_pin:
        entered_pin = st.text_input("أدخل رمز الدخول السري (PIN):", type="password", key=f"pin_in_{active_user_info['username']}")
        if not verify_pin_code(entered_pin, active_user_info["pin_code"]):
            pin_verified = False
            st.warning("🔒 يرجى إدخال رمز الـ PIN الصحيح لتفعيل صلاحيات هذا الحساب.")

    if pin_verified:
        st.session_state["active_user"] = active_user_info["full_name_ar"]
        st.session_state["active_user_info"] = active_user_info
    else:
        guest_perms = {k: False for k in ALL_PERMISSION_KEYS}
        guest_perms["mod_dashboard"] = True
        st.session_state["active_user"] = f"{active_user_info['full_name_ar']} (مقفل 🔒)"
        st.session_state["active_user_info"] = {
            **active_user_info,
            "permissions": guest_perms,
            "allowed_menus": [SYSTEM_MODULES["mod_dashboard"]],
            "max_discount_pct": 0.0
        }

    curr_u = st.session_state["active_user_info"]
    enabled_mods_cnt = sum(1 for k in SYSTEM_MODULES if curr_u["permissions"].get(k, False))
    enabled_acts_cnt = sum(1 for k in SYSTEM_ACTIONS if curr_u["permissions"].get(k, False))
    st.caption(
        f"💼 **{curr_u['job_title']}** | الصلاحيات: `{enabled_mods_cnt}/{len(SYSTEM_MODULES)}` شاشة و `{enabled_acts_cnt}/{len(SYSTEM_ACTIONS)}` عملية | سقف الخصم: `{curr_u['max_discount_pct']:.0f}%`"
    )

    st.divider()

    allowed_menu_list = curr_u["allowed_menus"]
    menu_option = st.radio(
        "الوحدات والقوائم المتاحة حسب صلاحياتك:",
        allowed_menu_list,
        index=0
    )

    st.divider()
    if curr_u["permissions"].get("act_export_reports", False):
        db_file_path = os.path.join(BASE_DIR, "mizanpro_ledger.db")
        if os.path.exists(db_file_path):
            with open(db_file_path, "rb") as f_db:
                st.download_button(
                    label="💾 نسخ احتياطي فوري لقاعدة البيانات (.db)",
                    data=f_db.read(),
                    file_name=f"mizanpro_backup_{date.today()}.db",
                    mime="application/octet-stream",
                    use_container_width=True
                )
    else:
        st.caption("🔒 النسخ الاحتياطي وتصدير الحزم مقيد حسب صلاحياتك.")
    st.caption(f"السنة المالية: `{comp_year_display}` | IFRS / SOCPA / ZATCA")


def has_perm(perm_key: str) -> bool:
    """التحقق السريع من صلاحية المستخدم النشط لأي عملية أو إجراء"""
    u_info = st.session_state.get("active_user_info", {})
    return bool(u_info.get("permissions", {}).get(perm_key, False))


def get_active_user_label() -> str:
    return st.session_state.get("active_user", "مدير النظام (Admin)")


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

        up_col1, up_col2, up_col3 = st.columns([2, 1.2, 1.2])
        with up_col1:
            uploaded_tb_file = st.file_uploader(
                "📂 ارفع ملف ميزان المراجعة هنا (Excel `.xlsx` أو `.csv` بأي تخطيط أعمدة):",
                type=["xlsx", "xls", "csv"]
            )
        with up_col2:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("🧪 تحميل بيانات ميزان (مؤسسة تساهيل طيبة) للتجربة", use_container_width=True, type="primary"):
                sample_raw = ExternalTBAnalyzerService.get_sample_tasaheel_tb_dataframe()
                st.session_state["ext_tb_classified_df"] = ExternalTBAnalyzerService.normalize_and_classify_tb(sample_raw)
                st.success("✅ تم تحميل وتبويب ميزان مراجعة (مؤسسة تساهيل طيبة التجارية) بنجاح!")
        with up_col3:
            st.markdown("<br>", unsafe_allow_html=True)
            sample_df_dl = ExternalTBAnalyzerService.get_sample_tasaheel_tb_dataframe()
            sample_buf = io.BytesIO()
            sample_df_dl.to_excel(sample_buf, index=False)
            sample_buf.seek(0)
            st.download_button(
                "📥 تنزيل قالب ميزان مراجعة Excel جاهز",
                data=sample_buf,
                file_name="Template_Trial_Balance_MizanPro.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True
            )

        if uploaded_tb_file is not None:
            try:
                st.session_state["ext_tb_classified_df"] = ExternalTBAnalyzerService.parse_uploaded_trial_balance(uploaded_tb_file)
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
                num_rows="dynamic"
            )
            active_tb_df = edited_df

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
            cf_table = [
                {"البيان": "صافي أرباح / (خسائر) الفترة قبل خصم الزكاة الشرعية", "ريال سعودي": f"{cpa_cf['profit_before_zakat']:,.0f}"},
                {"البيان": "استهلاك العقارات وآلات ومعدات", "ريال سعودي": f"{cpa_cf['depreciation']:,.0f}"},
                {"البيان": "صافي قبل التغيرات في رأس المال العامل", "ريال سعودي": f"{cpa_cf['profit_before_wc']:,.0f}"},
                {"البيان": "1️⃣ صافي التدفق النقدي من الأنشطة التشغيلية", "ريال سعودي": f"{cpa_cf['net_operating_cf']:,.0f}"},
                {"البيان": "2️⃣ صافي التدفق النقدي من الأنشطة الاستثمارية", "ريال سعودي": f"{cpa_cf['net_investing_cf']:,.0f}"},
                {"البيان": "3️⃣ صافي التدفق النقدي من الأنشطة التمويلية", "ريال سعودي": f"{cpa_cf['net_financing_cf']:,.0f}"},
                {"البيان": "💰 رصيد النقد في آخر العام", "ريال سعودي": f"{cpa_cf['closing_cash']:,.0f}"},
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
            col_dep1, col_dep2 = st.columns([1.2, 1])
            with col_dep1:
                st.markdown("##### **➕ تسجيل أصل ثابت جديد في السجل:**")
                fa_name = st.text_input("اسم ووصف الأصل الثابت:", placeholder="مثال: رافعة شوكية كهربائية للمستودع")
                fa_cat = st.selectbox("فئة الأصل:", ["السيارات ووسائل النقل", "الآلات والمعدات والأجهزة", "المباني والإنشاءات", "الأثاث والتركيبات والتجهيزات"])
                fa_c1, fa_c2, fa_c3 = st.columns(3)
                with fa_c1:
                    fa_cost = st.number_input("تكلفة الشراء (ريال):", min_value=0.0, step=1000.0)
                with fa_c2:
                    fa_rate = st.number_input("نسبة الإهلاك السنوي (%):", min_value=1.0, max_value=100.0, value=20.0, step=5.0)
                with fa_c3:
                    fa_dt = st.date_input("تاريخ الشراء:", value=date.today())
                fa_post_je = st.checkbox("توليد قيد شراء الأصل الثابت آلياً في دفتر اليومية (خصماً من البنك)", value=True)
                if st.button("💾 حفظ الأصل في السجل", type="primary", disabled=not has_perm("act_manage_assets")):
                    try:
                        LedgerService.create_or_update_fixed_asset(
                            db=db, name_ar=fa_name, category=fa_cat, purchase_date=fa_dt,
                            purchase_cost=fa_cost, depreciation_rate=fa_rate / 100.0,
                            post_purchase_entry=fa_post_je
                        )
                        st.success("✅ تم تسجيل الأصل الثابت بنجاح!")
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
                        je_dep = LedgerService.run_period_depreciation(db=db, dep_date=dep_run_date, months=dep_months)
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
            col_e1, col_e2 = st.columns([1.2, 1])
            with col_e1:
                st.markdown("##### **➕ إضافة موظف جديد في سجل الرواتب:**")
                e_name = st.text_input("اسم الموظف الكامل:")
                e_job = st.text_input("المسمى الوظيفي:", value="محاسب")
                ec1, ec2, ec3 = st.columns(3)
                with ec1:
                    e_nat = st.text_input("الجنسية:", value="سعودي")
                with ec2:
                    e_saudi = st.checkbox("خاضع لتأمينات السعوديين (GOSI)", value=True)
                with ec3:
                    e_join = st.date_input("تاريخ المباشرة:", value=date(2024, 1, 1))
                es1, es2, es3 = st.columns(3)
                with es1:
                    e_basic = st.number_input("الراتب الأساسي:", min_value=0.0, value=6000.0, step=500.0)
                with es2:
                    e_hous = st.number_input("بدل السكن:", min_value=0.0, value=1500.0, step=250.0)
                with es3:
                    e_trans = st.number_input("بدل النقل:", min_value=0.0, value=500.0, step=100.0)
                if st.button("💾 حفظ بيانات الموظف", disabled=not has_perm("act_manage_payroll")):
                    try:
                        LedgerService.create_or_update_employee(
                            db=db, name_ar=e_name, job_title=e_job, nationality=e_nat,
                            is_saudi=e_saudi, join_date=e_join, basic_salary=e_basic,
                            housing_allowance=e_hous, transport_allowance=e_trans
                        )
                        st.success("✅ تم حفظ بيانات الموظف!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ {str(e)}")

            with col_e2:
                st.markdown("##### **💸 إصدار وترحيل مسير الرواتب الشهري الجماعي:**")
                pr_month = st.text_input("شهر المسير:", value=date.today().strftime("%Y-%m"))
                pr_date = st.date_input("تاريخ صرف الرواتب:", value=date.today(), key="pr_dt")
                pr_inc_eos = st.checkbox("إثبات قسط مخصص مكافأة نهاية الخدمة الشهري آلياً في القيد", value=True)
                if st.button("🚀 اعتماد وصرف مسير الرواتب وترحيل القيد المحاسبي", type="primary", use_container_width=True, disabled=not has_perm("act_manage_payroll")):
                    try:
                        pr_obj = LedgerService.process_monthly_payroll(
                            db=db, period_month=pr_month, payment_date=pr_date, include_eos_accrual=pr_inc_eos
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
            cc_df = LedgerService.get_cost_centers_pnl(db)
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
    st.markdown("### **منظومة الرقابة المالية: أعمار الديون، مذكرة التسوية البنكية، وإقفال السنة المالية**")
    t_aging, t_bank, t_close = st.tabs([
        "📊 أعمار ديون العملاء والموردين (Aging & ECL)",
        "🏦 مذكرة التسوية البنكية الآلية",
        "🔒 إقفال السنة المالية وإدارة قاعدة البيانات"
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
            up_bank = st.file_uploader("ارفع كشف حساب البنك (Excel/CSV) أو اتركه فارغاً لتشغيل المطابقة على الكشف النموذجي:", type=["xlsx", "csv"], key="bnk_up")
            uploaded_bank_df = None
            if up_bank is not None:
                uploaded_bank_df = pd.read_csv(up_bank) if up_bank.name.endswith(".csv") else pd.read_excel(up_bank)

            rec_res = LedgerService.reconcile_bank_statement(db, bank_account_code="110201", bank_df=uploaded_bank_df)
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
                                {"account_code": "110201", "debit": 0.0, "credit": amt_abs, "description": "خصم من الحساب البنكي الجاري"}
                            ]
                            adj_desc = "إثبات رسوم وعمولات خدمات مصرفية من مذكرة التسوية البنكية"
                        else:
                            adj_lines = [
                                {"account_code": "110201", "debit": amt_abs, "credit": 0.0, "description": "إيداع بنكي من مذكرة التسوية"},
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
                        close_je = LedgerService.close_fiscal_year(db=db, fiscal_year=int(cl_year), lock_period=cl_lock)
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
                    if st.button("🔄 استبدال واستعادة النسخة الاحتياطية الآن", type="primary", disabled=not has_perm("act_reset_db")):
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
                                st.success("✅ تم التحقق من سلامة النسخة الاحتياطية واستعادتها بأمان!")
                                st.rerun()
                            except Exception as ex_db:
                                if os.path.exists(tmp_path):
                                    os.remove(tmp_path)
                                st.error(f"❌ تعذر استعادة النسخة الاحتياطية: {ex_db}")
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
            st.markdown("##### **➕ إضافة أو تحديث بطاقة صنف / خدمة:**")
            p1, p2, p3, p4 = st.columns(4)
            with p1:
                p_code = st.text_input("كود الصنف (اتركه فارغاً للتوليد الآلي):", placeholder="مثال: PRD-005")
            with p2:
                p_name = st.text_input("اسم الصنف / الخدمة (عربي):")
            with p3:
                p_cat = st.text_input("التصنيف:", value="قطع غيار")
            with p4:
                p_unit = st.selectbox("الوحدة:", ["حبة", "طقم", "كرتون", "لتر", "خدمة"])

            p5, p6, p7, p8 = st.columns(4)
            with p5:
                p_cost = st.number_input("التكلفة الافتراضية / المرجحة:", min_value=0.0, step=10.0)
            with p6:
                p_sale = st.number_input("سعر البيع الافتراضي (بدون ضريبة):", min_value=0.0, step=10.0)
            with p7:
                p_stock = st.number_input("رصيد أول المدة بالمخزن:", min_value=0.0, step=1.0)
            with p8:
                p_is_srv = st.checkbox("صنف خدمي (غير مخزني)", value=False)

            if st.button("💾 حفظ بطاقة الصنف", type="primary", disabled=not has_perm("act_manage_inventory")):
                try:
                    prod = LedgerService.create_or_update_product(
                        db=db, name_ar=p_name, code=p_code.strip() or None,
                        category=p_cat, unit=p_unit, cost_price=p_cost,
                        sale_price=p_sale, stock_quantity=p_stock, is_service=p_is_srv
                    )
                    st.success(f"✅ تم حفظ الصنف بنجاح برقم كود: {prod.code}")
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
                                new_actual_quantity=actual_qty, adjustment_date=adj_date, reason=adj_reason
                            )
                            st.success("✅ تمت التسوية الجردية وترحيل القيد المحاسبي بنجاح!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ خطأ: {str(e)}")

        with t_cust:
            col_c1, col_c2 = st.columns([1, 1])
            with col_c1:
                st.markdown("##### **➕ إضافة عميل جديد:**")
                c_name = st.text_input("اسم العميل / الشركة:")
                c_vat = st.text_input("الرقم الضريبي للعميل (15 رقماً للشركات):")
                c_phone = st.text_input("رقم الجوال / الهاتف:")
                c_addr = st.text_input("العنوان:")
                c_lim = st.number_input("الحد الائتماني المسموح (ريال):", min_value=0.0, step=5000.0)
                if st.button("💾 حفظ بيانات العميل", disabled=not has_perm("act_manage_inventory")):
                    try:
                        c_obj = LedgerService.create_or_update_customer(
                            db=db, name_ar=c_name, vat_number=c_vat, phone=c_phone, address=c_addr, credit_limit=c_lim
                        )
                        st.success(f"✅ تم حفظ العميل برقم: {c_obj.code}")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ {str(e)}")

            with col_c2:
                st.markdown("##### **📑 كشف حساب عميل تفصيلي:**")
                customers = db.query(Customer).order_by(Customer.id).all()
                if customers:
                    c_map = {f"{c.code} - {c.name_ar}": c.id for c in customers}
                    sel_c = st.selectbox("اختر العميل:", list(c_map.keys()))
                    c_stmt = LedgerService.get_party_statement(db, "CUSTOMER", c_map[sel_c])
                    st.metric("الرصيد المستحق على العميل", f"{c_stmt['net_balance']:,.2f} ريال")
                    if c_stmt["statement"]:
                        st.dataframe(pd.DataFrame(c_stmt["statement"]), use_container_width=True, hide_index=True)

        with t_supp:
            col_s1, col_s2 = st.columns([1, 1])
            with col_s1:
                st.markdown("##### **➕ إضافة مورد جديد:**")
                s_name = st.text_input("اسم المورد / الشركة الموردة:")
                s_vat = st.text_input("الرقم الضريبي للمورد:")
                s_phone = st.text_input("هاتف المورد:")
                s_addr = st.text_input("عنوان المورد:")
                if st.button("💾 حفظ بيانات المورد", disabled=not has_perm("act_manage_inventory")):
                    try:
                        s_obj = LedgerService.create_or_update_supplier(
                            db=db, name_ar=s_name, vat_number=s_vat, phone=s_phone, address=s_addr
                        )
                        st.success(f"✅ تم حفظ المورد برقم: {s_obj.code}")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ {str(e)}")

            with col_s2:
                st.markdown("##### **📑 كشف حساب مورد تفصيلي:**")
                suppliers = db.query(Supplier).order_by(Supplier.id).all()
                if suppliers:
                    s_map = {f"{s.code} - {s.name_ar}": s.id for s in suppliers}
                    sel_s = st.selectbox("اختر المورد:", list(s_map.keys()))
                    s_stmt = LedgerService.get_party_statement(db, "SUPPLIER", s_map[sel_s])
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
    tab_create, tab_return, tab_history = st.tabs([
        "📝 إصدار فاتورة مبيعات ضريبية",
        "↩️ إصدار إشعار دائن (مرتجع مبيعات)",
        "📂 أرشيف الفواتير والإشعارات والطباعة"
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

        pay_method_map = {
            "نقداً (الصندوق الرئيسي)": PaymentMethod.CASH,
            "تحويل بنكي / شبكة (POS)": PaymentMethod.BANK,
            "بالأجل (على حساب العميل)": PaymentMethod.CREDIT
        }
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
                selected_pay_label = st.selectbox("طريقة السداد:", list(pay_method_map.keys()))
                pay_method = pay_method_map[selected_pay_label]
            with f5:
                selected_inv_label = st.selectbox("نوع الفاتورة الضريبية:", list(inv_type_map.keys()))
                inv_type = inv_type_map[selected_inv_label]
            with f6:
                sel_cc_s = cc_choices[st.selectbox("مركز التكلفة / المشروع:", list(cc_choices.keys()), key="s_cc")]

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
                        allow_negative_stock=allow_neg_sale, performed_by=get_active_user_label()
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

            cn4, cn5, cn6, cn7 = st.columns(4)
            with cn4:
                cn_prod = prod_choices[st.selectbox("الصنف المرتجع:", list(prod_choices.keys()), key="cn_pk")]
            with cn5:
                cn_item_name = st.text_input("وصف البند المرتجع:", value=cn_prod.name_ar if cn_prod else "بند مرتجع مبيعات")
            with cn6:
                cn_qty = st.number_input("الكمية المرتجعة:", min_value=1.0, value=1.0, step=1.0)
            with cn7:
                cn_price = st.number_input("سعر الوحدة المرتجعة:", min_value=0.0, value=float(cn_prod.sale_price) if cn_prod else 100.0, step=10.0)

            cn_pay_label = st.selectbox("طريقة تسوية الإشعار الدائن:", list(pay_method_map.keys()), key="cn_pay")

            if st.button("🚀 إصدار وترحيل الإشعار الدائن", type="primary", disabled=not has_perm("act_create_sales")):
                try:
                    cn_obj = LedgerService.create_credit_debit_note(
                        db=db, note_type=NoteType.CREDIT_NOTE, party_name=cn_party or "عميل عام",
                        party_vat_number=orig_inv.customer_vat_number if orig_inv else None,
                        original_invoice_number=orig_inv.invoice_number if orig_inv else None,
                        sales_invoice_id=orig_inv.id if orig_inv else None,
                        customer_id=orig_inv.customer_id if orig_inv else None,
                        payment_method=pay_method_map[cn_pay_label], reason=cn_reason,
                        items_data=[{
                            "product_id": cn_prod.id if cn_prod else None, "item_name": cn_item_name,
                            "quantity": cn_qty, "unit_price": cn_price,
                            "cost_price": cn_prod.cost_price if cn_prod else 0.0, "tax_rate": float(cn_prod.tax_rate) if cn_prod else float(settings.default_vat_rate)
                        }]
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

        pay_method_map = {
            "بالأجل (على حساب المورد)": PaymentMethod.CREDIT,
            "تحويل بنكي من حساب الشركة": PaymentMethod.BANK,
            "نقداً من الصندوق الرئيسي": PaymentMethod.CASH
        }
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
                pur_pay_method = pay_method_map[st.selectbox("طريقة السداد للمورد:", list(pay_method_map.keys()))]
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
                        payment_method=pur_pay_method, supplier_vat_number=supp_vat, supplier_invoice_number=supp_inv_no
                    )
                    st.session_state["latest_purchase_id"] = new_pur.id
                    st.success(f"🎉 تم تسجيل فاتورة المشتريات برقم: {new_pur.invoice_number}")
                except Exception as e:
                    st.error(f"❌ {str(e)}")

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

            dn4, dn5, dn6, dn7 = st.columns(4)
            with dn4:
                dn_prod = prod_choices[st.selectbox("الصنف المرتجع للمورد:", list(prod_choices.keys()), key="dn_pk")]
            with dn5:
                dn_item_name = st.text_input("وصف البند المرتجع:", value=dn_prod.name_ar if dn_prod else "بند مرتجع مشتريات", key="dn_iname")
            with dn6:
                dn_qty = st.number_input("الكمية المرتجعة للمورد:", min_value=1.0, value=1.0, step=1.0, key="dn_qty")
            with dn7:
                dn_price = st.number_input("سعر الشراء للوحدة المرتجعة:", min_value=0.0, value=float(dn_prod.cost_price) if dn_prod else 100.0, step=10.0, key="dn_pr")

            dn_pay_label = st.selectbox("طريقة تسوية الإشعار المدين مع المورد:", list(pay_method_map.keys()), key="dn_pay")

            if st.button("🚀 إصدار وترحيل الإشعار المدين وخصم المخزون", type="primary", disabled=not has_perm("act_create_purchases")):
                try:
                    dn_obj = LedgerService.create_credit_debit_note(
                        db=db, note_type=NoteType.DEBIT_NOTE, party_name=dn_party or "مورد عام",
                        party_vat_number=orig_pinv.supplier_vat_number if orig_pinv else None,
                        original_invoice_number=orig_pinv.invoice_number if orig_pinv else None,
                        purchase_invoice_id=orig_pinv.id if orig_pinv else None,
                        supplier_id=orig_pinv.supplier_id if orig_pinv else None,
                        payment_method=pay_method_map[dn_pay_label], reason=dn_reason,
                        items_data=[{
                            "product_id": dn_prod.id if dn_prod else None, "item_name": dn_item_name,
                            "quantity": dn_qty, "unit_price": dn_price,
                            "cost_price": dn_prod.cost_price if dn_prod else dn_price, "tax_rate": float(dn_prod.tax_rate) if dn_prod else float(settings.default_vat_rate)
                        }]
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

        pay_map = {
            "نقداً (الصندوق الرئيسي - 110101)": PaymentMethod.CASH,
            "تحويل بنكي / شبكة (البنك الرئيسي - 110201)": PaymentMethod.BANK
        }

        with t_rv:
            r1, r2, r3 = st.columns(3)
            with r1:
                rv_party_type_lbl = st.selectbox("نوع جهة السداد:", ["عميل تجاري (حساب العملاء)", "حساب أستاذ عام آخر"])
                rv_party_type = VoucherPartyType.CUSTOMER if "عميل" in rv_party_type_lbl else VoucherPartyType.OTHER
            with r2:
                rv_pay_lbl = st.selectbox("طريقة التحصيل:", list(pay_map.keys()), key="rv_pay")
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
                        payment_method=pay_map[rv_pay_lbl], target_account_code=rv_target_acc,
                        customer_id=rv_cust_id, cost_center_id=rv_cc
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
                pv_pay_lbl = st.selectbox("طريقة الصرف:", list(pay_map.keys()), key="pv_pay")
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
                        payment_method=pay_map[pv_pay_lbl], target_account_code=pv_target_acc,
                        supplier_id=pv_supp_id, cost_center_id=pv_cc, include_input_vat=pv_inc_vat
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
                                db=db, entry_id=sel_je_obj.id, reason=rev_reason
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
        with t_stmt:
            leaf_accounts = db.query(Account).filter(Account.is_leaf == True).order_by(Account.code).all()
            account_map = {f"{acc.code} - {acc.name_ar}": acc.code for acc in leaf_accounts}
            selected_acc_label = st.selectbox("اختر الحساب:", list(account_map.keys()))
            if selected_acc_label:
                stmt_data = LedgerService.get_account_statement(db=db, account_code=account_map[selected_acc_label])
                b1, b2 = st.columns(2)
                b1.metric("رصيد أول المدة:", f"{stmt_data['opening_balance']:,.2f} ريال")
                b2.metric("رصيد نهاية الفترة:", f"{stmt_data['closing_balance']:,.2f} ريال")
                if stmt_data["statement"]:
                    st.dataframe(pd.DataFrame(stmt_data["statement"]), use_container_width=True, hide_index=True)

        with t_tb:
            inc_zero = st.checkbox("عرض الحسابات ذات الأرصدة الصفرية", value=False)
            tb_df = LedgerService.get_live_trial_balance(db, include_zero_balances=inc_zero)
            if not tb_df.empty:
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
        tb_df = LedgerService.get_live_trial_balance(db, include_zero_balances=True)
        engine = FinancialStatementsEngine(trial_balance_df=tb_df, fiscal_year=settings.fiscal_year, vat_rate=settings.default_vat_rate)
        report = engine.generate_full_financial_report()

        pnl = report["income_statement"]
        bs = report["balance_sheet"]
        cf = report["cash_flow_statement"]
        vat = report["vat_return"]
        zakat = report["zakat_declaration"]

        t1, t2, t3, t4, t5 = st.tabs([
            "📈 قائمة الدخل", "🏛️ المركز المالي", "💵 التدفقات النقدية",
            "🧾 إقرار القيمة المضافة (VAT)", "🕌 إقرار الزكاة (ZATCA)"
        ])
        with t1:
            st.table(pd.DataFrame([
                {"البند": "صافي الإيرادات التشغيلية", "المبلغ (ريال)": f"{pnl['net_revenue']:,.2f}"},
                {"البند": "تكلفة البضاعة المباعة", "المبلغ (ريال)": f"({pnl['cost_of_sales']:,.2f})"},
                {"البند": "مجمل الربح", "المبلغ (ريال)": f"{pnl['gross_profit']:,.2f}"},
                {"البند": "إجمالي المصروفات التشغيلية والإدارية", "المبلغ (ريال)": f"({pnl['operating_expenses']['total']:,.2f})"},
                {"البند": "صافي الربح قبل الزكاة", "المبلغ (ريال)": f"{pnl['profit_before_zakat']:,.2f}"},
                {"البند": "مخصص الزكاة الشرعية", "المبلغ (ريال)": f"({pnl['zakat_expense']:,.2f})"},
                {"البند": "صافي ربح الفترة النهائي", "المبلغ (ريال)": f"{pnl['net_profit']:,.2f}"},
            ]))
        with t2:
            st.write(f"**إجمالي الأصول:** `{bs['total_assets']:,.2f} ريال` | **إجمالي الالتزامات وحقوق الملكية:** `{bs['total_liabilities_and_equity']:,.2f} ريال`")
        with t3:
            st.write(f"**صافي النقد من الأنشطة التشغيلية:** `{cf['operating_activities']['net_cash_from_operating']:,.2f} ريال` | **رصيد النقد الختامي:** `{cf['closing_cash_balance']:,.2f} ريال`")
        with t4:
            st.write(f"**صافي ضريبة القيمة المضافة المستحقة:** `{vat['net_vat_due']:,.2f} ريال` ({vat['settlement_status']})")
        with t5:
            st.write(f"**وعاء الزكاة الشرعي:** `{zakat['zakat_base']:,.2f} ريال` | **الزكاة المستحقة:** `{zakat['zakat_due']:,.2f} ريال`")
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
        "🛡️ سجل الرقابة والتدقيق (Audit Trail)"
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
                in_pin = st.text_input("رمز الدخول السري الجديد (PIN - اتركه فارغاً للإبقاء على الرمز الحالي):", value="" if target_u else "1234", type="password")
                in_max_disc = st.number_input("سقف نسبة الخصم المسموح بها في المبيعات (%):", min_value=0.0, max_value=100.0, value=float(target_u.max_discount_pct if target_u and target_u.max_discount_pct is not None else 15.0), step=5.0)
                in_active = st.checkbox("الحساب نشط ومفعل للدخول", value=target_u.is_active if target_u else True)

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

            st.markdown("###### **2️⃣ تخصيص صلاحيات العمليات والإجراءات الدقيقة داخل النظام (16 عملية رقابية):**")
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
            logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(100).all()
            if logs:
                log_rows = [{
                    "رقم العملية": l.id,
                    "التاريخ والوقت": l.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "المستخدم المسؤول": getattr(l, "performed_by", None) or "مدير النظام",
                    "الجدول": l.table_name,
                    "نوع الإجراء": l.action,
                    "التفاصيل": l.details or ""
                } for l in logs]
                st.dataframe(pd.DataFrame(log_rows), use_container_width=True, hide_index=True)
    finally:
        db.close()