"""
MizanPro - Google Drive Cloud Integration Service (OAuth 2.0 + Firebase Auth)
النظام المالي المتكامل - ميزان برو
خدمة التكامل السحابي مع Google Drive لحفظ ومزامنة التقارير المالية، القوائم المعتمدة (CPA)، والنسخ الاحتياطية
"""

import os
import json
import base64
import urllib.request
import urllib.parse
from typing import List, Dict, Any, Optional

# قائمة النطاقات المعتمدة (Google Drive OAuth Scopes)
SCOPES: List[str] = [
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/drive.activity",
    "https://www.googleapis.com/auth/drive.activity.readonly",
    "https://www.googleapis.com/auth/drive.appdata",
    "https://www.googleapis.com/auth/drive.apps.readonly",
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/drive.install",
    "https://www.googleapis.com/auth/drive.meet.readonly",
    "https://www.googleapis.com/auth/drive.metadata",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/drive.photos.readonly",
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/drive.scripts",
]


class GoogleDriveService:
    """خدمة التكامل السحابي مع Google Drive عبر Firebase Auth وواجهة Drive REST API v3"""

    CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firebase-applet-config.json")

    @classmethod
    def load_firebase_config(cls) -> Dict[str, Any]:
        """قراءة إعدادات Firebase المعتمدة للمشروع من ملف firebase-applet-config.json"""
        if os.path.exists(cls.CONFIG_PATH):
            with open(cls.CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    @classmethod
    def list_files_with_bearer_token(
        cls,
        access_token: str,
        page_size: int = 20,
        query: str = "trashed = false"
    ) -> Dict[str, Any]:
        """استعلام ملفات Google Drive باستخدام رمز الوصول (Bearer Access Token)"""
        if not access_token:
            raise ValueError("رمز الوصول (Access Token) مطلوب للاتصال بـ Google Drive.")
        params = urllib.parse.urlencode({
            "pageSize": page_size,
            "q": query,
            "fields": "files(id,name,mimeType,size,modifiedTime,webViewLink,iconLink)",
            "orderBy": "modifiedTime desc"
        })
        url = f"https://www.googleapis.com/drive/v3/files?{params}"
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))

    @classmethod
    def render_google_drive_workspace_html(
        cls,
        excel_report_b64: str = "",
        excel_filename: str = "MizanPro_Executive_Report_2026.xlsx",
        cpa_word_b64: str = "",
        cpa_word_filename: str = "CPA_Audited_Financial_Statements_2026.doc",
        db_backup_b64: str = "",
        db_backup_filename: str = "MizanPro_Ledger_Backup.db",
        compact_mode: bool = False
    ) -> str:
        """
        توليد واجهة التكامل السحابي التفاعلية مع Google Drive:
        - مصادقة المستخدم عبر Firebase Auth (signInWithPopup) وحفظ رمز الوصول في الذاكرة (cachedAccessToken) فقط.
        - زر تسجيل الدخول الرسمي (Sign in with Google - gsi-material-button).
        - استعراض وبحث وتصفية ملفات Google Drive وسجل النشاطات (Drive Activity API).
        - رفع تقارير MizanPro (Excel 15 صفحة، تقرير المراجع القانوني Word، النسخة الاحتياطية لقاعدة البيانات) بضغطة واحدة.
        - نافذة تأكيد إلزامية (Confirmation Modal) قبل أي عملية تعديل/استبدال أو حذف لملفات المستخدم على Google Drive.
        """
        firebase_cfg = cls.load_firebase_config()
        firebase_cfg_json = json.dumps(firebase_cfg, ensure_ascii=False)
        scopes_json = json.dumps(SCOPES, ensure_ascii=False)

        html = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8" />
<link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700;800&family=Roboto:wght@500&display=swap" rel="stylesheet">
<style>
  * {{
    box-sizing: border-box;
    font-family: 'Tajawal', sans-serif;
  }}
  body {{
    margin: 0;
    padding: 0;
    background: transparent;
    color: #0f172a;
    direction: rtl;
  }}
  .gdrive-shell {{
    background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
    border: 1px solid #cbd5e1;
    border-radius: 14px;
    padding: 18px 20px;
    box-shadow: 0 4px 16px rgba(15, 23, 42, 0.05);
  }}
  .gdrive-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 12px;
    padding-bottom: 14px;
    border-bottom: 1px solid #e2e8f0;
  }}
  .gdrive-brand {{
    display: flex;
    align-items: center;
    gap: 12px;
  }}
  .gdrive-title {{
    margin: 0;
    font-size: 1.15rem;
    font-weight: 800;
    color: #0f172a;
  }}
  .gdrive-subtitle {{
    margin: 2px 0 0 0;
    font-size: 0.85rem;
    color: #475569;
  }}

  /* Official Sign in with Google Button (.gsi-material-button) */
  .gsi-material-button {{
    -moz-user-select: none;
    -webkit-user-select: none;
    -ms-user-select: none;
    -webkit-appearance: none;
    background-color: #ffffff;
    background-image: none;
    border: 1px solid #747775;
    -webkit-border-radius: 20px;
    border-radius: 20px;
    -webkit-box-sizing: border-box;
    box-sizing: border-box;
    color: #1f1f1f;
    cursor: pointer;
    font-family: 'Roboto', 'Tajawal', arial, sans-serif;
    font-size: 14px;
    height: 40px;
    letter-spacing: 0.25px;
    outline: none;
    overflow: hidden;
    padding: 0 16px;
    position: relative;
    text-align: center;
    -webkit-transition: background-color .218s, border-color .218s, box-shadow .218s;
    transition: background-color .218s, border-color .218s, box-shadow .218s;
    vertical-align: middle;
    white-space: nowrap;
    width: auto;
    max-width: 400px;
    min-width: min-content;
    direction: ltr;
  }}
  .gsi-material-button .gsi-material-button-icon {{
    height: 20px;
    margin-right: 10px;
    min-width: 20px;
    width: 20px;
  }}
  .gsi-material-button .gsi-material-button-content-wrapper {{
    -webkit-align-items: center;
    align-items: center;
    display: flex;
    -webkit-flex-direction: row;
    flex-direction: row;
    -webkit-flex-wrap: nowrap;
    flex-wrap: nowrap;
    height: 100%;
    justify-content: space-between;
    position: relative;
    width: 100%;
  }}
  .gsi-material-button .gsi-material-button-contents {{
    -webkit-flex-grow: 1;
    flex-grow: 1;
    font-family: 'Roboto', 'Tajawal', arial, sans-serif;
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    vertical-align: top;
  }}
  .gsi-material-button .gsi-material-button-state {{
    -webkit-transition: opacity .218s;
    transition: opacity .218s;
    bottom: 0;
    left: 0;
    opacity: 0;
    position: absolute;
    right: 0;
    top: 0;
  }}
  .gsi-material-button:hover {{
    -webkit-box-shadow: 0 1px 2px 0 rgba(60, 64, 67, .30), 0 1px 3px 1px rgba(60, 64, 67, .15);
    box-shadow: 0 1px 2px 0 rgba(60, 64, 67, .30), 0 1px 3px 1px rgba(60, 64, 67, .15);
    background-color: #f8fafd;
  }}

  .user-pill {{
    display: inline-flex;
    align-items: center;
    gap: 10px;
    background: #f0fdf4;
    border: 1px solid #86efac;
    padding: 6px 14px;
    border-radius: 999px;
    font-size: 0.85rem;
    color: #166534;
    font-weight: 700;
  }}
  .user-pill img {{
    width: 26px;
    height: 26px;
    border-radius: 50%;
  }}
  .btn {{
    border: none;
    border-radius: 8px;
    padding: 8px 14px;
    font-size: 0.86rem;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.15s ease;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }}
  .btn-primary {{
    background: #1d4ed8;
    color: #ffffff;
  }}
  .btn-primary:hover {{
    background: #1e40af;
  }}
  .btn-success {{
    background: #059669;
    color: #ffffff;
  }}
  .btn-success:hover {{
    background: #047857;
  }}
  .btn-outline {{
    background: #ffffff;
    color: #334155;
    border: 1px solid #cbd5e1;
  }}
  .btn-outline:hover {{
    background: #f1f5f9;
  }}
  .btn-danger {{
    background: #dc2626;
    color: #ffffff;
  }}
  .btn-danger:hover {{
    background: #b91c1c;
  }}
  .btn-warning {{
    background: #d97706;
    color: #ffffff;
  }}
  .btn-warning:hover {{
    background: #b45309;
  }}

  .status-banner {{
    margin-top: 12px;
    padding: 10px 14px;
    border-radius: 8px;
    font-size: 0.88rem;
    font-weight: 600;
    display: none;
  }}
  .status-info {{
    background: #eff6ff;
    color: #1e40af;
    border: 1px solid #bfdbfe;
  }}
  .status-success {{
    background: #f0fdf4;
    color: #166534;
    border: 1px solid #bbf7d0;
  }}
  .status-error {{
    background: #fef2f2;
    color: #991b1b;
    border: 1px solid #fecaca;
  }}

  .quick-actions-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 12px;
    margin-top: 14px;
  }}
  .action-card {{
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    gap: 10px;
  }}
  .action-card h4 {{
    margin: 0;
    font-size: 0.94rem;
    color: #0f172a;
  }}
  .action-card p {{
    margin: 4px 0 0 0;
    font-size: 0.78rem;
    color: #64748b;
    line-height: 1.4;
  }}

  .toolbar {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
    justify-content: space-between;
    margin-top: 16px;
    padding-top: 14px;
    border-top: 1px solid #e2e8f0;
  }}
  .search-input {{
    flex: 1;
    min-width: 200px;
    padding: 8px 12px;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    font-size: 0.88rem;
  }}
  .filter-select {{
    padding: 8px 12px;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    font-size: 0.88rem;
    background: #ffffff;
  }}

  .files-table-wrap {{
    margin-top: 12px;
    max-height: 320px;
    overflow-y: auto;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    background: #ffffff;
  }}
  table.files-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
  }}
  table.files-table th {{
    background: #f8fafc;
    color: #334155;
    font-weight: 700;
    text-align: right;
    padding: 10px 12px;
    position: sticky;
    top: 0;
    border-bottom: 1px solid #cbd5e1;
  }}
  table.files-table td {{
    padding: 9px 12px;
    border-bottom: 1px solid #f1f5f9;
    color: #1e293b;
    vertical-align: middle;
  }}
  table.files-table tr:hover td {{
    background: #f8fafc;
  }}

  /* Mandatory Confirmation Dialog Modal */
  .modal-backdrop {{
    position: fixed;
    inset: 0;
    background: rgba(15, 23, 42, 0.55);
    display: none;
    align-items: center;
    justify-content: center;
    z-index: 9999;
    padding: 16px;
  }}
  .modal-box {{
    background: #ffffff;
    border-radius: 14px;
    max-width: 480px;
    width: 100%;
    padding: 20px 22px;
    box-shadow: 0 20px 38px rgba(15, 23, 42, 0.25);
    border: 1px solid #cbd5e1;
  }}
  .modal-title {{
    margin: 0 0 8px 0;
    font-size: 1.08rem;
    font-weight: 800;
    color: #0f172a;
  }}
  .modal-body {{
    font-size: 0.9rem;
    color: #334155;
    line-height: 1.55;
    margin-bottom: 18px;
    background: #f8fafc;
    padding: 12px;
    border-radius: 8px;
    border-right: 4px solid #dc2626;
  }}
  .modal-actions {{
    display: flex;
    justify-content: flex-end;
    gap: 10px;
  }}
</style>
</head>
<body>

<div class="gdrive-shell">
  <div class="gdrive-header">
    <div class="gdrive-brand">
      <svg width="34" height="34" viewBox="0 0 87.3 78" xmlns="http://www.w3.org/2000/svg">
        <path d="m6.6 66.85 3.85 6.65c.8 1.4 1.95 2.5 3.3 3.3l13.75-23.8h-27.5c0 1.55.4 3.1 1.2 4.5z" fill="#0066da"/>
        <path d="m43.65 25-13.75-23.8c-1.35.8-2.5 1.9-3.3 3.3l-25.4 44a9.06 9.06 0 0 0 -1.2 4.5h27.5z" fill="#00ac47"/>
        <path d="m73.55 76.8c1.35-.8 2.5-1.9 3.3-3.3l1.6-2.75 7.65-13.25c.8-1.4 1.2-2.95 1.2-4.5h-27.502l5.852 11.5z" fill="#ea4335"/>
        <path d="m43.65 25 13.75-23.8c-1.35-.8-2.9-1.2-4.5-1.2h-18.5c-1.6 0-3.15.45-4.5 1.2z" fill="#00832d"/>
        <path d="m59.8 53h-32.3l-13.75 23.8c1.35.8 2.9 1.2 4.5 1.2h50.8c1.6 0 3.15-.45 4.5-1.2z" fill="#2684fc"/>
        <path d="m73.4 26.5-12.7-22c-.8-1.4-1.95-2.5-3.3-3.3l-13.75 23.8 16.15 28h27.45c0-1.55-.4-3.1-1.2-4.5z" fill="#ffba00"/>
      </svg>
      <div>
        <h3 class="gdrive-title">مركز التكامل السحابي مع Google Drive</h3>
        <p class="gdrive-subtitle">حفظ ومزامنة القوائم المالية المعتمدة (CPA)، مصنف الإكسيل التنفيذي (15 صفحة)، والنسخ الاحتياطية مباشرة في حسابك على Google Drive</p>
      </div>
    </div>

    <!-- Auth Section -->
    <div id="authArea">
      <button id="googleSignInBtn" class="gsi-material-button" onclick="handleGoogleSignIn()">
        <div class="gsi-material-button-state"></div>
        <div class="gsi-material-button-content-wrapper">
          <div class="gsi-material-button-icon">
            <svg version="1.1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" xmlns:xlink="http://www.w3.org/1999/xlink" style="display: block;">
              <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"></path>
              <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"></path>
              <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"></path>
              <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"></path>
              <path fill="none" d="M0 0h48H0z"></path>
            </svg>
          </div>
          <span class="gsi-material-button-contents">Sign in with Google</span>
          <span style="display: none;">Sign in with Google</span>
        </div>
      </button>

      <div id="signedInUserBox" style="display: none; align-items: center; gap: 10px;">
        <span class="user-pill">
          <img id="userAvatar" src="" alt="" style="display:none;" />
          <span id="userNameEmail">متصل بـ Google Drive</span>
        </span>
        <button class="btn btn-outline" onclick="handleGoogleSignOut()">تسجيل الخروج</button>
      </div>
    </div>
  </div>

  <div id="statusBanner" class="status-banner"></div>

  <!-- Authenticated Workspace Content -->
  <div id="driveWorkspace" style="display: none;">
    <div class="quick-actions-grid">
      <div class="action-card">
        <div>
          <h4>📊 رفع المصنف المالي التنفيذي (15 صفحة)</h4>
          <p>حفظ نسخة فورية من مصنف الإكسيل التنفيذي الشامل للقوائم والزكاة والضريبة في Google Drive.</p>
        </div>
        <button class="btn btn-success" onclick="uploadPrebuiltReport('excel')">☁️ رفع مصنف الإكسيل إلى Drive</button>
      </div>

      <div class="action-card">
        <div>
          <h4>📝 رفع تقرير المراجع القانوني (Word .doc)</h4>
          <p>رفع القوائم المالية المعتمدة والإيضاحات الـ 18 بصيغة Word قابلة للتعديل إلى Google Drive.</p>
        </div>
        <button class="btn btn-primary" onclick="uploadPrebuiltReport('word')">☁️ رفع تقرير الـ CPA إلى Drive</button>
      </div>

      <div class="action-card">
        <div>
          <h4>💾 نسخ احتياطي سحابي لقاعدة البيانات</h4>
          <p>رفع ملف قاعدة البيانات المحاسبية (SQLite .db) إلى Google Drive لحفظه بأمان.</p>
        </div>
        <button class="btn btn-outline" onclick="uploadPrebuiltReport('db')">☁️ رفع النسخة الاحتياطية لـ Drive</button>
      </div>

      <div class="action-card">
        <div>
          <h4>📤 رفع ملف من جهازك أو إنشاء مجلد</h4>
          <p>ارفع أي ميزان مراجعة خارجي أو مستند محاسبي مباشرة إلى مجلداتك في Google Drive.</p>
        </div>
        <div style="display:flex; gap:6px; flex-wrap:wrap;">
          <label class="btn btn-outline" style="cursor:pointer;">
            📁 اختيار ملف للرفع
            <input type="file" id="localFileInput" style="display:none;" onchange="handleLocalFileSelect(event)" />
          </label>
          <button class="btn btn-outline" onclick="createMizanProFolder()">➕ مجلد MizanPro</button>
        </div>
      </div>
    </div>

    <div class="toolbar">
      <div style="display:flex; gap:8px; flex:1; flex-wrap:wrap;">
        <input type="text" id="searchQueryInput" class="search-input" placeholder="🔍 ابحث في ملفات Google Drive بالاسم..." onkeydown="if(event.key==='Enter') loadDriveFiles();" />
        <select id="mimeFilterSelect" class="filter-select" onchange="loadDriveFiles()">
          <option value="all">جميع الملفات والمجلدات</option>
          <option value="spreadsheets">جداول البيانات (Excel / Google Sheets)</option>
          <option value="documents">المستندات والتقارير (Word / Docs / PDF)</option>
          <option value="folders">المجلدات فقط</option>
        </select>
        <button class="btn btn-primary" onclick="loadDriveFiles()">🔄 تحديث القائمة</button>
        <button class="btn btn-outline" onclick="loadDriveActivity()">🕒 سجل النشاطات</button>
      </div>
      <div>
        <button class="btn btn-danger" onclick="promptBulkDeleteSelected()">🗑️ حذف المحدد</button>
      </div>
    </div>

    <div id="activityPanel" style="display:none; margin-top:12px; padding:12px; background:#f8fafc; border:1px solid #cbd5e1; border-radius:10px; font-size:0.84rem;"></div>

    <div class="files-table-wrap">
      <table class="files-table">
        <thead>
          <tr>
            <th style="width:36px;"><input type="checkbox" id="selectAllCheckbox" onchange="toggleSelectAllFiles(this)" /></th>
            <th>اسم الملف / المستند</th>
            <th>النوع</th>
            <th>الحجم</th>
            <th>آخر تعديل</th>
            <th>الإجراءات السحابية</th>
          </tr>
        </thead>
        <tbody id="driveFilesTbody">
          <tr>
            <td colspan="6" style="text-align:center; padding:24px; color:#64748b;">قم بتسجيل الدخول عبر Google لاستعراض وإدارة ملفاتك على Google Drive.</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- Mandatory Confirmation Modal for Mutating/Destructive Actions -->
<div id="confirmModalBackdrop" class="modal-backdrop">
  <div class="modal-box">
    <h4 id="confirmModalTitle" class="modal-title">⚠️ تأكيد العملية على Google Drive</h4>
    <div id="confirmModalBody" class="modal-body"></div>
    <div class="modal-actions">
      <button class="btn btn-outline" onclick="closeConfirmModal()">إلغاء الأمر (Cancel)</button>
      <button id="confirmModalActionBtn" class="btn btn-danger" onclick="executeConfirmedAction()">تأكيد التنفيذ (Confirm)</button>
    </div>
  </div>
</div>

<script type="module">
  import {{ initializeApp, getApps, getApp }} from 'https://www.gstatic.com/firebasejs/11.0.1/firebase-app.js';
  import {{ getAuth, signInWithPopup, GoogleAuthProvider, onAuthStateChanged }} from 'https://www.gstatic.com/firebasejs/11.0.1/firebase-auth.js';

  const firebaseConfig = {firebase_cfg_json};
  const SCOPES = {scopes_json};

  const PREBUILT_PAYLOADS = {{
    excel: {{
      b64: "{excel_report_b64}",
      name: "{excel_filename}",
      mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    }},
    word: {{
      b64: "{cpa_word_b64}",
      name: "{cpa_word_filename}",
      mime: "application/msword"
    }},
    db: {{
      b64: "{db_backup_b64}",
      name: "{db_backup_filename}",
      mime: "application/octet-stream"
    }}
  }};

  const app = getApps().length === 0 ? initializeApp(firebaseConfig) : getApp();
  const auth = getAuth(app);
  const provider = new GoogleAuthProvider();
  SCOPES.forEach((scope) => provider.addScope(scope));

  // In-memory access token cache (NEVER stored in localStorage or sessionStorage)
  let isSigningIn = false;
  let cachedAccessToken = null;
  let pendingConfirmCallback = null;

  function showStatus(msg, type = 'info') {{
    const el = document.getElementById('statusBanner');
    el.className = 'status-banner status-' + type;
    el.textContent = msg;
    el.style.display = 'block';
  }}

  function updateAuthUI(user, hasToken) {{
    const signInBtn = document.getElementById('googleSignInBtn');
    const signedInBox = document.getElementById('signedInUserBox');
    const workspace = document.getElementById('driveWorkspace');
    const nameEmailEl = document.getElementById('userNameEmail');
    const avatarEl = document.getElementById('userAvatar');

    if (user && hasToken) {{
      signInBtn.style.display = 'none';
      signedInBox.style.display = 'inline-flex';
      workspace.style.display = 'block';
      nameEmailEl.textContent = (user.displayName ? user.displayName + ' (' + user.email + ')' : user.email);
      if (user.photoURL) {{
        avatarEl.src = user.photoURL;
        avatarEl.style.display = 'inline-block';
      }}
    }} else {{
      signInBtn.style.display = 'inline-block';
      signedInBox.style.display = 'none';
      workspace.style.display = 'none';
    }}
  }}

  export const initAuth = (onAuthSuccess, onAuthFailure) => {{
    return onAuthStateChanged(auth, async (user) => {{
      if (user) {{
        if (cachedAccessToken) {{
          if (onAuthSuccess) onAuthSuccess(user, cachedAccessToken);
        }} else if (!isSigningIn) {{
          cachedAccessToken = null;
          if (onAuthFailure) onAuthFailure();
        }}
      }} else {{
        cachedAccessToken = null;
        if (onAuthFailure) onAuthFailure();
      }}
    }});
  }};

  window.handleGoogleSignIn = async () => {{
    try {{
      isSigningIn = true;
      showStatus('جاري فتح نافذة المصادقة الآمنة مع Google...', 'info');
      const result = await signInWithPopup(auth, provider);
      const credential = GoogleAuthProvider.credentialFromResult(result);
      if (!credential || !credential.accessToken) {{
        throw new Error('تعذر الحصول على رمز الوصول (Access Token) من مصادقة Google.');
      }}
      cachedAccessToken = credential.accessToken;
      updateAuthUI(result.user, true);
      showStatus('✅ تم الربط بنجاح مع حسابك في Google Drive!', 'success');
      await window.loadDriveFiles();
    }} catch (err) {{
      console.error('Sign in error:', err);
      showStatus('❌ تعذر تسجيل الدخول إلى Google Drive: ' + (err.message || err), 'error');
    }} finally {{
      isSigningIn = false;
    }}
  }};

  window.handleGoogleSignOut = async () => {{
    await auth.signOut();
    cachedAccessToken = null;
    updateAuthUI(null, false);
    showStatus('تم تسجيل الخروج ومسح رمز الوصول من الذاكرة.', 'info');
  }};

  function openConfirmModal(title, bodyText, actionLabel, actionBtnClass, onConfirm) {{
    document.getElementById('confirmModalTitle').textContent = title;
    document.getElementById('confirmModalBody').textContent = bodyText;
    const btn = document.getElementById('confirmModalActionBtn');
    btn.textContent = actionLabel;
    btn.className = 'btn ' + actionBtnClass;
    pendingConfirmCallback = onConfirm;
    document.getElementById('confirmModalBackdrop').style.display = 'flex';
  }}

  window.closeConfirmModal = () => {{
    pendingConfirmCallback = null;
    document.getElementById('confirmModalBackdrop').style.display = 'none';
  }};

  window.executeConfirmedAction = async () => {{
    const cb = pendingConfirmCallback;
    window.closeConfirmModal();
    if (cb) {{
      await cb();
    }}
  }};

  function formatBytes(bytes) {{
    if (!bytes) return '—';
    const b = parseInt(bytes, 10);
    if (isNaN(b) || b === 0) return '—';
    if (b < 1024) return b + ' B';
    if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB';
    return (b / (1024 * 1024)).toFixed(2) + ' MB';
  }}

  function b64ToBlob(b64Data, contentType = '', sliceSize = 512) {{
    const byteCharacters = atob(b64Data);
    const byteArrays = [];
    for (let offset = 0; offset < byteCharacters.length; offset += sliceSize) {{
      const slice = byteCharacters.slice(offset, offset + sliceSize);
      const byteNumbers = new Array(slice.length);
      for (let i = 0; i < slice.length; i++) {{
        byteNumbers[i] = slice.charCodeAt(i);
      }}
      const byteArray = new Uint8Array(byteNumbers);
      byteArrays.push(byteArray);
    }}
    return new Blob(byteArrays, {{ type: contentType }});
  }}

  window.loadDriveFiles = async () => {{
    if (!cachedAccessToken) {{
      updateAuthUI(null, false);
      return;
    }}
    try {{
      const searchQ = (document.getElementById('searchQueryInput').value || '').trim();
      const mimeFilter = document.getElementById('mimeFilterSelect').value;
      let qParts = ['trashed = false'];
      if (searchQ) {{
        const safeQ = searchQ.replace(/'/g, "\\'");
        qParts.push(`name contains '${{safeQ}}'`);
      }}
      if (mimeFilter === 'spreadsheets') {{
        qParts.push("(mimeType = 'application/vnd.google-apps.spreadsheet' or mimeType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' or mimeType = 'text/csv')");
      }} else if (mimeFilter === 'documents') {{
        qParts.push("(mimeType = 'application/vnd.google-apps.document' or mimeType = 'application/msword' or mimeType = 'application/pdf')");
      }} else if (mimeFilter === 'folders') {{
        qParts.push("mimeType = 'application/vnd.google-apps.folder'");
      }}

      const params = new URLSearchParams({{
        pageSize: '25',
        q: qParts.join(' and '),
        fields: 'files(id,name,mimeType,size,modifiedTime,webViewLink)',
        orderBy: 'modifiedTime desc'
      }});

      const res = await fetch(`https://www.googleapis.com/drive/v3/files?${{params.toString()}}`, {{
        headers: {{ Authorization: `Bearer ${{cachedAccessToken}}` }}
      }});
      if (res.status === 401) {{
        cachedAccessToken = null;
        updateAuthUI(null, false);
        showStatus('انتهت صلاحية الجلسة. يرجى تسجيل الدخول مجدداً.', 'error');
        return;
      }}
      const data = await res.json();
      const files = data.files || [];
      const tbody = document.getElementById('driveFilesTbody');
      tbody.innerHTML = '';

      if (files.length === 0) {{
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px; color:#64748b;">لا توجد ملفات مطابقة للبحث في Google Drive.</td></tr>';
        return;
      }}

      files.forEach((f) => {{
        const tr = document.createElement('tr');
        const isFolder = f.mimeType === 'application/vnd.google-apps.folder';
        const typeBadge = isFolder ? '📁 مجلد' : (f.mimeType.includes('spreadsheet') || f.name.endsWith('.xlsx') ? '📊 جدول بيانات' : (f.mimeType.includes('word') || f.name.endsWith('.doc') ? '📝 مستند Word' : '📄 ملف'));
        const modDate = f.modifiedTime ? new Date(f.modifiedTime).toLocaleString('ar-SA') : '—';
        const safeName = (f.name || '').replace(/'/g, "\\'").replace(/"/g, '&quot;');

        tr.innerHTML = `
          <td><input type="checkbox" class="drive-file-chk" data-id="${{f.id}}" data-name="${{safeName}}" /></td>
          <td style="font-weight:700;">${{f.name}}</td>
          <td>${{typeBadge}}</td>
          <td>${{formatBytes(f.size)}}</td>
          <td style="direction:ltr; text-align:right;">${{modDate}}</td>
          <td>
            <div style="display:flex; gap:6px; flex-wrap:wrap;">
              ${{f.webViewLink ? `<a href="${{f.webViewLink}}" target="_blank" rel="noopener noreferrer" class="btn btn-outline" style="text-decoration:none; padding:4px 10px; font-size:0.78rem;">🔗 فتح في Drive</a>` : ''}}
              ${{!isFolder ? `<button class="btn btn-warning" style="padding:4px 10px; font-size:0.78rem;" onclick="promptOverwriteFile('${{f.id}}', '${{safeName}}')">🔄 تحديث بالتقرير الحالي</button>` : ''}}
              <button class="btn btn-danger" style="padding:4px 10px; font-size:0.78rem;" onclick="promptDeleteSingleFile('${{f.id}}', '${{safeName}}')">🗑️ حذف</button>
            </div>
          </td>
        `;
        tbody.appendChild(tr);
      }});
    }} catch (err) {{
      console.error('Error listing Drive files:', err);
      showStatus('❌ تعذر جلب قائمة الملفات من Google Drive: ' + err.message, 'error');
    }}
  }};

  window.uploadBlobToDrive = async (blob, filename, mimeType, existingFileId = null) => {{
    if (!cachedAccessToken) {{
      showStatus('يرجى تسجيل الدخول إلى Google Drive أولاً.', 'error');
      return;
    }}
    try {{
      showStatus(`⏳ جاري رفع "${{filename}}" إلى Google Drive...`, 'info');
      const metadata = {{ name: filename, mimeType: mimeType }};
      const form = new FormData();
      form.append('metadata', new Blob([JSON.stringify(metadata)], {{ type: 'application/json' }}));
      form.append('file', blob);

      const url = existingFileId
        ? `https://www.googleapis.com/upload/drive/v3/files/${{existingFileId}}?uploadType=multipart`
        : 'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart';
      const method = existingFileId ? 'PATCH' : 'POST';

      const res = await fetch(url, {{
        method: method,
        headers: {{ Authorization: `Bearer ${{cachedAccessToken}}` }},
        body: form
      }});
      const data = await res.json();
      if (!res.ok) {{
        throw new Error((data.error && data.error.message) || 'فشل رفع الملف');
      }}
      showStatus(`✅ تم حفظ "${{data.name || filename}}" في Google Drive بنجاح!`, 'success');
      await window.loadDriveFiles();
    }} catch (err) {{
      showStatus('❌ خطأ أثناء رفع الملف إلى Google Drive: ' + err.message, 'error');
    }}
  }};

  window.uploadPrebuiltReport = async (key) => {{
    const item = PREBUILT_PAYLOADS[key];
    if (!item || !item.b64) {{
      showStatus('⚠️ هذا التقرير غير متوفر حالياً للرفع المباشر.', 'error');
      return;
    }}
    const blob = b64ToBlob(item.b64, item.mime);
    await window.uploadBlobToDrive(blob, item.name, item.mime, null);
  }};

  window.handleLocalFileSelect = async (event) => {{
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    await window.uploadBlobToDrive(file, file.name, file.type || 'application/octet-stream', null);
    event.target.value = '';
  }};

  window.createMizanProFolder = async () => {{
    if (!cachedAccessToken) return;
    try {{
      const folderName = 'MizanPro ERP - الأرشيف المالي السحابي';
      const res = await fetch('https://www.googleapis.com/drive/v3/files', {{
        method: 'POST',
        headers: {{
          Authorization: `Bearer ${{cachedAccessToken}}`,
          'Content-Type': 'application/json'
        }},
        body: JSON.stringify({{
          name: folderName,
          mimeType: 'application/vnd.google-apps.folder'
        }})
      }});
      const data = await res.json();
      if (!res.ok) throw new Error((data.error && data.error.message) || 'تعذر إنشاء المجلد');
      showStatus(`✅ تم إنشاء المجلد "${{data.name}}" في Google Drive بنجاح!`, 'success');
      await window.loadDriveFiles();
    }} catch (err) {{
      showStatus('❌ تعذر إنشاء المجلد: ' + err.message, 'error');
    }}
  }};

  // Mandatory Confirmation before updating/overwriting an existing file
  window.promptOverwriteFile = (fileId, fileName) => {{
    openConfirmModal(
      '⚠️ تأكيد تحديث واستبدال محتوى ملف على Google Drive',
      `هل أنت متأكد من رغبتك في تحديث واستبدال محتوى الملف "${{fileName}}" في Google Drive بأحدث نسخة من تقرير النظام؟ لا يمكن التراجع عن هذا التعديل تلقائياً.`,
      'تأكيد التحديث (Confirm Update)',
      'btn-warning',
      async () => {{
        const isWord = fileName.endsWith('.doc') || fileName.endsWith('.docx');
        const payload = isWord ? PREBUILT_PAYLOADS.word : PREBUILT_PAYLOADS.excel;
        const blob = b64ToBlob(payload.b64, payload.mime);
        await window.uploadBlobToDrive(blob, fileName, payload.mime, fileId);
      }}
    );
  }};

  // Mandatory Confirmation before deleting a single file
  window.promptDeleteSingleFile = (fileId, fileName) => {{
    openConfirmModal(
      '⚠️ تأكيد حذف ملف من Google Drive',
      `هل أنت متأكد من حذف الملف "${{fileName}}" نهائياً من حسابك في Google Drive؟ هذا الإجراء لا يمكن التراجع عنه.`,
      'تأكيد الحذف النهائي (Delete)',
      'btn-danger',
      async () => {{
        await deleteDriveFilesByIds([fileId]);
      }}
    );
  }};

  // Mandatory Confirmation before bulk deleting selected files
  window.promptBulkDeleteSelected = () => {{
    const checked = Array.from(document.querySelectorAll('.drive-file-chk:checked'));
    if (checked.length === 0) {{
      showStatus('يرجى تحديد ملف واحد على الأقل من الجدول لحذفه.', 'info');
      return;
    }}
    const names = checked.map((c) => c.getAttribute('data-name')).join(' ، ');
    const ids = checked.map((c) => c.getAttribute('data-id'));
    openConfirmModal(
      `⚠️ تأكيد حذف (${{ids.length}}) ملفات من Google Drive`,
      `سيتم حذف (${{ids.length}}) ملف/ملفات بشكل نهائي من Google Drive: [${{names}}]. هل تؤكد تنفيذ الحذف؟`,
      `تأكيد حذف (${{ids.length}}) ملفات`,
      'btn-danger',
      async () => {{
        await deleteDriveFilesByIds(ids);
      }}
    );
  }};

  async function deleteDriveFilesByIds(fileIds) {{
    if (!cachedAccessToken) return;
    try {{
      showStatus(`⏳ جاري حذف (${{fileIds.length}}) ملف من Google Drive...`, 'info');
      for (const fileId of fileIds) {{
        const res = await fetch(`https://www.googleapis.com/drive/v3/files/${{fileId}}`, {{
          method: 'DELETE',
          headers: {{ Authorization: `Bearer ${{cachedAccessToken}}` }}
        }});
        if (!res.ok && res.status !== 204) {{
          const errData = await res.json().catch(() => ({{}}));
          throw new Error((errData.error && errData.error.message) || 'فشل حذف الملف');
        }}
      }}
      showStatus(`✅ تم حذف (${{fileIds.length}}) ملف من Google Drive بنجاح.`, 'success');
      await window.loadDriveFiles();
    }} catch (err) {{
      showStatus('❌ تعذر حذف الملف من Google Drive: ' + err.message, 'error');
    }}
  }}

  window.toggleSelectAllFiles = (masterChk) => {{
    document.querySelectorAll('.drive-file-chk').forEach((chk) => {{
      chk.checked = masterChk.checked;
    }});
  }};

  window.loadDriveActivity = async () => {{
    if (!cachedAccessToken) return;
    const panel = document.getElementById('activityPanel');
    panel.style.display = 'block';
    panel.innerHTML = '⏳ جاري استعلام أحدث نشاطات Google Drive (Drive Activity API)...';
    try {{
      const res = await fetch('https://driveactivity.googleapis.com/v2/activity:query', {{
        method: 'POST',
        headers: {{
          Authorization: `Bearer ${{cachedAccessToken}}`,
          'Content-Type': 'application/json'
        }},
        body: JSON.stringify({{ pageSize: 5 }})
      }});
      const data = await res.json();
      const activities = data.activities || [];
      if (activities.length === 0) {{
        panel.innerHTML = 'ℹ️ لا توجد نشاطات حديثة مسجلة حالياً.';
        return;
      }}
      const itemsHtml = activities.slice(0, 5).map((act) => {{
        const ts = act.timestamp ? new Date(act.timestamp).toLocaleString('ar-SA') : '';
        const targetTitle = (act.targets && act.targets[0] && act.targets[0].driveItem && act.targets[0].driveItem.title) || 'ملف على Drive';
        const actionType = Object.keys(act.primaryActionDetail || {{}})[0] || 'نشاط';
        return `<li><strong>${{targetTitle}}</strong> — نوع الإجراء: <code>${{actionType}}</code> (${{ts}})</li>`;
      }}).join('');
      panel.innerHTML = `<strong>🕒 أحدث 5 نشاطات في Google Drive:</strong><ul style="margin:6px 0 0 0; padding-right:18px;">${{itemsHtml}}</ul>`;
    }} catch (err) {{
      panel.innerHTML = '⚠️ تعذر جلب سجل النشاطات: ' + err.message;
    }}
  }};

  // Initialize auth listener on load
  initAuth(
    (user) => {{
      updateAuthUI(user, true);
      window.loadDriveFiles();
    }},
    () => {{
      updateAuthUI(null, false);
    }}
  );
</script>
</body>
</html>
"""
        return html
