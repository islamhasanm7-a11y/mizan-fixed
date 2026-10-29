"""
MizanPro - Database Engine, Test Isolation & Sanitized Backup Management
النظام المالي المتكامل - ميزان برو
ملف إدارة الاتصال بقاعدة البيانات والجلسات مع عزل قواعد الاختبار المؤقتة وتطهير النسخ الاحتياطية من بيانات الدخول
"""

import os
import shutil
import sqlite3
import tempfile
from typing import Optional
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

# مسار قاعدة البيانات الأساسية للتطبيق (مع دعم العزل التام لبيئة الاختبارات عبر متغيرات البيئة)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PRODUCTION_DB_PATH = os.path.abspath(os.path.join(BASE_DIR, "mizanpro_ledger.db"))
ACTIVE_DB_PATH = os.path.abspath(os.environ.get("MIZANPRO_DB_PATH", PRODUCTION_DB_PATH))
DATABASE_URL = os.environ.get("MIZANPRO_DATABASE_URL", f"sqlite:///{ACTIVE_DB_PATH}")

# محرك قاعدة البيانات مع مهلة انتظار لمنع قفل القاعدة عند التزامن
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30},
    echo=False
)


def _configure_sqlite_connection(dbapi_connection, connection_record):
    """تفعيل المفاتيح الخارجية ومهلة القفل في كل اتصال بقاعدة بيانات SQLite"""
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys = ON;")
        cursor.execute("PRAGMA busy_timeout = 30000;")
        cursor.execute("PRAGMA synchronous = NORMAL;")
    finally:
        cursor.close()


event.listen(engine, "connect", _configure_sqlite_connection)

# مصنع الجلسات المحاسبية (Session Factory)
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# الفئة الأساسية لنماذج الجداول (Base Model)
Base = declarative_base()


def is_isolated_test_db(target_engine=None) -> bool:
    """التحقق الصارم من أن المحرك الحالي يعمل على قاعدة بيانات اختبار مؤقتة معزولة وليس قاعدة التطبيق الفعلية"""
    eng = target_engine or engine
    url_str = str(eng.url)
    if ":memory:" in url_str:
        return True
    db_file = eng.url.database
    if not db_file:
        return False
    return os.path.abspath(db_file) != PRODUCTION_DB_PATH


def create_sanitized_backup_bytes(source_db_path: Optional[str] = None) -> bytes:
    """
    إنشاء نسخة احتياطية مطهرة أمنياً (Sanitized Backup) من قاعدة البيانات
    بحيث يتم مسح كافة رموز الدخول السرية وتجزئاتها (pin_code) قبل التصدير أو الرفع لـ Google Drive
    لمنع تسريب بيانات الدخول إذا تمت مشاركة ملف الأرشيف.
    """
    src_path = os.path.abspath(source_db_path or ACTIVE_DB_PATH)
    if not os.path.exists(src_path):
        return b""

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_f:
        tmp_path = tmp_f.name

    try:
        src_conn = sqlite3.connect(src_path)
        dst_conn = sqlite3.connect(tmp_path)
        with dst_conn:
            src_conn.backup(dst_conn)
        src_conn.close()

        # تطهير جدول المستخدمين من أي رموز دخول أو تجزئات سرية داخل النسخة المصدرة
        cur = dst_conn.cursor()
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        if "app_users" in tables:
            cols = [r[1] for r in cur.execute("PRAGMA table_info(app_users)").fetchall()]
            if "must_change_pin" in cols:
                cur.execute("UPDATE app_users SET pin_code = 'REDACTED_IN_BACKUP', must_change_pin = 1")
            else:
                cur.execute("UPDATE app_users SET pin_code = 'REDACTED_IN_BACKUP'")
            dst_conn.commit()
        cur.execute("VACUUM")
        dst_conn.commit()
        dst_conn.close()

        with open(tmp_path, "rb") as f_out:
            return f_out.read()
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def get_db():
    """
    دالة مولدة (Generator) لإنشاء جلسة تعامل مع قاعدة البيانات
    وتضمن إغلاقها تلقائياً بعد انتهاء العملية لمنع تسريب الذاكرة (Connection Leaks).
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()