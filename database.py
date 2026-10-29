"""
MizanPro - Database Engine & Session Management
النظام المالي المتكامل - ميزان برو
ملف إدارة الاتصال بقاعدة البيانات والجلسات مع تفعيل قيود التكامل المرجعي ومهلة الانتظار للتزامن الآمن
"""

import os
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

# مسار قاعدة البيانات المحلية SQLite
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'mizanpro_ledger.db')}"

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