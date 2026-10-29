"""
MizanPro ERP - Explicit Environment Setup & Dependency Provisioning Script
خطوة تجهيز وتثبيت بيئة التشغيل المعتمدة (منفصلة عن وقت تشغيل التطبيق)
Usage:
    python3 setup_env.py [--use-lock]
"""

import os
import subprocess
import sys


REQUIRED_MODULES = ("streamlit", "pandas", "plotly", "sqlalchemy", "openpyxl")


def check_installed_dependencies() -> list[str]:
    """التحقق من وجود كافة الحزم الأساسية في بيئة بايثون الحالية"""
    missing = []
    for mod in REQUIRED_MODULES:
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    return missing


def provision_environment(use_lock: bool = True) -> int:
    """تثبيت الاعتماديات المثبتة من ملف القفل (requirements.lock) أو (requirements.txt)"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    req_file = os.path.join(base_dir, "requirements.lock" if use_lock else "requirements.txt")
    if not os.path.exists(req_file):
        req_file = os.path.join(base_dir, "requirements.txt")

    print(f"📦 جاري تجهيز بيئة التشغيل من الملف المعتمد: {os.path.basename(req_file)} ...")
    cmd = [sys.executable, "-m", "pip", "install", "--no-input", "-r", req_file]
    res = subprocess.run(cmd, check=False)
    if res.returncode != 0:
        print("❌ فشل تثبيت الاعتماديات عبر pip.", file=sys.stderr)
        return res.returncode

    missing = check_installed_dependencies()
    if missing:
        print(f"❌ لا تزال بعض الحزم غير متوفرة بعد التثبيت: {missing}", file=sys.stderr)
        return 1

    print("✅ تم تجهيز بيئة التشغيل وتثبيت كافة الاعتماديات المثبتة بنجاح.")
    return 0


if __name__ == "__main__":
    use_lock_flag = "--no-lock" not in sys.argv
    sys.exit(provision_environment(use_lock=use_lock_flag))
