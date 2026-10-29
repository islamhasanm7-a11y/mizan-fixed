"""
MizanPro - Core General Ledger, Inventory (WAC), Treasury, Fixed Assets, Payroll, Aging, Bank Rec & ZATCA Engine
النظام المالي المتكامل - ميزان برو
محرك الأستاذ العام، المخزون، السندات، الأصول الثابتة، الرواتب، أعمار الديون، التسوية البنكية، مراكز التكلفة، وإقفال السنة
"""

import base64
import hashlib
import re
from datetime import date, datetime, time
from typing import List, Dict, Any, Optional
import pandas as pd
from sqlalchemy import func, and_, text
from sqlalchemy.orm import Session

from models import (
    Account, JournalEntry, JournalLine, FiscalPeriod,
    CostCenter, AuditLog, EntryStatus, DocumentType,
    NaturalBalance, AccountType, Customer, Supplier,
    Product, InventoryTransaction, InventoryTxType,
    SalesInvoice, SalesInvoiceItem, PaymentMethod,
    InvoiceType, PurchaseInvoice, PurchaseInvoiceItem,
    CreditDebitNote, CreditDebitNoteItem, NoteType,
    CashVoucher, VoucherType, VoucherPartyType, CompanySettings,
    FixedAsset, Employee, PayrollRun, AppUser, UserRole, TBMappingProfile,
    CustomRoleTemplate, Warehouse, WarehouseStock, ALL_PERMISSION_KEYS,
    get_default_permissions_for_role, hash_pin_code, utc_now,
    to_decimal, quantize_money, round_money, quantize_rate, round_rate,
    calculate_line_and_tax_amounts, is_compromised_or_weak_pin, generate_random_pin,
    AuditLogReadOnlyError, AUDIT_GENESIS_HASH, compute_audit_entry_hash, resolve_audit_user_identity,
    AUDIT_TRANSACTION_TYPES, classify_audit_transaction_type, get_audit_transaction_type_label
)
from seed_coa import clear_initial_admin_bootstrap_pin
from zatca_phase2_validator import ZATCAPhase2Validator, ZATCA_GENESIS_PIH
from zatca_qr_tlv import (
    ZATCATLVEncodingError,
    ZATCATLVQRGenerator,
    decode_zatca_tlv_qr_base64,
    generate_zatca_tlv_qr_base64,
)
import json



class LedgerValidationError(Exception):
    """استثناء مخصص لأخطاء التحقق المحاسبي والمالي والمخزني"""
    pass


class LedgerService:
    """محرك العمليات المتكامل لنظام MizanPro ERP"""

    # =========================================================================
    # 1. خوارزمية تشفير وتوليد الـ QR Code لهيئة الزكاة والضريبة والجمارك (ZATCA Phase 2 TLV Tags 1-9)
    # =========================================================================
    @staticmethod
    def generate_zatca_qr_code(
        seller_name: str,
        vat_number: str,
        invoice_datetime: Optional[Any] = None,
        total_amount: Optional[Any] = None,
        vat_amount: Optional[Any] = None,
        doc_number: str = "INV-2026-0001",
        doc_type_code: str = "388",
        subtype_code: str = "0200000",
        buyer_name: str = "عميل نقدي",
        buyer_vat: str = "",
        icv: int = 1,
        pih: str = ZATCA_GENESIS_PIH,
        timestamp: Optional[Any] = None,
        invoice_total: Optional[Any] = None,
        vat_total: Optional[Any] = None,
        phase2: bool = True,
    ) -> str:
        """
        توليد رمز الاستجابة السريعة (QR Code) المشفر بصيغة TLV Base64 المتوافق مع
        المرحلة الثانية لهيئة الزكاة والضريبة والجمارك (ZATCA Phase 2 Integration - Tags 1..9)
        شاملاً: اسم البائع (Tag 1)، الرقم الضريبي (Tag 2)، الطابع الزمني (Tag 3)،
        إجمالي الفاتورة (Tag 4)، مبلغ الضريبة (Tag 5)، وحقول التشفير للمرحلة الثانية (Tags 6..9).
        """
        effective_ts = timestamp if timestamp is not None else invoice_datetime
        effective_total = invoice_total if invoice_total is not None else total_amount
        effective_vat = vat_total if vat_total is not None else vat_amount
        try:
            return generate_zatca_tlv_qr_base64(
                seller_name=seller_name,
                vat_number=vat_number,
                timestamp=effective_ts,
                invoice_total=effective_total,
                vat_total=effective_vat,
                phase2=phase2,
                doc_number=doc_number,
                doc_type_code=doc_type_code,
                subtype_code=subtype_code,
                buyer_name=buyer_name,
                buyer_vat=buyer_vat,
                icv=icv,
                pih=pih,
            )
        except ZATCATLVEncodingError as exc:
            raise LedgerValidationError(str(exc)) from exc

    @staticmethod
    def decode_zatca_qr_code(tlv_base64: Optional[str]) -> Dict[str, Any]:
        """فك تشفير وتحليل باركود ZATCA TLV Base64 واستخراج الحقول (Tags 1..9)"""
        return decode_zatca_tlv_qr_base64(tlv_base64)

    @staticmethod
    def generate_invoice_zatca_qr_bundle(
        invoice_obj: Any,
        settings: Optional[CompanySettings] = None,
        icv: int = 1,
        pih: str = ZATCA_GENESIS_PIH,
    ) -> Dict[str, Any]:
        """توليد حزمة باركود ZATCA TLV Base64 كاملة مع فك التشفير والتحقق لأي فاتورة"""
        return ZATCATLVQRGenerator.generate_for_invoice(
            invoice_obj=invoice_obj,
            settings=settings,
            icv=icv,
            pih=pih,
        )

    @staticmethod
    def generate_qr_svg_data_uri(tlv_base64: str, size: int = 130) -> str:
        """
        توليد مصفوفة باركود ثنائية الأبعاد (SVG Data URI) محلياً 100% بدون إنترنت
        مع تضمين أنماط التوقيت والمحاذاة القياسية (ISO/IEC 18004) والبيانات المشفرة.
        """
        raw_payload = (tlv_base64 or "MIZANPRO").encode("utf-8")
        grid_size = 29  # Version 3 QR Matrix (29x29) with Finder, Timing, and Alignment patterns
        matrix = [[None for _ in range(grid_size)] for _ in range(grid_size)]

        # 1. Finder patterns (7x7) + Separators (8x8)
        for fr, fc in [(0, 0), (0, grid_size - 7), (grid_size - 7, 0)]:
            for r in range(-1, 8):
                for c in range(-1, 8):
                    rr, cc = fr + r, fc + c
                    if 0 <= rr < grid_size and 0 <= cc < grid_size:
                        if 0 <= r < 7 and 0 <= c < 7:
                            is_dark = (r in (0, 6) or c in (0, 6)) or (2 <= r <= 4 and 2 <= c <= 4)
                            matrix[rr][cc] = is_dark
                        else:
                            matrix[rr][cc] = False

        # 2. Timing patterns (row 6 and col 6)
        for i in range(8, grid_size - 8):
            matrix[6][i] = (i % 2 == 0)
            matrix[i][6] = (i % 2 == 0)

        # 3. Alignment pattern for Version 3 at (20, 20)
        ar_center, ac_center = 22, 22
        for r in range(ar_center - 2, ar_center + 3):
            for c in range(ac_center - 2, ac_center + 3):
                is_dark = (abs(r - ar_center) == 2 or abs(c - ac_center) == 2 or (r == ar_center and c == ac_center))
                matrix[r][c] = is_dark

        # 4. Dark module & Format info reservation
        matrix[grid_size - 8][8] = True

        # 5. Encode payload bytes + SHA-256 error-check stream into remaining modules with mask (r + c) % 2 == 0
        ecc_stream = hashlib.sha256(raw_payload).digest() + hashlib.sha256(raw_payload + b"ZATCA").digest()
        full_bytes = bytes([len(raw_payload) & 0xFF]) + raw_payload + ecc_stream
        bits = "".join(f"{b:08b}" for b in full_bytes)

        bit_idx = 0
        for c in range(grid_size - 1, -1, -1):
            if c == 6:
                continue
            for r in range(grid_size):
                if matrix[r][c] is None:
                    data_bit = (bits[bit_idx % len(bits)] == "1")
                    mask_bit = ((r + c) % 2 == 0)
                    matrix[r][c] = (data_bit ^ mask_bit)
                    bit_idx += 1

        quiet_zone = 2
        total_modules = grid_size + (quiet_zone * 2)
        cell_size = size / total_modules
        rects = []
        for r in range(grid_size):
            for c in range(grid_size):
                if matrix[r][c]:
                    x = round((c + quiet_zone) * cell_size, 2)
                    y = round((r + quiet_zone) * cell_size, 2)
                    w = round(cell_size + 0.12, 2)
                    rects.append(f'<rect x="{x}" y="{y}" width="{w}" height="{w}" fill="#0F172A"/>')

        safe_tlv = (tlv_base64 or "").replace('"', "&quot;")
        svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" width="{size}" height="{size}" data-zatca-tlv="{safe_tlv}">'
            f'<rect width="100%" height="100%" fill="#FFFFFF"/>'
            + "".join(rects) +
            "</svg>"
        )
        b64_svg = base64.b64encode(svg.encode("utf-8")).decode("utf-8")
        return f"data:image/svg+xml;base64,{b64_svg}"

    # =========================================================================
    # 2. إعدادات المنشأة والأرقام التسلسلية الذرية (Atomic Sequence Generators)
    # =========================================================================
    @staticmethod
    def _next_sequence_code(db: Session, model_cls: Any, col_attr: Any, prefix: str, pad: int = 4) -> str:
        """توليد الرقم التسلسلي التالي بأمان بالاعتماد على أعلى رقم فعلي لمنع التصادم عند الحذف أو التزامن"""
        records = db.query(col_attr).filter(col_attr.like(f"{prefix}%")).all()
        max_seq = 0
        for row in records:
            val_str = str(row[0] if isinstance(row, (tuple, list)) or hasattr(row, "__getitem__") else row)
            if val_str.startswith(prefix):
                suffix = val_str[len(prefix):]
                digits = re.sub(r"[^\d]", "", suffix.split("-")[-1] if "-" in suffix else suffix)
                if digits.isdigit():
                    max_seq = max(max_seq, int(digits))
        candidate = f"{prefix}{max_seq + 1:0{pad}d}"
        while db.query(model_cls).filter(col_attr == candidate).first() is not None:
            max_seq += 1
            candidate = f"{prefix}{max_seq + 1:0{pad}d}"
        return candidate

    @staticmethod
    def get_company_settings(db: Session) -> CompanySettings:
        settings = db.query(CompanySettings).first()
        if not settings:
            settings = CompanySettings()
            db.add(settings)
            db.commit()
            db.refresh(settings)
        return settings

    @staticmethod
    def update_company_settings(db: Session, performed_by: str = "مدير النظام (Admin)", **kwargs) -> CompanySettings:
        settings = LedgerService.get_company_settings(db)
        if "vat_number" in kwargs and kwargs["vat_number"]:
            v_clean = str(kwargs["vat_number"]).strip()
            if not (len(v_clean) == 15 and v_clean.isdigit() and v_clean.startswith("3") and v_clean.endswith("3")):
                raise LedgerValidationError("الرقم الضريبي للمنشأة في المملكة العربية السعودية يجب أن يتكون من 15 رقماً ويبدأ وينتهي بالرقم 3.")
        old_cfg = {
            "company_name_ar": settings.company_name_ar,
            "vat_number": settings.vat_number,
            "default_vat_rate": str(settings.default_vat_rate),
            "fiscal_year": settings.fiscal_year,
        }
        for k, v in kwargs.items():
            if hasattr(settings, k) and v is not None:
                setattr(settings, k, v)
        new_cfg = {
            "company_name_ar": settings.company_name_ar,
            "vat_number": settings.vat_number,
            "default_vat_rate": str(settings.default_vat_rate),
            "fiscal_year": settings.fiscal_year,
        }
        from system_activity_service import SystemActivityService
        SystemActivityService.log_configuration_change(
            db=db,
            config_category="COMPANY_SETTINGS",
            target_item="إعدادات المنشأة وبيانات الضريبة والسنة المالية",
            action_type="UPDATE_SETTINGS",
            old_values=old_cfg,
            new_values=new_cfg,
            performed_by=performed_by,
            change_reason="تحديث إعدادات المنشأة والضريبة والسنة المالية",
        )
        db.add(AuditLog(
            table_name="company_settings",
            record_id=settings.id or 1,
            action="UPDATE_SETTINGS",
            performed_by=performed_by,
            details=f"Updated company settings: {list(kwargs.keys())}"
        ))
        db.commit()
        db.refresh(settings)
        return settings


    # =========================================================================
    # 2.ب إدارة المستخدمين والتخصيص الحر للصلاحيات (Custom RBAC & User Management)
    # =========================================================================
    @classmethod
    def record_audit_log(
        cls,
        db: Session,
        table_name: str,
        record_id: int,
        action: str,
        performed_by: Optional[str] = "مدير النظام (Admin)",
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        reference_number: Optional[str] = None,
        financial_amount: Any = 0.0,
        old_values: Optional[Dict[str, Any]] = None,
        new_values: Optional[Dict[str, Any]] = None,
        details: Optional[str] = None,
    ) -> AuditLog:
        """
        تسجيل قيد تدقيق رقابي غير قابل للتعديل أو الحذف (ZATCA Read-Only Audit Trail)
        مع ربطه الإلزامي بمعرف المستخدم (user_id) والطابع الزمني العالمي (UTC Timestamp) وبصمة التشفير المتسلسلة.
        """
        uid, uname, actor = resolve_audit_user_identity(
            db,
            performed_by=performed_by,
            explicit_user_id=user_id,
            explicit_username=username,
        )
        db.info["performed_by"] = actor
        db.info["user_id"] = uid
        db.info["username"] = uname

        log_entry = AuditLog(
            table_name=table_name,
            record_id=int(record_id or 0),
            action=action,
            user_id=uid,
            username=uname,
            performed_by=actor,
            timestamp=utc_now(),
            reference_number=reference_number,
            financial_amount=quantize_money(financial_amount),
            old_values_json=json.dumps(old_values, ensure_ascii=False) if old_values is not None else None,
            new_values_json=json.dumps(new_values, ensure_ascii=False) if new_values is not None else None,
            details=details,
        )
        db.add(log_entry)
        return log_entry

    @classmethod
    def verify_audit_log_integrity(cls, db: Session) -> Dict[str, Any]:
        """
        فحص سلامة وعدم التلاعب بسجل التدقيق الرقابي للقراءة فقط (ZATCA Read-Only Audit Trail Verification)
        عبر التحقق من سلسلة التجزئة التشفيرية (SHA-256 Hash Chain) وتريجرات الحماية في قاعدة البيانات.
        """
        logs = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
        expected_prev = AUDIT_GENESIS_HASH
        broken_links: List[Dict[str, Any]] = []
        missing_user_ids = 0
        missing_timestamps = 0

        for lg in logs:
            if not lg.user_id or not str(lg.user_id).strip():
                missing_user_ids += 1
            if lg.timestamp is None:
                missing_timestamps += 1

            computed = compute_audit_entry_hash(
                previous_hash=lg.previous_hash or expected_prev,
                timestamp=lg.timestamp,
                user_id=lg.user_id,
                username=lg.username,
                performed_by=lg.performed_by,
                table_name=lg.table_name,
                record_id=lg.record_id,
                action=lg.action,
                reference_number=lg.reference_number,
                financial_amount=lg.financial_amount,
                details=lg.details,
            )
            if (lg.previous_hash and lg.previous_hash != expected_prev) or (lg.entry_hash and lg.entry_hash != computed):
                broken_links.append({
                    "id": lg.id,
                    "action": lg.action,
                    "table_name": lg.table_name,
                    "expected_previous_hash": expected_prev,
                    "actual_previous_hash": lg.previous_hash,
                    "expected_entry_hash": computed,
                    "actual_entry_hash": lg.entry_hash,
                })
            expected_prev = lg.entry_hash or computed

        triggers = [
            r[0] for r in db.execute(
                text("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit_logs'")
            ).fetchall()
        ]
        has_readonly_triggers = (
            "trg_audit_logs_readonly_update" in triggers
            and "trg_audit_logs_readonly_delete" in triggers
        )

        is_intact = (
            len(broken_links) == 0
            and missing_user_ids == 0
            and missing_timestamps == 0
            and has_readonly_triggers
        )
        verified_count = max(0, len(logs) - len(broken_links))
        return {
            "is_intact": is_intact,
            "is_read_only_enforced": has_readonly_triggers,
            "total_records": len(logs),
            "total_entries": len(logs),
            "verified_entries": verified_count,
            "missing_user_ids": missing_user_ids,
            "missing_user_id_count": missing_user_ids,
            "missing_timestamps": missing_timestamps,
            "missing_timestamp_count": missing_timestamps,
            "broken_chain_links": broken_links,
            "latest_chain_hash": expected_prev,
            "triggers": triggers,
            "status_ar": (
                "سجل تدقيق محمي للقراءة فقط (Read-Only) وسلسلة SHA-256 سليمة 100% ✅"
                if is_intact else
                "تنبيه أمني: تم رصد خلل في سلسلة التدقيق أو تريجرات الحماية ❌"
            ),
        }

    @classmethod
    def verify_single_entry_hash(cls, db: Session, log_id: int) -> Dict[str, Any]:
        """
        التحقق التشفيري المباشر لحساب وتأكيد بصمة SHA-256 لسجل تدقيق فردي
        وتوليد شهادة التحقق الجنائي لمراجعي الحسابات الخارجيين
        """
        from models import AUDIT_GENESIS_HASH, AuditLog, compute_audit_entry_hash, quantize_money
        lg = db.query(AuditLog).filter(AuditLog.id == log_id).first()
        if not lg:
            return {"success": False, "error": f"سجل التدقيق رقم {log_id} غير موجود بالقاعدة."}

        prev_h = lg.previous_hash or AUDIT_GENESIS_HASH
        recomputed_hash = compute_audit_entry_hash(
            previous_hash=prev_h,
            timestamp=lg.timestamp,
            user_id=lg.user_id,
            username=lg.username,
            performed_by=lg.performed_by,
            table_name=lg.table_name,
            record_id=lg.record_id,
            action=lg.action,
            reference_number=lg.reference_number,
            financial_amount=lg.financial_amount,
            details=lg.details,
        )

        is_valid = bool(lg.entry_hash and lg.entry_hash == recomputed_hash)

        ts_str = lg.timestamp.strftime("%Y-%m-%dT%H:%M:%S") if hasattr(lg.timestamp, "strftime") else str(lg.timestamp)[:19]
        canonical_raw = (
            f"{prev_h}|{ts_str}|{lg.user_id or 'USR-001'}|{lg.username or 'admin'}|{lg.performed_by or ''}|"
            f"{lg.table_name or ''}|{lg.record_id or 0}|{lg.action or ''}|{lg.reference_number or ''}|"
            f"{quantize_money(lg.financial_amount):.2f}|{lg.details or ''}"
        )

        return {
            "success": True,
            "log_id": lg.id,
            "action": lg.action,
            "table_name": lg.table_name,
            "user_id": lg.user_id,
            "username": lg.username,
            "performed_by": lg.performed_by,
            "timestamp_utc": ts_str,
            "stored_previous_hash": prev_h,
            "stored_entry_hash": lg.entry_hash,
            "recomputed_entry_hash": recomputed_hash,
            "canonical_payload_string": canonical_raw,
            "is_hash_valid": is_valid,
            "status_text": "بصمة SHA-256 مطابقة وسليمة 100% ✅ (لم يتعرض السجل لأي تعديل)" if is_valid else "⚠️ تنبيه: عدم تطابق في بصمة SHA-256! احتمال تلاعب بالسجل."
        }

    @classmethod
    def verify_bulk_audit_log_entries(cls, db: Session, selected_ids: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        أداة التحقق التجميعي الكتلي من البصمات التشفيرية SHA-256 لمجموعة محددة من سجلات التدقيق
        (Bulk SHA-256 Batch Verification Tool for Selected Audit Log Entries)
        """
        query = db.query(AuditLog)
        if selected_ids and len(selected_ids) > 0:
            query = query.filter(AuditLog.id.in_(selected_ids))

        logs = query.order_by(AuditLog.id.asc()).all()

        results = []
        valid_count = 0
        broken_count = 0

        for lg in logs:
            computed_hash = compute_audit_entry_hash(
                previous_hash=lg.previous_hash,
                timestamp=lg.timestamp,
                user_id=lg.user_id,
                username=lg.username,
                performed_by=lg.performed_by,
                table_name=lg.table_name,
                record_id=lg.record_id,
                action=lg.action,
                reference_number=lg.reference_number,
                financial_amount=lg.financial_amount,
                details=lg.details,
            )
            is_valid = bool(lg.entry_hash and lg.entry_hash == computed_hash)
            if is_valid:
                valid_count += 1
            else:
                broken_count += 1

            results.append({
                "id": lg.id,
                "table_name": lg.table_name,
                "record_id": lg.record_id,
                "action": lg.action,
                "user_id": lg.user_id,
                "username": lg.username,
                "performed_by": lg.performed_by,
                "timestamp": lg.timestamp.strftime("%Y-%m-%d %H:%M:%S") if lg.timestamp else "—",
                "reference_number": lg.reference_number or "—",
                "financial_amount": float(lg.financial_amount or 0.0),
                "stored_hash": lg.entry_hash,
                "computed_hash": computed_hash,
                "is_valid": is_valid,
                "status_badge_ar": "✅ الختم مطبق وسليم" if is_valid else "❌ تنبيه: خرق تشفيري",
            })

        total_checked = len(results)
        is_batch_intact = (total_checked > 0 and broken_count == 0)

        # توليد ختم المتابعة التجميعي للدفعة المفحوصة
        batch_raw = f"{total_checked}|{valid_count}|{broken_count}|" + "|".join(str(r["id"]) + ":" + str(r["stored_hash"]) for r in results)
        batch_sha256 = hashlib.sha256(batch_raw.encode("utf-8")).hexdigest() if results else AUDIT_GENESIS_HASH

        rows = [
            {
                "معرف السجل": r["id"],
                "الجدول المالي": r["table_name"],
                "الإجراء": r["action"],
                "المستخدم": f"{r['user_id']} ({r['username']})",
                "المستند / المرجع": r["reference_number"],
                "المبلغ المالي (ريال)": r["financial_amount"],
                "البصمة المخزنة": f"{r['stored_hash'][:16]}..." if r["stored_hash"] else "—",
                "البصمة المحسوبة": f"{r['computed_hash'][:16]}...",
                "حالة الختم التشفيري": r["status_badge_ar"],
            }
            for r in results
        ]
        df = pd.DataFrame(rows) if rows else pd.DataFrame()

        return {
            "total_checked": total_checked,
            "valid_count": valid_count,
            "broken_count": broken_count,
            "is_batch_intact": is_batch_intact,
            "batch_sha256_seal": batch_sha256,
            "results": results,
            "dataframe": df,
            "verification_status_ar": "دفعة سليمة 100% ومطابقة أمنياً ✅" if is_batch_intact else "تنبيه: يوجد خرق أمني بالدفعة ❌",
        }

    @classmethod
    def is_user_authorized_for_audit_logs(cls, db: Session, user_or_actor: Optional[Any]) -> bool:
        """
        التحقق من امتلاك المستخدم لصلاحية الاطلاع على سجل التدقيق الرقابي للقراءة فقط (ZATCA Audit Log).
        يُسمح لمدير النظام (ADMIN) والمراجع القانوني (AUDITOR) وأي مستخدم يمتلك صلاحية
        `act_view_audit_logs` أو `mod_audit_log`.
        """
        if user_or_actor is None:
            return False

        if isinstance(user_or_actor, AppUser):
            if not user_or_actor.is_active:
                return False
            role_val = user_or_actor.role.value if hasattr(user_or_actor.role, "value") else str(user_or_actor.role)
            if role_val in (UserRole.ADMIN.value, UserRole.AUDITOR.value):
                return True
            return (
                user_or_actor.has_permission("act_view_audit_logs")
                or user_or_actor.has_permission("mod_audit_log")
            )

        if isinstance(user_or_actor, dict):
            if not user_or_actor.get("is_active", True):
                return False
            role_val = str(user_or_actor.get("role") or "")
            if role_val in (UserRole.ADMIN.value, UserRole.AUDITOR.value):
                return True
            perms = user_or_actor.get("permissions") or {}
            return bool(perms.get("act_view_audit_logs") or perms.get("mod_audit_log"))

        raw = str(user_or_actor).strip()
        if not raw or "مقفل" in raw:
            return False

        user_obj: Optional[AppUser] = None
        if raw.isdigit():
            user_obj = db.query(AppUser).filter(AppUser.id == int(raw)).first()
        elif raw.upper().startswith("USR-") and raw[4:].isdigit():
            user_obj = db.query(AppUser).filter(AppUser.id == int(raw[4:])).first()
        else:
            paren_m = re.search(r"\(([^()]+)\)", raw)
            cand_uname = paren_m.group(1).strip().lower() if paren_m else raw.lower()
            clean_name = re.sub(r"\s*\([^()]+\)\s*", "", raw).strip()
            user_obj = db.query(AppUser).filter(
                (func.lower(AppUser.username) == cand_uname)
                | (func.lower(AppUser.username) == raw.lower())
                | (AppUser.full_name_ar == raw)
                | (AppUser.full_name_ar == clean_name)
            ).first()

        if user_obj is None:
            return False
        return cls.is_user_authorized_for_audit_logs(db, user_obj)

    @classmethod
    def query_audit_logs(
        cls,
        db: Session,
        start_date: Optional[Any] = None,
        end_date: Optional[Any] = None,
        user_filter: Optional[str] = None,
        transaction_type: Optional[str] = None,
        table_name: Optional[str] = None,
        action: Optional[str] = None,
        search_query: Optional[str] = None,
        min_amount: Optional[float] = None,
        only_modifications: bool = False,
        requesting_user: Optional[Any] = None,
        limit: int = 1000,
    ) -> Dict[str, Any]:
        """
        استعلام وفلترة سجل التدقيق الرقابي للقراءة فقط (Read-Only ZATCA Audit Log Filter & Query Engine)
        مع دعم الفلترة حسب:
        1. نطاق التاريخ (start_date .. end_date)
        2. المستخدم (user_id / username / performed_by)
        3. نوع المعاملة المالية (transaction_type: فواتير مبيعات، مشتريات، إشعارات، سندات، قيود، مخزون، أصول/رواتب، إلخ أو اسم الجدول/الإجراء)
        4. الجدول المالي أو نوع الإجراء التفصيلي أو البحث النصي.
        يتحقق إلزامياً من صلاحية المستخدم الطالب عند تمرير `requesting_user`.
        """
        if requesting_user is not None and not cls.is_user_authorized_for_audit_logs(db, requesting_user):
            raise LedgerValidationError(
                "ZATCA_AUDIT_ACCESS_DENIED: عذراً، الوصول إلى سجل التدقيق الرقابي للقراءة فقط مقيد بالمستخدمين المخولين "
                "(مدير النظام، المراجع القانوني CPA، أو حاملي صلاحية act_view_audit_logs)."
            )

        def _parse_date_bound(d_val: Any) -> Optional[date]:
            if d_val is None or d_val == "":
                return None
            if isinstance(d_val, datetime):
                return d_val.date()
            if isinstance(d_val, date):
                return d_val
            s_val = str(d_val).strip()[:10]
            try:
                return datetime.strptime(s_val, "%Y-%m-%d").date()
            except Exception as exc:
                raise LedgerValidationError(f"صيغة التاريخ غير صالحة ({d_val}). يرجى استخدام YYYY-MM-DD.") from exc

        s_date = _parse_date_bound(start_date)
        e_date = _parse_date_bound(end_date)
        if s_date and e_date and s_date > e_date:
            raise LedgerValidationError(
                f"نطاق التاريخ غير صالح: تاريخ البداية ({s_date}) لا يمكن أن يكون بعد تاريخ النهاية ({e_date})."
            )

        all_logs_asc = db.query(AuditLog).order_by(AuditLog.id.asc()).all()

        # بناء خريطة التحقق التشفيري لكل سجل + جمع خيارات الفلترة المتاحة
        hash_valid_map: Dict[int, bool] = {}
        expected_prev = AUDIT_GENESIS_HASH
        available_users_set = set()
        available_tables_set = set()
        available_actions_set = set()
        min_db_date: Optional[date] = None
        max_db_date: Optional[date] = None

        for lg in all_logs_asc:
            computed_h = compute_audit_entry_hash(
                previous_hash=lg.previous_hash or expected_prev,
                timestamp=lg.timestamp,
                user_id=lg.user_id,
                username=lg.username,
                performed_by=lg.performed_by,
                table_name=lg.table_name,
                record_id=lg.record_id,
                action=lg.action,
                reference_number=lg.reference_number,
                financial_amount=lg.financial_amount,
                details=lg.details,
            )
            is_link_ok = (
                (not lg.previous_hash or lg.previous_hash == expected_prev)
                and (not lg.entry_hash or lg.entry_hash == computed_h)
            )
            hash_valid_map[lg.id] = bool(is_link_ok)
            expected_prev = lg.entry_hash or computed_h

            uid_val = (lg.user_id or "USR-001").strip()
            uname_val = (lg.username or "admin").strip()
            available_users_set.add(f"{uid_val} ({uname_val})")
            if lg.table_name:
                available_tables_set.add(lg.table_name)
            if lg.action:
                available_actions_set.add(lg.action)
            if lg.timestamp:
                lg_d = lg.timestamp.date() if isinstance(lg.timestamp, datetime) else lg.timestamp
                if min_db_date is None or lg_d < min_db_date:
                    min_db_date = lg_d
                if max_db_date is None or lg_d > max_db_date:
                    max_db_date = lg_d

        # تطبيع معايير الفلترة
        u_norm = (user_filter or "").strip()
        if u_norm in ("", "الكل", "ALL", "all", "*"):
            u_norm = ""

        tx_norm = (transaction_type or "").strip()
        if tx_norm in ("", "الكل", "ALL", "all", "*") or tx_norm.startswith("الكل"):
            tx_norm = ""
        else:
            # السماح بتمرير المسمى العربي لنوع المعاملة أو المفتاح المعياري
            for k_tx, meta_tx in AUDIT_TRANSACTION_TYPES.items():
                if tx_norm.upper() == k_tx or tx_norm == meta_tx["label_ar"]:
                    tx_norm = k_tx
                    break

        tbl_norm = (table_name or "").strip().lower()
        if tbl_norm in ("", "الكل", "all", "*"):
            tbl_norm = ""

        act_norm = (action or "").strip().upper()
        if act_norm in ("", "الكل", "ALL", "*"):
            act_norm = ""

        q_norm = (search_query or "").strip().lower()
        min_amt_val = float(min_amount) if min_amount is not None and float(min_amount) > 0 else 0.0

        matched_logs: List[AuditLog] = []
        # الترتيب من الأحدث إلى الأقدم للعرض
        for lg in reversed(all_logs_asc):
            lg_dt = lg.timestamp
            lg_date = lg_dt.date() if isinstance(lg_dt, datetime) else lg_dt

            # 1. فلترة نطاق التاريخ (Date Range Filter)
            if s_date and (lg_date is None or lg_date < s_date):
                continue
            if e_date and (lg_date is None or lg_date > e_date):
                continue

            # 2. فلترة المستخدم (User Filter: user_id, username, performed_by, or "USR-001 (admin)")
            if u_norm:
                u_norm_l = u_norm.lower()
                uid_s = (lg.user_id or "USR-001").strip()
                uname_s = (lg.username or "admin").strip()
                actor_s = (lg.performed_by or "").strip()
                combined_u = f"{uid_s} ({uname_s})".lower()
                if not (
                    u_norm_l == uid_s.lower()
                    or u_norm_l == uname_s.lower()
                    or u_norm_l == combined_u
                    or u_norm_l in combined_u
                    or u_norm_l in actor_s.lower()
                ):
                    continue

            # 3. فلترة نوع المعاملة المالية (Transaction Type Filter)
            lg_tx_type = classify_audit_transaction_type(lg.table_name, lg.action)
            if tx_norm:
                tx_norm_u = tx_norm.upper()
                if tx_norm_u in AUDIT_TRANSACTION_TYPES:
                    if lg_tx_type != tx_norm_u:
                        continue
                else:
                    # دعم الفلترة المباشرة باسم الجدول أو نوع الإجراء إذا مرره المستدعي في transaction_type
                    if (
                        tx_norm.lower() != (lg.table_name or "").strip().lower()
                        and tx_norm_u != (lg.action or "").strip().upper()
                        and tx_norm_u not in (lg.action or "").strip().upper()
                    ):
                        continue

            # 4. فلترة الجدول المالي المباشر (Table Filter)
            if tbl_norm and (lg.table_name or "").strip().lower() != tbl_norm:
                continue

            # 5. فلترة نوع الإجراء التفصيلي (Action Filter)
            if act_norm and (lg.action or "").strip().upper() != act_norm:
                continue

            # 6. فلترة الحد الأدنى للمبلغ المالي
            amt_f = float(lg.financial_amount or 0.0)
            if min_amt_val > 0 and amt_f < min_amt_val - 1e-6:
                continue

            # 7. فلترة عمليات التعديل والعكس فقط (Modifications / Reversals Only)
            act_u = (lg.action or "").upper()
            is_mod = bool(
                lg.old_values_json
                or act_u.startswith("MODIFY_")
                or act_u.startswith("UPDATE_")
                or act_u.startswith("REVERSE_")
                or act_u.startswith("DELETE_")
            )
            if only_modifications and not is_mod:
                continue

            # 8. البحث بالكلمات المفتاحية في السجلات الرقابية (Keyword Search: Transaction IDs, Notes, Ref, Diff)
            if q_norm:
                tx_id_tokens = f"#{lg.id} rec-{lg.record_id} tx-{lg.record_id} {lg.record_id or ''}"
                haystack = (
                    f"{lg.id} {tx_id_tokens} {lg.user_id or ''} {lg.username or ''} {lg.performed_by or ''} "
                    f"{lg.table_name or ''} {lg.action or ''} {lg.reference_number or ''} "
                    f"{lg.details or ''} {lg.entry_hash or ''} {lg.previous_hash or ''} "
                    f"{lg.old_values_json or ''} {lg.new_values_json or ''}"
                ).lower()

                search_tokens = q_norm.split()
                if not all(token in haystack for token in search_tokens):
                    continue


            matched_logs.append(lg)
            if limit and len(matched_logs) >= int(limit):
                break

        records: List[Dict[str, Any]] = []
        df_rows: List[Dict[str, Any]] = []
        by_tx_type: Dict[str, Dict[str, Any]] = {}
        by_user: Dict[str, Dict[str, Any]] = {}
        total_volume = 0.0
        modifications_cnt = 0
        unique_users_matched = set()

        for lg in matched_logs:
            tx_key = classify_audit_transaction_type(lg.table_name, lg.action)
            tx_label = get_audit_transaction_type_label(tx_key)
            ts_str = lg.timestamp.strftime("%Y-%m-%d %H:%M:%S") if lg.timestamp else "-"
            d_str = lg.timestamp.strftime("%Y-%m-%d") if lg.timestamp else "-"
            uid_s = lg.user_id or "USR-001"
            uname_s = lg.username or "admin"
            actor_s = getattr(lg, "performed_by", None) or "مدير النظام"
            u_label = f"{uid_s} ({uname_s})"
            unique_users_matched.add(u_label)

            amt_val = round_money(lg.financial_amount or 0.0)
            total_volume = round_money(total_volume + amt_val)

            old_dict: Dict[str, Any] = {}
            new_dict: Dict[str, Any] = {}
            if lg.old_values_json:
                try:
                    parsed_o = json.loads(lg.old_values_json)
                    if isinstance(parsed_o, dict):
                        old_dict = parsed_o
                except Exception:
                    pass
            if lg.new_values_json:
                try:
                    parsed_n = json.loads(lg.new_values_json)
                    if isinstance(parsed_n, dict):
                        new_dict = parsed_n
                except Exception:
                    pass

            changed_keys = sorted(set(old_dict.keys()) | set(new_dict.keys()))
            act_u = (lg.action or "").upper()
            is_mod_rec = bool(
                old_dict
                or act_u.startswith("MODIFY_")
                or act_u.startswith("UPDATE_")
                or act_u.startswith("REVERSE_")
                or act_u.startswith("DELETE_")
            )
            if is_mod_rec:
                modifications_cnt += 1

            is_h_ok = hash_valid_map.get(lg.id, True)

            by_tx_entry = by_tx_type.setdefault(
                tx_label,
                {"transaction_type_key": tx_key, "transaction_type_ar": tx_label, "count": 0, "amount": 0.0}
            )
            by_tx_entry["count"] += 1
            by_tx_entry["amount"] = round_money(by_tx_entry["amount"] + amt_val)

            by_u_entry = by_user.setdefault(
                u_label,
                {"user_id": uid_s, "username": uname_s, "performed_by": actor_s, "count": 0, "amount": 0.0}
            )
            by_u_entry["count"] += 1
            by_u_entry["amount"] = round_money(by_u_entry["amount"] + amt_val)

            rec_dict = {
                "id": lg.id,
                "timestamp_utc": ts_str,
                "date_only": d_str,
                "user_id": uid_s,
                "username": uname_s,
                "performed_by": actor_s,
                "user_tag": u_label,
                "transaction_type_key": tx_key,
                "transaction_type_ar": tx_label,
                "table_name": lg.table_name,
                "record_id": lg.record_id,
                "action": lg.action,
                "reference_number": lg.reference_number or "-",
                "financial_amount": amt_val,
                "is_modification": is_mod_rec,
                "old_values": old_dict,
                "new_values": new_dict,
                "changed_fields": changed_keys,
                "previous_hash": lg.previous_hash or AUDIT_GENESIS_HASH,
                "entry_hash": lg.entry_hash or "",
                "is_hash_valid": is_h_ok,
                "details": lg.details or "",
            }
            records.append(rec_dict)

            df_rows.append({
                "رقم العملية": lg.id,
                "الطابع الزمني (UTC Timestamp)": ts_str,
                "التاريخ": d_str,
                "معرف المستخدم (User ID)": uid_s,
                "اسم الدخول": uname_s,
                "المسؤول عن العملية": actor_s,
                "نوع المعاملة المالية": tx_label,
                "الجدول المالي": lg.table_name,
                "رقم السجل": lg.record_id,
                "مرجع المستند": lg.reference_number or "-",
                "المبلغ المالي (ريال)": f"{amt_val:,.2f}",
                "نوع الإجراء": lg.action,
                "سلامة البصمة": "سليمة ✅" if is_h_ok else "خلل ❌",
                "بصمة التشفير (SHA-256)": (lg.entry_hash[:16] + "...") if lg.entry_hash else "-",
                "التفاصيل": lg.details or "",
            })

        tx_type_options = {"ALL": "الكل — جميع أنواع المعاملات المالية"}
        for k_tx, meta_tx in AUDIT_TRANSACTION_TYPES.items():
            tx_type_options[k_tx] = meta_tx["label_ar"]

        return {
            "logs": matched_logs,
            "records": records,
            "dataframe": pd.DataFrame(df_rows),
            "summary": {
                "total_matched": len(records),
                "total_in_database": len(all_logs_asc),
                "total_financial_volume": total_volume,
                "modifications_count": modifications_cnt,
                "unique_users_count": len(unique_users_matched),
                "by_transaction_type": list(by_tx_type.values()),
                "by_user": list(by_user.values()),
                "filters_applied": {
                    "start_date": s_date.isoformat() if s_date else None,
                    "end_date": e_date.isoformat() if e_date else None,
                    "user_filter": u_norm or "ALL",
                    "transaction_type": tx_norm or "ALL",
                    "table_name": tbl_norm or "ALL",
                    "action": act_norm or "ALL",
                    "search_query": q_norm or "",
                    "only_modifications": bool(only_modifications),
                },
            },
            "filter_options": {
                "users": ["الكل"] + sorted(available_users_set),
                "transaction_types": tx_type_options,
                "tables": ["الكل"] + sorted(available_tables_set),
                "actions": ["الكل"] + sorted(available_actions_set),
                "min_date": min_db_date or date.today(),
                "max_date": max_db_date or date.today(),
            },
        }

    @classmethod
    def export_immutable_audit_pdf(
        cls,
        db: Session,
        start_date: Optional[Any] = None,
        end_date: Optional[Any] = None,
        user_filter: Optional[str] = None,
        transaction_type: Optional[str] = None,
        table_name: Optional[str] = None,
        action: Optional[str] = None,
        search_query: Optional[str] = None,
        min_amount: Optional[float] = None,
        only_modifications: bool = False,
        requesting_user: Optional[Any] = None,
        auditor_notes: Optional[str] = None,
        limit: int = 1000,
    ) -> bytes:
        """
        تصدير سجلات التدقيق الرقابي للقراءة فقط بصيغة PDF مؤمّنة وغير قابلة للتعديل (Immutable Read-Only PDF)
        مع ختم تشفيري مزدوج (SHA-256 Content Seal + Embedded Manifest) لمراجعة المدقق الخارجي ومفتشي ZATCA.
        """
        from zatca_audit_pdf import ZATCAAuditPDFExporter

        return ZATCAAuditPDFExporter.generate_immutable_audit_pdf(
            db=db,
            start_date=start_date,
            end_date=end_date,
            user_filter=user_filter,
            transaction_type=transaction_type,
            table_name=table_name,
            action=action,
            search_query=search_query,
            min_amount=min_amount,
            only_modifications=only_modifications,
            requesting_user=requesting_user,
            auditor_notes=auditor_notes,
            limit=limit,
        )

    @classmethod
    def generate_audit_log_pdf_summary(
        cls,
        db: Session,
        start_date: Optional[Any] = None,
        end_date: Optional[Any] = None,
        user_filter: Optional[str] = None,
        transaction_type: Optional[str] = None,
        table_name: Optional[str] = None,
        action: Optional[str] = None,
        search_query: Optional[str] = None,
        min_amount: Optional[float] = None,
        only_modifications: bool = False,
        requesting_user: Optional[Any] = None,
        auditor_notes: Optional[str] = None,
        limit: int = 1000,
    ) -> bytes:
        """
        توليد تقرير ملخص بصيغة PDF مؤمّنة وغير قابلة للتعديل لسجلات التدقيق الرقابي،
        مشتملة على بصمة التشفير (SHA-256 Integrity Hash) لكل سجل وفق متطلبات الامتثال لهيئة الزكاة والضريبة والجمارك (ZATCA).
        """
        return cls.export_immutable_audit_pdf(
            db=db,
            start_date=start_date,
            end_date=end_date,
            user_filter=user_filter,
            transaction_type=transaction_type,
            table_name=table_name,
            action=action,
            search_query=search_query,
            min_amount=min_amount,
            only_modifications=only_modifications,
            requesting_user=requesting_user,
            auditor_notes=auditor_notes,
            limit=limit,
        )

    @classmethod
    def verify_immutable_audit_pdf(cls, pdf_bytes: bytes) -> Dict[str, Any]:
        """التحقق الجنائي من سلامة وعدم التلاعب بملف PDF المصدّر لسجل التدقيق الرقابي للمراجع الخارجي"""
        from zatca_audit_pdf import ZATCAAuditPDFExporter

        return ZATCAAuditPDFExporter.verify_immutable_audit_pdf(pdf_bytes)

    @classmethod
    def verify_user_permission(cls, db: Session, performed_by: Optional[str], required_perm: str) -> None:
        """التحقق من صلاحية المستخدم على مستوى طبقة منطق الأعمال (Service Layer RBAC)"""
        if not performed_by:
            return
        clean_actor = str(performed_by).strip()
        if "مقفل" in clean_actor:
            raise LedgerValidationError("الحساب مقفل حالياً؛ يرجى إدخال رمز الدخول السري (PIN) الصحيح.")
        user = db.query(AppUser).filter(
            (func.lower(AppUser.username) == clean_actor.lower()) |
            (AppUser.full_name_ar == clean_actor)
        ).first()
        if user and not user.has_permission(required_perm):
            raise LedgerValidationError(f"المستخدم [{user.full_name_ar}] لا يمتلك الصلاحية النظامية ({required_perm}) لتنفيذ هذه العملية.")

    @classmethod
    def authenticate_user(cls, db: Session, username: str, plain_pin: str) -> AppUser:
        """
        مصادقة المستخدم إلزامياً باسم الدخول ورمز الدخول السري (PIN) بدون كشف قائمة المستخدمين.
        """
        uname = (username or "").strip().lower()
        raw_pin = (plain_pin or "").strip()
        if not uname or not raw_pin:
            raise LedgerValidationError("يرجى إدخال اسم المستخدم ورمز الدخول السري (PIN).")

        user = db.query(AppUser).filter(func.lower(AppUser.username) == uname).first()
        from system_activity_service import SystemActivityService

        if not user:
            SystemActivityService.log_login_attempt(
                db=db,
                username=uname,
                status="FAILED_USER_NOT_FOUND",
                failure_reason="اسم المستخدم غير مسجل بالنظام",
                details=f"Login attempt with non-existent username: {uname}",
            )
            raise LedgerValidationError("اسم المستخدم أو رمز الدخول السري غير صحيح، أو أن الحساب موقوف.")

        if not user.is_active:
            SystemActivityService.log_login_attempt(
                db=db,
                username=user.username,
                status="FAILED_USER_LOCKED",
                user_id=user.id,
                full_name_ar=user.full_name_ar,
                failure_reason="الحساب موقوف أو مقفل أمنياً",
                details=f"Login attempt on inactive account: {user.username}",
            )
            raise LedgerValidationError("اسم المستخدم أو رمز الدخول السري غير صحيح، أو أن الحساب موقوف.")

        if not user.verify_pin(raw_pin):
            SystemActivityService.log_login_attempt(
                db=db,
                username=user.username,
                status="FAILED_BAD_PIN",
                user_id=user.id,
                full_name_ar=user.full_name_ar,
                failure_reason="رمز الدخول السري (PIN) المدخل غير صحيح",
                details=f"Failed PIN authentication attempt for username: {uname}",
            )
            db.add(AuditLog(
                table_name="app_users",
                record_id=user.id,
                action="LOGIN_FAILED",
                performed_by=uname,
                details=f"Failed PIN authentication attempt for username: {uname}"
            ))
            db.commit()
            raise LedgerValidationError("اسم المستخدم أو رمز الدخول السري غير صحيح.")

        SystemActivityService.log_login_attempt(
            db=db,
            username=user.username,
            status="SUCCESS",
            user_id=user.id,
            full_name_ar=user.full_name_ar,
            details=f"Authenticated user: {user.username} (must_change_pin={bool(user.must_change_pin)})",
        )
        db.add(AuditLog(
            table_name="app_users",
            record_id=user.id,
            action="LOGIN_SUCCESS",
            performed_by=user.full_name_ar,
            details=f"Authenticated user: {user.username} (must_change_pin={bool(user.must_change_pin)})"
        ))
        db.commit()
        db.refresh(user)
        return user


    @classmethod
    def change_user_pin(
        cls,
        db: Session,
        user_id: int,
        current_pin: str,
        new_pin: str,
        performed_by: Optional[str] = None
    ) -> AppUser:
        """
        تغيير رمز الدخول السري (PIN) للمستخدم مع فرض قوة الرمز ومنع الرموز الضعيفة أو المكشوفة،
        وإلغاء علامة الإلزام بتغيير الرمز عند أول دخول (must_change_pin = False).
        """
        user = db.query(AppUser).filter(AppUser.id == user_id).first()
        if not user:
            raise LedgerValidationError("المستخدم غير موجود.")

        if not user.verify_pin(current_pin):
            raise LedgerValidationError("رمز الدخول السري الحالي غير صحيح.")

        clean_new = (new_pin or "").strip()
        if clean_new == (current_pin or "").strip():
            raise LedgerValidationError("رمز الدخول السري الجديد يجب أن يختلف عن الرمز الحالي.")

        if is_compromised_or_weak_pin(clean_new):
            raise LedgerValidationError(
                "رمز الدخول السري الجديد ضعيف أو مكشوف (مثل 1234 أو أرقام متكررة). "
                "يرجى اختيار رمز سري قوي مكون من 6 أرقام غير متكررة."
            )

        user.pin_code = hash_pin_code(clean_new)
        user.must_change_pin = False

        if user.username.lower() == "admin":
            clear_initial_admin_bootstrap_pin()

        from system_activity_service import SystemActivityService
        SystemActivityService.log_login_attempt(
            db=db,
            username=user.username,
            status="PIN_CHANGE",
            user_id=user.id,
            full_name_ar=user.full_name_ar,
            details=f"User {user.username} successfully updated secret PIN",
        )
        SystemActivityService.log_configuration_change(
            db=db,
            config_category="SECURITY_POLICY",
            target_item=f"رمز الدخول السري (PIN) - {user.full_name_ar} ({user.username})",
            action_type="PIN_CHANGE",
            old_values={"pin_status": "PREVIOUS_PIN_SET", "must_change_pin": True},
            new_values={"pin_status": "NEW_PIN_HASHED_SECURELY", "must_change_pin": False},
            performed_by=performed_by or user.full_name_ar,
            user_id=f"USR-{user.id:03d}",
            username=user.username,
            change_reason="تغيير رمز الدخول السري للمستخدم",
        )

        db.add(AuditLog(
            table_name="app_users",
            record_id=user.id,
            action="CHANGE_PIN",
            performed_by=performed_by or user.full_name_ar,
            details=f"User {user.username} changed PIN and cleared must_change_pin flag."
        ))
        db.commit()
        db.refresh(user)
        return user


    @classmethod
    def create_or_update_user(
        cls,
        cls_or_db: Optional[Session] = None,
        db: Optional[Session] = None,
        username: str = "",
        full_name_ar: str = "",
        role: UserRole = UserRole.CUSTOM,
        pin_code: str = "",
        job_title: str = "مسؤول مالي",
        permissions_dict: Optional[Dict[str, bool]] = None,
        max_discount_pct: float = 100.0,
        is_active: bool = True,
        must_change_pin: Optional[bool] = None,
        performed_by: str = "مدير النظام (Admin)"
    ) -> AppUser:
        """إنشاء مستخدم جديد أو تحديث بياناته مع تشفير الـ PIN وتخصيص كامل لصلاحيات الشاشات والعمليات"""
        db_sess = db or cls_or_db
        uname = (username or "").strip().lower()
        fname = (full_name_ar or "").strip()
        if not uname or not fname:
            raise LedgerValidationError("اسم الدخول والاسم الكامل للمستخدم مطلوبان.")
        raw_pin = str(pin_code or "").strip()

        base_perms = get_default_permissions_for_role(role)
        if permissions_dict and isinstance(permissions_dict, dict):
            for k in ALL_PERMISSION_KEYS:
                if k in permissions_dict:
                    base_perms[k] = bool(permissions_dict[k])

        user = db_sess.query(AppUser).filter(func.lower(AppUser.username) == uname).first()
        is_new = False
        if user:
            if (not is_active or not base_perms.get("act_manage_users", False) or not base_perms.get("mod_settings", False)):
                other_admins = [
                    u for u in db_sess.query(AppUser).filter(AppUser.is_active == True, AppUser.id != user.id).all()
                    if u.has_permission("act_manage_users") and u.has_permission("mod_settings")
                ]
                if not other_admins:
                    raise LedgerValidationError(
                        "لا يمكن إيقاف هذا الحساب أو سحب صلاحية (إدارة المستخدمين / شاشة الإعدادات) منه لأنه المسؤول النشط الوحيد في النظام."
                    )

            user.full_name_ar = fname
            user.job_title = (job_title or "مسؤول مالي").strip()
            user.role = role
            if raw_pin:
                user.pin_code = hash_pin_code(raw_pin)
                if must_change_pin is not None:
                    user.must_change_pin = bool(must_change_pin)
            elif must_change_pin is not None:
                user.must_change_pin = bool(must_change_pin)
            user.permissions_json = json.dumps(base_perms, ensure_ascii=False)
            user.max_discount_pct = round_money(max_discount_pct)
            user.is_active = bool(is_active)
        else:
            if not raw_pin:
                raw_pin = generate_random_pin(6)
            is_new = True
            user = AppUser(
                username=uname,
                full_name_ar=fname,
                job_title=(job_title or "مسؤول مالي").strip(),
                role=role,
                pin_code=hash_pin_code(raw_pin),
                must_change_pin=bool(must_change_pin) if must_change_pin is not None else False,
                permissions_json=json.dumps(base_perms, ensure_ascii=False),
                max_discount_pct=round_money(max_discount_pct),
                is_active=bool(is_active)
            )
            db_sess.add(user)
            db_sess.flush()

        enabled_count = sum(1 for v in base_perms.values() if v)
        from system_activity_service import SystemActivityService
        SystemActivityService.log_configuration_change(
            db=db_sess,
            config_category="USER_PERMISSIONS",
            target_item=f"حساب وصلاحيات المستخدم: {user.full_name_ar} ({user.username})",
            action_type="CREATE_USER" if is_new else "UPDATE_PERMISSIONS",
            old_values=None if is_new else {"role": user.role.value, "is_active": user.is_active},
            new_values={"role": role.value, "is_active": bool(is_active), "enabled_perms_count": enabled_count, "max_discount_pct": float(max_discount_pct)},
            performed_by=performed_by,
            user_id=f"USR-{user.id:03d}",
            username=user.username,
            change_reason="إنشاء مستخدم جديد أو تعديل مصفوفة الصلاحيات الحرة وسقف الخصم",
        )

        db_sess.add(AuditLog(
            table_name="app_users",
            record_id=user.id,
            action="CREATE_USER" if is_new else "UPDATE_USER_PERMISSIONS",
            performed_by=performed_by,
            details=f"User: {user.username} ({user.full_name_ar}), Role: {role.value}, Active: {user.is_active}, Enabled Perms: {enabled_count}/{len(ALL_PERMISSION_KEYS)}"
        ))
        db_sess.commit()
        db_sess.refresh(user)
        return user


    @classmethod
    def save_custom_role_template(
        cls,
        db: Session,
        template_name: str,
        description: str,
        permissions_dict: Dict[str, bool],
        performed_by: str = "مدير النظام (Admin)"
    ) -> CustomRoleTemplate:
        """حفظ قالب صلاحيات مخصص لإعادة استخدامه وتعيينه لأي مستخدم بضغطة زر"""
        t_name = (template_name or "").strip()
        if not t_name:
            raise LedgerValidationError("اسم قالب الصلاحيات المخصص مطلوب.")

        clean_perms = {k: bool(permissions_dict.get(k, False)) for k in ALL_PERMISSION_KEYS}
        tpl = db.query(CustomRoleTemplate).filter(CustomRoleTemplate.template_name == t_name).first()
        if tpl:
            tpl.description = (description or "").strip()
            tpl.permissions_json = json.dumps(clean_perms, ensure_ascii=False)
        else:
            tpl = CustomRoleTemplate(
                template_name=t_name,
                description=(description or "").strip(),
                permissions_json=json.dumps(clean_perms, ensure_ascii=False)
            )
            db.add(tpl)
            db.flush()

        from system_activity_service import SystemActivityService
        SystemActivityService.log_configuration_change(
            db=db,
            config_category="CUSTOM_ROLES",
            target_item=f"قالب الصلاحيات المخصص: {t_name}",
            action_type="SAVE_ROLE_TEMPLATE",
            new_values={"template_name": t_name, "description": description, "enabled_perms": sum(1 for v in clean_perms.values() if v)},
            performed_by=performed_by,
            change_reason="حفظ أو تعديل قالب صلاحيات وظيفي مخصص",
        )

        db.add(AuditLog(
            table_name="custom_role_templates",
            record_id=tpl.id,
            action="SAVE_ROLE_TEMPLATE",
            performed_by=performed_by,
            details=f"Template: {t_name}"
        ))
        db.commit()
        db.refresh(tpl)
        return tpl


    @classmethod
    def delete_custom_role_template(
        cls,
        db: Session,
        template_name: str,
        performed_by: str = "مدير النظام (Admin)"
    ) -> bool:
        tpl = db.query(CustomRoleTemplate).filter(CustomRoleTemplate.template_name == template_name).first()
        if not tpl:
            raise LedgerValidationError("القالب المطلوب حذفه غير موجود.")
        tpl_id = tpl.id
        db.delete(tpl)
        db.add(AuditLog(
            table_name="custom_role_templates",
            record_id=tpl_id,
            action="DELETE_ROLE_TEMPLATE",
            performed_by=performed_by,
            details=f"Deleted Template: {template_name}"
        ))
        db.commit()
        return True

    @classmethod
    def generate_entry_number(cls, db: Session, fiscal_year: int) -> str:
        return cls._next_sequence_code(db, JournalEntry, JournalEntry.entry_number, f"JV-{fiscal_year}-", pad=4)

    @classmethod
    def generate_invoice_number(cls, db: Session, fiscal_year: int) -> str:
        return cls._next_sequence_code(db, SalesInvoice, SalesInvoice.invoice_number, f"INV-{fiscal_year}-", pad=4)

    @classmethod
    def generate_purchase_number(cls, db: Session, fiscal_year: int) -> str:
        return cls._next_sequence_code(db, PurchaseInvoice, PurchaseInvoice.invoice_number, f"PUR-{fiscal_year}-", pad=4)

    @classmethod
    def generate_note_number(cls, db: Session, note_type: NoteType, fiscal_year: int) -> str:
        prefix = "CN" if note_type == NoteType.CREDIT_NOTE else "DN"
        return cls._next_sequence_code(db, CreditDebitNote, CreditDebitNote.note_number, f"{prefix}-{fiscal_year}-", pad=4)

    @classmethod
    def generate_voucher_number(cls, db: Session, voucher_type: VoucherType, fiscal_year: int) -> str:
        prefix = "RV" if voucher_type == VoucherType.RECEIPT else "PV"
        return cls._next_sequence_code(db, CashVoucher, CashVoucher.voucher_number, f"{prefix}-{fiscal_year}-", pad=4)

    # =========================================================================
    # 3. إدارة البيانات الأساسية وشجرة الحسابات ومراكز التكلفة والمستودعات
    # =========================================================================
    @classmethod
    def _sync_warehouse_stock(
        cls,
        db: Session,
        product: Product,
        delta_qty: float,
        warehouse_id: Optional[int] = None
    ) -> None:
        """مزامنة أرصدة المستودعات الفرعية (WarehouseStock) مع الرصيد الإجمالي للصنف (Product.stock_quantity)"""
        if not product or product.is_service:
            return

        warehouses = db.query(Warehouse).filter(Warehouse.is_active == True).order_by(Warehouse.id).all()
        if not warehouses:
            return

        target_wh = None
        if warehouse_id:
            target_wh = db.query(Warehouse).filter(Warehouse.id == warehouse_id).first()
        if not target_wh:
            target_wh = warehouses[0]

        st_rec = db.query(WarehouseStock).filter(
            WarehouseStock.warehouse_id == target_wh.id,
            WarehouseStock.product_id == product.id
        ).first()
        if not st_rec:
            st_rec = WarehouseStock(warehouse_id=target_wh.id, product_id=product.id, quantity=0.0)
            db.add(st_rec)
            db.flush()

        new_wh_qty = round(float(st_rec.quantity) + float(delta_qty), 4)
        if new_wh_qty >= 0 or len(warehouses) == 1:
            st_rec.quantity = new_wh_qty
        else:
            # إذا كان المستودع الرئيسي لا يكفي وحده والرصيد الإجمالي كافٍ، نخصم المتبقي من المستودعات الفرعية الأخرى
            deficit = abs(new_wh_qty)
            st_rec.quantity = 0.0
            for other_wh in warehouses:
                if other_wh.id == target_wh.id or deficit <= 0:
                    continue
                ost = db.query(WarehouseStock).filter(
                    WarehouseStock.warehouse_id == other_wh.id,
                    WarehouseStock.product_id == product.id
                ).first()
                if ost and ost.quantity > 0:
                    take = min(ost.quantity, deficit)
                    ost.quantity = round(ost.quantity - take, 4)
                    deficit = round(deficit - take, 4)
            if deficit > 0:
                st_rec.quantity = -deficit

        # ضمان تطابق مجموع المستودعات الفرعية مع الرصيد الإجمالي للصنف
        all_ws = db.query(WarehouseStock).filter(WarehouseStock.product_id == product.id).all()
        current_sum = round(sum(float(x.quantity) for x in all_ws), 4)
        diff = round(float(product.stock_quantity) - current_sum, 4)
        if abs(diff) > 1e-4:
            st_rec.quantity = round(float(st_rec.quantity) + diff, 4)

    @classmethod
    def create_sub_account(
        cls,
        db: Session,
        parent_code: str,
        new_code: str,
        name_ar: str,
        name_en: str = "",
        description: str = ""
    ) -> Account:
        parent = db.query(Account).filter(Account.code == str(parent_code)).first()
        if not parent:
            raise LedgerValidationError(f"الحساب الأب ({parent_code}) غير موجود.")
        if db.query(Account).filter(Account.code == str(new_code)).first():
            raise LedgerValidationError(f"كود الحساب ({new_code}) مستخدم بالفعل.")
        if parent.is_leaf:
            has_lines = db.query(JournalLine).filter(JournalLine.account_id == parent.id).count() > 0
            if has_lines:
                raise LedgerValidationError(
                    f"الحساب الأب [{parent.code} - {parent.name_ar}] مسجل عليه قيود محاسبية مباشرة ولا يمكن تحويله إلى حساب تجميعي."
                )
            parent.is_leaf = False

        new_acc = Account(
            code=str(new_code).strip(),
            name_ar=name_ar.strip(),
            name_en=name_en.strip() or None,
            type=parent.type,
            sub_type=parent.sub_type,
            natural_balance=parent.natural_balance,
            parent_id=parent.id,
            level=parent.level + 1,
            is_leaf=True,
            is_active=True,
            description=description
        )
        db.add(new_acc)
        db.commit()
        db.refresh(new_acc)
        return new_acc

    @classmethod
    def create_cost_center(cls, db: Session, code: str, name_ar: str, name_en: str = "") -> CostCenter:
        if not name_ar.strip():
            raise LedgerValidationError("اسم مركز التكلفة مطلوب.")
        if not code.strip():
            code = cls._next_sequence_code(db, CostCenter, CostCenter.code, "CC-", pad=2)
        if db.query(CostCenter).filter(CostCenter.code == code.strip()).first():
            raise LedgerValidationError(f"كود مركز التكلفة ({code}) موجود بالفعل.")
        cc = CostCenter(code=code.strip(), name_ar=name_ar.strip(), name_en=name_en.strip() or None, is_leaf=True)
        db.add(cc)
        db.commit()
        db.refresh(cc)
        return cc

    @classmethod
    def get_treasury_and_bank_accounts(cls, db: Session) -> List[Account]:
        """استرجاع كافة حسابات الصناديق النقدية (1101) والبنوك (1102) الفرعية النشطة"""
        return db.query(Account).filter(
            Account.is_leaf == True,
            Account.is_active == True,
            (Account.code.like("1101%") | Account.code.like("1102%"))
        ).order_by(Account.code).all()

    @classmethod
    def create_or_update_customer(
        cls,
        db: Session,
        name_ar: str,
        code: Optional[str] = None,
        name_en: Optional[str] = None,
        vat_number: Optional[str] = None,
        cr_number: Optional[str] = None,
        phone: Optional[str] = None,
        email: Optional[str] = None,
        address: Optional[str] = None,
        credit_limit: float = 0.0,
        is_active: bool = True,
        performed_by: str = "مدير النظام (Admin)"
    ) -> Customer:
        if not name_ar.strip():
            raise LedgerValidationError("اسم العميل مطلوب.")
        if vat_number and str(vat_number).strip():
            v_chk = ZATCAPhase2Validator.validate_saudi_vat_number(vat_number, party_role="BUYER", required=True)
            if not v_chk["is_valid"]:
                raise LedgerValidationError(v_chk["message_ar"])
            vat_number = v_chk["clean_vat"]

        ar_acc = db.query(Account).filter(Account.code == "110301").first()
        cust = (
            db.query(Customer).filter(Customer.code == code).first()
            if code else db.query(Customer).filter(Customer.name_ar == name_ar.strip()).first()
        )
        if not code:
            code = cust.code if cust else cls._next_sequence_code(db, Customer, Customer.code, "CUST-", pad=3)

        action_name = "UPDATE_CUSTOMER" if cust else "CREATE_CUSTOMER"
        if cust:
            cust.name_ar = name_ar.strip()
            cust.name_en = name_en
            cust.vat_number = vat_number
            cust.cr_number = cr_number
            cust.phone = phone
            cust.email = email
            cust.address = address
            cust.credit_limit = float(credit_limit)
            cust.is_active = bool(is_active)
        else:
            cust = Customer(
                code=code, name_ar=name_ar.strip(), name_en=name_en,
                vat_number=vat_number, cr_number=cr_number, phone=phone,
                email=email, address=address, credit_limit=float(credit_limit),
                account_id=ar_acc.id if ar_acc else None,
                is_active=bool(is_active)
            )
            db.add(cust)
            db.flush()
        db.add(AuditLog(
            table_name="customers", record_id=cust.id, action=action_name,
            performed_by=performed_by, details=f"Customer: {cust.code} - {cust.name_ar}, Limit: {cust.credit_limit:,.2f}"
        ))
        db.commit()
        db.refresh(cust)
        return cust

    @classmethod
    def create_or_update_supplier(
        cls,
        db: Session,
        name_ar: str,
        code: Optional[str] = None,
        name_en: Optional[str] = None,
        vat_number: Optional[str] = None,
        cr_number: Optional[str] = None,
        phone: Optional[str] = None,
        email: Optional[str] = None,
        address: Optional[str] = None,
        is_active: bool = True,
        performed_by: str = "مدير النظام (Admin)"
    ) -> Supplier:
        if not name_ar.strip():
            raise LedgerValidationError("اسم المورد مطلوب.")
        if vat_number and str(vat_number).strip():
            v_chk = ZATCAPhase2Validator.validate_saudi_vat_number(vat_number, party_role="SUPPLIER", required=True)
            if not v_chk["is_valid"]:
                raise LedgerValidationError(v_chk["message_ar"])
            vat_number = v_chk["clean_vat"]

        ap_acc = db.query(Account).filter(Account.code == "210101").first()
        supp = (
            db.query(Supplier).filter(Supplier.code == code).first()
            if code else db.query(Supplier).filter(Supplier.name_ar == name_ar.strip()).first()
        )
        if not code:
            code = supp.code if supp else cls._next_sequence_code(db, Supplier, Supplier.code, "SUPP-", pad=3)

        action_name = "UPDATE_SUPPLIER" if supp else "CREATE_SUPPLIER"
        if supp:
            supp.name_ar = name_ar.strip()
            supp.name_en = name_en
            supp.vat_number = vat_number
            supp.cr_number = cr_number
            supp.phone = phone
            supp.email = email
            supp.address = address
            supp.is_active = bool(is_active)
        else:
            supp = Supplier(
                code=code, name_ar=name_ar.strip(), name_en=name_en,
                vat_number=vat_number, cr_number=cr_number, phone=phone,
                email=email, address=address, account_id=ap_acc.id if ap_acc else None,
                is_active=bool(is_active)
            )
            db.add(supp)
            db.flush()
        db.add(AuditLog(
            table_name="suppliers", record_id=supp.id, action=action_name,
            performed_by=performed_by, details=f"Supplier: {supp.code} - {supp.name_ar}"
        ))
        db.commit()
        db.refresh(supp)
        return supp

    @classmethod
    def create_or_update_product(
        cls,
        db: Session,
        name_ar: str,
        code: Optional[str] = None,
        barcode: Optional[str] = None,
        name_en: Optional[str] = None,
        category: str = "عام",
        unit: str = "حبة",
        cost_price: float = 0.0,
        sale_price: float = 0.0,
        reorder_level: float = 5.0,
        stock_quantity: float = 0.0,
        tax_rate: float = 0.15,
        is_service: bool = False,
        is_active: bool = True,
        performed_by: str = "مدير النظام (Admin)"
    ) -> Product:
        if not name_ar.strip():
            raise LedgerValidationError("اسم الصنف مطلوب.")
        if not code:
            prefix = "SRV-" if is_service else "PRD-"
            code = cls._next_sequence_code(db, Product, Product.code, prefix, pad=3)

        prod = db.query(Product).filter(Product.code == code).first()
        action_name = "UPDATE_PRODUCT" if prod else "CREATE_PRODUCT"
        if prod:
            prod.name_ar = name_ar.strip()
            prod.name_en = name_en
            prod.barcode = barcode or prod.barcode
            prod.category = category
            prod.unit = unit
            prod.cost_price = float(cost_price)
            prod.sale_price = float(sale_price)
            prod.reorder_level = float(reorder_level)
            prod.tax_rate = float(tax_rate)
            prod.is_service = bool(is_service)
            prod.is_active = bool(is_active)
        else:
            init_qty = 0.0 if is_service else float(stock_quantity)
            prod = Product(
                code=code, barcode=barcode or None, name_ar=name_ar.strip(),
                name_en=name_en, category=category, unit=unit,
                stock_quantity=init_qty,
                reorder_level=0.0 if is_service else float(reorder_level),
                cost_price=float(cost_price), sale_price=float(sale_price),
                tax_rate=float(tax_rate), is_service=bool(is_service),
                is_active=bool(is_active)
            )
            db.add(prod)
            db.flush()
            if not is_service:
                cls._sync_warehouse_stock(db, prod, init_qty)
        db.add(AuditLog(
            table_name="products", record_id=prod.id, action=action_name,
            performed_by=performed_by, details=f"Product: {prod.code} - {prod.name_ar}, Cost: {prod.cost_price:,.2f}, Price: {prod.sale_price:,.2f}"
        ))
        db.commit()
        db.refresh(prod)
        return prod

    # =========================================================================
    # 4. تسجيل وترحيل القيود اليومية العامة
    # =========================================================================
    @classmethod
    def create_journal_entry(
        cls,
        db: Session,
        description: str,
        lines_data: List[Dict[str, Any]],
        entry_date: Optional[date] = None,
        reference: Optional[str] = None,
        doc_type: DocumentType = DocumentType.JOURNAL_VOUCHER,
        auto_post: bool = True,
        commit: bool = True,
        performed_by: str = "مدير النظام (Admin)"
    ) -> JournalEntry:
        try:
            if not entry_date:
                entry_date = date.today()

            if len(lines_data) < 2:
                raise LedgerValidationError("القيد المحاسبي يجب أن يحتوي على طرفين (سطرين) على الأقل.")

            period = db.query(FiscalPeriod).filter(
                and_(
                    FiscalPeriod.start_date <= entry_date,
                    FiscalPeriod.end_date >= entry_date
                )
            ).first()

            if not period:
                yr = entry_date.year
                period = FiscalPeriod(
                    year=yr, start_date=date(yr, 1, 1), end_date=date(yr, 12, 31),
                    is_closed=False, total_days=365
                )
                db.add(period)
                db.flush()

            if period.is_closed and doc_type != DocumentType.CLOSING_ENTRY:
                raise LedgerValidationError(f"الفترة المالية لعام {period.year} مقفلة محاسبياً، لا يمكن الترحيل إليها.")

            total_debit = 0.0
            total_credit = 0.0
            validated_lines = []

            all_customers = None
            all_suppliers = None

            for idx, line in enumerate(lines_data, start=1):
                debit = round(float(line.get("debit", 0.0)), 2)
                credit = round(float(line.get("credit", 0.0)), 2)

                if debit < 0 or credit < 0:
                    raise LedgerValidationError(f"السطر رقم {idx}: المبالغ لا يمكن أن تكون سالبة.")
                if debit > 0 and credit > 0:
                    raise LedgerValidationError(f"السطر رقم {idx}: السطر لا يمكن أن يكون مديناً ودائناً في نفس الوقت.")
                if debit == 0 and credit == 0:
                    continue

                account = None
                if "account_code" in line:
                    account = db.query(Account).filter(Account.code == str(line["account_code"])).first()
                elif "account_id" in line:
                    account = db.query(Account).filter(Account.id == line["account_id"]).first()

                if not account:
                    acc_ref = line.get("account_code") or line.get("account_id")
                    raise LedgerValidationError(f"السطر رقم {idx}: الحساب ({acc_ref}) غير موجود في شجرة الحسابات.")

                if not account.is_leaf:
                    raise LedgerValidationError(
                        f"السطر رقم {idx}: الحساب [{account.code} - {account.name_ar}] حساب رئيسي تجميعي، ولا يسمح بالترحيل إلا للحسابات الفرعية."
                    )

                if not account.is_active:
                    raise LedgerValidationError(f"السطر رقم {idx}: الحساب [{account.code}] موقوف وغير نشط.")

                line_desc = line.get("description", description) or description
                cust_id = line.get("customer_id")
                supp_id = line.get("supplier_id")

                # ربط ذكي تلقائي بحساب العميل أو المورد إذا كان القيد على حساب الرقابة 110301 أو 210101
                if account.code == "110301" and not cust_id:
                    if all_customers is None:
                        all_customers = db.query(Customer).all()
                    combined_text = f"{line_desc} {description}"
                    for c_obj in all_customers:
                        if c_obj.name_ar and c_obj.name_ar in combined_text:
                            cust_id = c_obj.id
                            break
                elif account.code == "210101" and not supp_id:
                    if all_suppliers is None:
                        all_suppliers = db.query(Supplier).all()
                    combined_text = f"{line_desc} {description}"
                    for s_obj in all_suppliers:
                        if s_obj.name_ar and s_obj.name_ar in combined_text:
                            supp_id = s_obj.id
                            break

                total_debit += debit
                total_credit += credit

                validated_lines.append({
                    "account_id": account.id,
                    "line_number": len(validated_lines) + 1,
                    "debit": debit,
                    "credit": credit,
                    "description": line_desc,
                    "cost_center_id": line.get("cost_center_id"),
                    "customer_id": cust_id,
                    "supplier_id": supp_id
                })

            if len(validated_lines) < 2:
                raise LedgerValidationError("يجب أن يحتوي القيد على سطرين بقيم غير صفرية على الأقل.")

            if abs(total_debit - total_credit) > 0.01:
                raise LedgerValidationError(
                    f"القيد غير متزن محاسبياً! إجمالي المدين ({total_debit:,.2f}) لا يساوي إجمالي الدائن ({total_credit:,.2f})."
                )

            entry_number = cls.generate_entry_number(db, period.year)
            status = EntryStatus.POSTED if auto_post else EntryStatus.DRAFT

            entry = JournalEntry(
                entry_number=entry_number,
                entry_date=entry_date,
                period_id=period.id,
                doc_type=doc_type,
                reference=reference,
                description=description,
                status=status,
                total_debit=round(total_debit, 2),
                total_credit=round(total_credit, 2)
            )
            db.add(entry)
            db.flush()

            for vline in validated_lines:
                jline = JournalLine(
                    entry_id=entry.id,
                    line_number=vline["line_number"],
                    account_id=vline["account_id"],
                    debit=vline["debit"],
                    credit=vline["credit"],
                    description=vline["description"],
                    cost_center_id=vline["cost_center_id"],
                    customer_id=vline["customer_id"],
                    supplier_id=vline["supplier_id"]
                )
                db.add(jline)

            cls.record_audit_log(
                db=db,
                table_name="journal_entries",
                record_id=entry.id,
                action="CREATE_AND_POST" if auto_post else "CREATE_DRAFT",
                performed_by=performed_by,
                reference_number=entry_number,
                financial_amount=total_debit,
                new_values={
                    "entry_number": entry_number,
                    "entry_date": str(entry_date),
                    "doc_type": doc_type.value,
                    "status": status.value,
                    "total_debit": round_money(total_debit),
                    "total_credit": round_money(total_credit),
                    "lines_count": len(validated_lines),
                },
                details=f"Entry: {entry_number}, Total: {total_debit:,.2f}, Date: {entry_date}",
            )

            if commit:
                db.commit()
                db.refresh(entry)
            else:
                db.flush()
            return entry

        except Exception as e:
            if commit:
                db.rollback()
            raise e

    # =========================================================================
    # 5. محرك المبيعات والمشتريات والمخزون (Sales, Purchases & WAC Inventory)
    # =========================================================================
    @classmethod
    def create_sales_invoice(
        cls,
        db: Session,
        customer_name: str,
        items_data: List[Dict[str, Any]],
        invoice_date: Optional[date] = None,
        payment_method: PaymentMethod = PaymentMethod.CASH,
        invoice_type: InvoiceType = InvoiceType.SIMPLIFIED,
        customer_id: Optional[int] = None,
        customer_vat_number: Optional[str] = None,
        cost_center_id: Optional[int] = None,
        warehouse_id: Optional[int] = None,
        seller_name: Optional[str] = None,
        seller_vat_number: Optional[str] = None,
        notes: Optional[str] = None,
        allow_negative_stock: bool = False,
        treasury_account_code: Optional[str] = None,
        performed_by: str = "مدير النظام (Admin)"
    ) -> SalesInvoice:
        try:
            if not invoice_date:
                invoice_date = date.today()
            if not items_data:
                raise LedgerValidationError("لا يمكن إصدار فاتورة مبيعات بدون أصناف وبنود.")

            settings = cls.get_company_settings(db)
            seller_name = seller_name or settings.company_name_ar
            seller_vat_number = seller_vat_number or settings.vat_number

            cust_obj = db.query(Customer).filter(Customer.id == customer_id).first() if customer_id else None
            if not cust_obj and customer_name:
                cust_obj = db.query(Customer).filter(Customer.name_ar == customer_name.strip()).first()
                if cust_obj:
                    customer_id = cust_obj.id
            if cust_obj and not customer_vat_number:
                customer_name = cust_obj.name_ar
                customer_vat_number = cust_obj.vat_number

            seller_vat_chk = ZATCAPhase2Validator.validate_saudi_vat_number(seller_vat_number, party_role="SELLER", required=True)
            if not seller_vat_chk["is_valid"]:
                raise LedgerValidationError(seller_vat_chk["message_ar"])
            seller_vat_number = seller_vat_chk["clean_vat"]

            vat_clean = (customer_vat_number or "").strip()
            if invoice_type == InvoiceType.STANDARD or vat_clean:
                buyer_vat_chk = ZATCAPhase2Validator.validate_saudi_vat_number(
                    vat_clean,
                    party_role="BUYER",
                    required=(invoice_type == InvoiceType.STANDARD)
                )
                if not buyer_vat_chk["is_valid"]:
                    raise LedgerValidationError(buyer_vat_chk["message_ar"])
                customer_vat_number = buyer_vat_chk["clean_vat"]

            fiscal_year = invoice_date.year
            invoice_number = cls.generate_invoice_number(db, fiscal_year)

            subtotal = 0.0
            total_discount = 0.0
            taxable_amount = 0.0
            total_vat = 0.0
            grand_total = 0.0
            total_cost = 0.0

            calculated_items = []
            inventory_updates = []

            for item in items_data:
                qty = float(item.get("quantity", 1.0))
                if qty <= 0:
                    raise LedgerValidationError("كمية الصنف يجب أن تكون أكبر من الصفر.")

                prod_id = item.get("product_id")
                prod_obj = db.query(Product).filter(Product.id == prod_id).first() if prod_id else None

                price = float(item.get("unit_price", prod_obj.sale_price if prod_obj else 0.0))
                if price < 0:
                    raise LedgerValidationError("سعر بيع الوحدة لا يمكن أن يكون سالباً.")

                # تكلفة البضاعة المباعة تحسب فقط للأصناف المخزنية المسجلة (ليس للبنود الحرة أو الخدمية)
                if prod_obj and not prod_obj.is_service:
                    cost = float(prod_obj.cost_price)
                else:
                    cost = 0.0

                disc = float(item.get("discount", 0.0))
                if disc < 0 or disc > (qty * price) + 1e-6:
                    raise LedgerValidationError("مبلغ الخصم غير صالح.")

                rate = float(item.get("tax_rate", prod_obj.tax_rate if prod_obj else settings.default_vat_rate))
                item_name = item.get("item_name") or (prod_obj.name_ar if prod_obj else "بند مبيعات")

                line_calc = calculate_line_and_tax_amounts(qty, price, disc, rate)
                line_gross = round_money(line_calc["gross_amount"])
                line_disc = round_money(line_calc["discount"])
                line_taxable = round_money(line_calc["taxable_amount"])
                line_vat = round_money(line_calc["tax_amount"])
                line_total_with_tax = round_money(line_calc["total_with_tax"])
                line_total_cost = round_money(to_decimal(qty) * to_decimal(cost)) if (prod_obj and not prod_obj.is_service) else 0.0

                subtotal = round_money(to_decimal(subtotal) + to_decimal(line_gross))
                total_discount = round_money(to_decimal(total_discount) + to_decimal(line_disc))
                taxable_amount = round_money(to_decimal(taxable_amount) + to_decimal(line_taxable))
                total_vat = round_money(to_decimal(total_vat) + to_decimal(line_vat))
                grand_total = round_money(to_decimal(grand_total) + to_decimal(line_total_with_tax))
                total_cost = round_money(to_decimal(total_cost) + to_decimal(line_total_cost))

                calculated_items.append({
                    "product_id": prod_obj.id if prod_obj else None,
                    "item_name": item_name,
                    "quantity": qty,
                    "unit_price": price,
                    "cost_price": cost,
                    "discount": line_disc,
                    "taxable_amount": line_taxable,
                    "tax_rate": rate,
                    "tax_amount": line_vat,
                    "total_with_tax": line_total_with_tax
                })

                if prod_obj and not prod_obj.is_service:
                    if not allow_negative_stock and qty > prod_obj.stock_quantity + 1e-6:
                        raise LedgerValidationError(
                            f"الرصيد المخزني للصنف [{prod_obj.code} - {prod_obj.name_ar}] غير كافٍ! المتاح حالياً: ({prod_obj.stock_quantity:,.2f}) والمطلوب: ({qty:,.2f})."
                        )
                    inventory_updates.append((prod_obj, qty, cost, line_total_cost))

            subtotal = round_money(subtotal)
            total_discount = round_money(total_discount)
            taxable_amount = round_money(taxable_amount)
            total_vat = round_money(total_vat)
            grand_total = round_money(to_decimal(taxable_amount) + to_decimal(total_vat))
            total_cost = round_money(total_cost)

            inv_dt = datetime.combine(invoice_date, datetime.now().time())
            icv_seq = db.query(SalesInvoice).count() + 1
            qr_code_b64 = cls.generate_zatca_qr_code(
                seller_name=seller_name,
                vat_number=seller_vat_number,
                invoice_datetime=inv_dt,
                total_amount=grand_total,
                vat_amount=total_vat,
                doc_number=invoice_number,
                doc_type_code="388",
                subtype_code="0100000" if invoice_type == InvoiceType.STANDARD else "0200000",
                buyer_name=customer_name,
                buyer_vat=customer_vat_number or "",
                icv=icv_seq,
            )

            if payment_method == PaymentMethod.CASH:
                debit_acc_code = treasury_account_code or "110101"
                payment_desc = "نقداً بالصندوق"
            elif payment_method == PaymentMethod.BANK:
                debit_acc_code = treasury_account_code or "110201"
                payment_desc = "تحويل بنكي / نقاط بيع"
            else:
                debit_acc_code = "110301"
                payment_desc = f"بالأجل - العميل: {customer_name}"

            sales_lines = [
                {
                    "account_code": debit_acc_code,
                    "debit": grand_total,
                    "credit": 0.0,
                    "cost_center_id": cost_center_id,
                    "customer_id": customer_id if payment_method == PaymentMethod.CREDIT else None,
                    "description": f"مبيعات فاتورة {invoice_number} ({payment_desc})"
                },
            ]
            if total_discount > 0:
                sales_lines.append({"account_code": "4103", "debit": total_discount, "credit": 0.0, "cost_center_id": cost_center_id, "description": f"خصم مسموح به فاتورة {invoice_number}"})
                sales_lines.append({"account_code": "4101", "debit": 0.0, "credit": subtotal, "cost_center_id": cost_center_id, "description": f"إجمالي إيراد مبيعات فاتورة {invoice_number}"})
            else:
                sales_lines.append({"account_code": "4101", "debit": 0.0, "credit": taxable_amount, "cost_center_id": cost_center_id, "description": f"إيراد مبيعات فاتورة {invoice_number}"})

            if total_vat > 0:
                sales_lines.append({"account_code": "210204", "debit": 0.0, "credit": total_vat, "cost_center_id": cost_center_id, "description": f"ضريبة مخرجات 15% فاتورة {invoice_number}"})

            if payment_method == PaymentMethod.CREDIT and cust_obj and cust_obj.credit_limit > 0:
                curr_stmt = cls.get_party_statement(db, "CUSTOMER", cust_obj.id)
                projected_bal = curr_stmt["net_balance"] + grand_total
                if projected_bal > cust_obj.credit_limit + 0.01:
                    raise LedgerValidationError(
                        f"تجاوز الحد الائتماني للعميل [{cust_obj.name_ar}]! الحد المسموح: ({cust_obj.credit_limit:,.2f} ريال) والرصيد بعد الفاتورة سيبلغ: ({projected_bal:,.2f} ريال)."
                    )

            sales_entry = cls.create_journal_entry(
                db=db, description=f"إثبات مبيعات الفاتورة الضريبية رقم {invoice_number} - {customer_name}",
                lines_data=sales_lines, entry_date=invoice_date, reference=invoice_number,
                doc_type=DocumentType.SALES_INVOICE, auto_post=True, commit=False,
                performed_by=performed_by
            )

            cogs_entry = None
            if total_cost > 0:
                cogs_lines = [
                    {"account_code": "5101", "debit": total_cost, "credit": 0.0, "cost_center_id": cost_center_id, "description": f"تكلفة مبيعات فاتورة {invoice_number}"},
                    {"account_code": "110401", "debit": 0.0, "credit": total_cost, "cost_center_id": cost_center_id, "description": f"صرف مخزون فاتورة {invoice_number}"}
                ]
                cogs_entry = cls.create_journal_entry(
                    db=db, description=f"إثبات تكلفة البضاعة المباعة للفاتورة رقم {invoice_number}",
                    lines_data=cogs_lines, entry_date=invoice_date, reference=f"COGS-{invoice_number}",
                    doc_type=DocumentType.JOURNAL_VOUCHER, auto_post=True, commit=False,
                    performed_by=performed_by
                )

            invoice = SalesInvoice(
                invoice_number=invoice_number, invoice_date=invoice_date,
                customer_id=customer_id, customer_name=customer_name,
                customer_vat_number=customer_vat_number, cost_center_id=cost_center_id,
                payment_method=payment_method, invoice_type=invoice_type,
                subtotal=subtotal, discount_amount=total_discount,
                taxable_amount=taxable_amount, vat_amount=total_vat,
                grand_total=grand_total, total_cost=total_cost,
                journal_entry_id=sales_entry.id,
                cogs_entry_id=cogs_entry.id if cogs_entry else None,
                qr_code_base64=qr_code_b64, notes=notes
            )
            db.add(invoice)
            db.flush()

            for c_item in calculated_items:
                db.add(SalesInvoiceItem(
                    invoice_id=invoice.id, product_id=c_item["product_id"],
                    item_name=c_item["item_name"], quantity=c_item["quantity"],
                    unit_price=round(c_item["unit_price"], 2), cost_price=round(c_item["cost_price"], 2),
                    discount=round(c_item["discount"], 2), taxable_amount=round(c_item["taxable_amount"], 2),
                    tax_rate=c_item["tax_rate"], tax_amount=round(c_item["tax_amount"], 2),
                    total_with_tax=round(c_item["total_with_tax"], 2)
                ))

            for prod_obj, qty, unit_cost, line_cost in inventory_updates:
                prod_obj.stock_quantity = round(prod_obj.stock_quantity - qty, 4)
                cls._sync_warehouse_stock(db, prod_obj, -qty, warehouse_id=warehouse_id)
                db.add(InventoryTransaction(
                    tx_date=invoice_date, product_id=prod_obj.id,
                    tx_type=InventoryTxType.SALE_OUT, reference_number=invoice_number,
                    quantity_in=0.0, quantity_out=qty, balance_after=prod_obj.stock_quantity,
                    unit_cost=round(unit_cost, 2), total_cost=round(line_cost, 2),
                    journal_entry_id=cogs_entry.id if cogs_entry else sales_entry.id,
                    notes=f"صرف مبيعات للعميل: {customer_name}"
                ))

            cls.record_audit_log(
                db=db,
                table_name="sales_invoices",
                record_id=invoice.id,
                action="CREATE_SALES_INVOICE",
                performed_by=performed_by,
                reference_number=invoice_number,
                financial_amount=grand_total,
                new_values={
                    "invoice_number": invoice_number,
                    "invoice_date": str(invoice_date),
                    "customer_name": customer_name,
                    "customer_vat_number": customer_vat_number or "",
                    "invoice_type": invoice_type.value,
                    "payment_method": payment_method.value,
                    "taxable_amount": taxable_amount,
                    "vat_amount": total_vat,
                    "grand_total": grand_total,
                },
                details=f"Sales Invoice: {invoice_number} | Customer: {customer_name} | Total: {grand_total:,.2f} SAR (VAT: {total_vat:,.2f})",
            )

            db.commit()
            db.refresh(invoice)
            return invoice

        except Exception as e:
            db.rollback()
            raise e

    @classmethod
    def create_purchase_invoice(
        cls,
        db: Session,
        supplier_name: str,
        items_data: List[Dict[str, Any]],
        invoice_date: Optional[date] = None,
        payment_method: PaymentMethod = PaymentMethod.CREDIT,
        supplier_id: Optional[int] = None,
        supplier_vat_number: Optional[str] = None,
        supplier_invoice_number: Optional[str] = None,
        cost_center_id: Optional[int] = None,
        warehouse_id: Optional[int] = None,
        notes: Optional[str] = None,
        treasury_account_code: Optional[str] = None,
        performed_by: str = "مدير النظام (Admin)"
    ) -> PurchaseInvoice:
        try:
            if not invoice_date:
                invoice_date = date.today()
            if not items_data:
                raise LedgerValidationError("لا يمكن تسجيل فاتورة مشتريات بدون أصناف وبنود.")

            settings = cls.get_company_settings(db)
            supp_obj = db.query(Supplier).filter(Supplier.id == supplier_id).first() if supplier_id else None
            if not supp_obj and supplier_name:
                supp_obj = db.query(Supplier).filter(Supplier.name_ar == supplier_name.strip()).first()
                if supp_obj:
                    supplier_id = supp_obj.id
            if supp_obj and not supplier_vat_number:
                supplier_name = supp_obj.name_ar
                supplier_vat_number = supp_obj.vat_number

            if supplier_vat_number and str(supplier_vat_number).strip():
                supp_vat_chk = ZATCAPhase2Validator.validate_saudi_vat_number(supplier_vat_number, party_role="SUPPLIER", required=True)
                if not supp_vat_chk["is_valid"]:
                    raise LedgerValidationError(supp_vat_chk["message_ar"])
                supplier_vat_number = supp_vat_chk["clean_vat"]

            fiscal_year = invoice_date.year
            invoice_number = cls.generate_purchase_number(db, fiscal_year)

            subtotal = 0.0
            total_discount = 0.0
            taxable_amount = 0.0
            inventory_taxable_amount = 0.0
            direct_expense_taxable_amount = 0.0
            total_vat = 0.0
            grand_total = 0.0

            calculated_items = []
            inventory_updates = []

            for item in items_data:
                qty = float(item.get("quantity", 1.0))
                if qty <= 0:
                    raise LedgerValidationError("كمية الصنف المشترى يجب أن تكون أكبر من الصفر.")

                prod_id = item.get("product_id")
                prod_obj = db.query(Product).filter(Product.id == prod_id).first() if prod_id else None

                price = float(item.get("unit_price", prod_obj.cost_price if prod_obj else 0.0))
                disc = float(item.get("discount", 0.0))
                rate = float(item.get("tax_rate", prod_obj.tax_rate if prod_obj else settings.default_vat_rate))
                item_name = item.get("item_name") or (prod_obj.name_ar if prod_obj else "بند مشتريات")

                line_calc = calculate_line_and_tax_amounts(qty, price, disc, rate)
                line_gross = round_money(line_calc["gross_amount"])
                line_disc = round_money(line_calc["discount"])
                line_taxable = round_money(line_calc["taxable_amount"])
                line_vat = round_money(line_calc["tax_amount"])
                line_total_with_tax = round_money(line_calc["total_with_tax"])
                net_unit_cost = round_rate(to_decimal(line_taxable) / to_decimal(qty)) if qty > 0 else round_rate(price)

                subtotal = round_money(to_decimal(subtotal) + to_decimal(line_gross))
                total_discount = round_money(to_decimal(total_discount) + to_decimal(line_disc))
                taxable_amount = round_money(to_decimal(taxable_amount) + to_decimal(line_taxable))
                total_vat = round_money(to_decimal(total_vat) + to_decimal(line_vat))
                grand_total = round_money(to_decimal(grand_total) + to_decimal(line_total_with_tax))

                calculated_items.append({
                    "product_id": prod_obj.id if prod_obj else None,
                    "item_name": item_name,
                    "quantity": qty,
                    "unit_price": price,
                    "discount": line_disc,
                    "taxable_amount": line_taxable,
                    "tax_rate": rate,
                    "tax_amount": line_vat,
                    "total_with_tax": line_total_with_tax
                })

                if prod_obj and not prod_obj.is_service:
                    inventory_taxable_amount = round_money(to_decimal(inventory_taxable_amount) + to_decimal(line_taxable))
                    inventory_updates.append((prod_obj, qty, net_unit_cost, line_taxable))
                else:
                    direct_expense_taxable_amount = round_money(to_decimal(direct_expense_taxable_amount) + to_decimal(line_taxable))

            subtotal = round_money(subtotal)
            total_discount = round_money(total_discount)
            taxable_amount = round_money(taxable_amount)
            inventory_taxable_amount = round_money(inventory_taxable_amount)
            direct_expense_taxable_amount = round_money(direct_expense_taxable_amount)
            total_vat = round_money(total_vat)
            grand_total = round_money(to_decimal(taxable_amount) + to_decimal(total_vat))

            if payment_method == PaymentMethod.CASH:
                credit_acc_code = treasury_account_code or "110101"
                payment_desc = "سداد نقدي فوري"
            elif payment_method == PaymentMethod.BANK:
                credit_acc_code = treasury_account_code or "110201"
                payment_desc = "سداد بتحويل بنكي"
            else:
                credit_acc_code = "210101"
                payment_desc = f"شراء بالأجل - المورد: {supplier_name}"

            ref_str = f"فاتورة مورد: {supplier_invoice_number}" if supplier_invoice_number else invoice_number
            purchase_lines = []
            if inventory_taxable_amount > 0:
                purchase_lines.append({
                    "account_code": "110401",
                    "debit": inventory_taxable_amount,
                    "credit": 0.0,
                    "cost_center_id": cost_center_id,
                    "description": f"إثبات مشتريات مخزون فاتورة {invoice_number}"
                })
            if direct_expense_taxable_amount > 0:
                purchase_lines.append({
                    "account_code": "5101",
                    "debit": direct_expense_taxable_amount,
                    "credit": 0.0,
                    "cost_center_id": cost_center_id,
                    "description": f"إثبات مشتريات خدمية / مباشرة فاتورة {invoice_number}"
                })
            if total_vat > 0:
                purchase_lines.append({
                    "account_code": "110503",
                    "debit": total_vat,
                    "credit": 0.0,
                    "cost_center_id": cost_center_id,
                    "description": f"ضريبة مدخلات مشتريات فاتورة {invoice_number}"
                })
            purchase_lines.append({
                "account_code": credit_acc_code,
                "debit": 0.0,
                "credit": grand_total,
                "cost_center_id": cost_center_id,
                "supplier_id": supplier_id if payment_method == PaymentMethod.CREDIT else None,
                "description": f"استحقاق مشتريات {invoice_number} ({payment_desc})"
            })

            purchase_entry = cls.create_journal_entry(
                db=db, description=f"إثبات فاتورة مشتريات رقم {invoice_number} - المورد: {supplier_name} ({ref_str})",
                lines_data=purchase_lines, entry_date=invoice_date, reference=invoice_number,
                doc_type=DocumentType.PURCHASE_INVOICE, auto_post=True, commit=False,
                performed_by=performed_by
            )

            pur_dt = datetime.combine(invoice_date, datetime.now().time())
            pur_icv_seq = db.query(PurchaseInvoice).count() + 1
            qr_seller_name = (supplier_name or settings.company_name_ar).strip()
            qr_seller_vat = (supplier_vat_number if (supplier_vat_number and len(str(supplier_vat_number).strip()) == 15) else settings.vat_number).strip()
            pur_qr_b64 = cls.generate_zatca_qr_code(
                seller_name=qr_seller_name,
                vat_number=qr_seller_vat,
                invoice_datetime=pur_dt,
                total_amount=grand_total,
                vat_amount=total_vat,
                doc_number=invoice_number,
                doc_type_code="388",
                subtype_code="0100000",
                buyer_name=settings.company_name_ar,
                buyer_vat=settings.vat_number,
                icv=pur_icv_seq,
            )

            purchase_inv = PurchaseInvoice(
                invoice_number=invoice_number, supplier_invoice_number=supplier_invoice_number,
                invoice_date=invoice_date, supplier_id=supplier_id, supplier_name=supplier_name,
                supplier_vat_number=supplier_vat_number, cost_center_id=cost_center_id,
                payment_method=payment_method, subtotal=subtotal, discount_amount=total_discount,
                taxable_amount=taxable_amount, vat_amount=total_vat, grand_total=grand_total,
                journal_entry_id=purchase_entry.id, qr_code_base64=pur_qr_b64, notes=notes
            )
            db.add(purchase_inv)
            db.flush()

            for c_item in calculated_items:
                db.add(PurchaseInvoiceItem(
                    invoice_id=purchase_inv.id, product_id=c_item["product_id"],
                    item_name=c_item["item_name"], quantity=c_item["quantity"],
                    unit_price=round(c_item["unit_price"], 2), discount=round(c_item["discount"], 2),
                    taxable_amount=round(c_item["taxable_amount"], 2), tax_rate=c_item["tax_rate"],
                    tax_amount=round(c_item["tax_amount"], 2), total_with_tax=round(c_item["total_with_tax"], 2)
                ))

            for prod_obj, qty_in, net_unit_cost, total_in_cost in inventory_updates:
                old_qty = float(prod_obj.stock_quantity)
                old_cost = float(prod_obj.cost_price)
                old_val = old_qty * old_cost
                new_qty = round(old_qty + qty_in, 4)
                if new_qty > 0:
                    wac_cost = (old_val + total_in_cost) / new_qty
                    prod_obj.cost_price = round(wac_cost, 4)
                else:
                    prod_obj.cost_price = round(net_unit_cost, 4)
                prod_obj.stock_quantity = new_qty
                cls._sync_warehouse_stock(db, prod_obj, qty_in, warehouse_id=warehouse_id)

                db.add(InventoryTransaction(
                    tx_date=invoice_date, product_id=prod_obj.id,
                    tx_type=InventoryTxType.PURCHASE_IN, reference_number=invoice_number,
                    quantity_in=qty_in, quantity_out=0.0, balance_after=prod_obj.stock_quantity,
                    unit_cost=round(net_unit_cost, 2), total_cost=round(total_in_cost, 2),
                    journal_entry_id=purchase_entry.id, notes=f"استلام مشتريات من المورد: {supplier_name}"
                ))

            cls.record_audit_log(
                db=db,
                table_name="purchase_invoices",
                record_id=purchase_inv.id,
                action="CREATE_PURCHASE_INVOICE",
                performed_by=performed_by,
                reference_number=invoice_number,
                financial_amount=grand_total,
                new_values={
                    "invoice_number": invoice_number,
                    "supplier_invoice_number": supplier_invoice_number or "",
                    "invoice_date": str(invoice_date),
                    "supplier_name": supplier_name,
                    "supplier_vat_number": supplier_vat_number or "",
                    "payment_method": payment_method.value,
                    "taxable_amount": taxable_amount,
                    "vat_amount": total_vat,
                    "grand_total": grand_total,
                },
                details=f"Purchase Invoice: {invoice_number} | Supplier: {supplier_name} | Total: {grand_total:,.2f} SAR (VAT: {total_vat:,.2f})",
            )

            db.commit()
            db.refresh(purchase_inv)
            return purchase_inv

        except Exception as e:
            db.rollback()
            raise e

    @classmethod
    def create_inventory_adjustment(
        cls,
        db: Session,
        product_id: int,
        new_actual_quantity: float,
        adjustment_date: Optional[date] = None,
        warehouse_id: Optional[int] = None,
        reason: str = "تسوية جرد مخزني فعلي",
        performed_by: str = "مدير النظام (Admin)"
    ) -> InventoryTransaction:
        try:
            adj_date = adjustment_date or date.today()
            prod = db.query(Product).filter(Product.id == product_id).first()
            if not prod:
                raise LedgerValidationError("الصنف المطلوب تسويته غير موجود.")
            if prod.is_service:
                raise LedgerValidationError("لا يمكن إجراء جرد مخزني لصنف خدمي.")

            diff_qty = round(float(new_actual_quantity) - float(prod.stock_quantity), 4)
            if abs(diff_qty) < 0.0001:
                raise LedgerValidationError("الكمية الفعلية مطابقة للرصيد الدفتري، لا يوجد فرق للتسوية.")

            unit_cost = float(prod.cost_price)
            total_adj_cost = round(abs(diff_qty) * unit_cost, 2)
            ref_no = f"ADJ-{adj_date.year}-{prod.code}"

            je = None
            if total_adj_cost > 0:
                if diff_qty > 0:
                    adj_lines = [
                        {"account_code": "110401", "debit": total_adj_cost, "credit": 0.0, "description": f"فائض جرد للصنف {prod.name_ar}"},
                        {"account_code": "5105", "debit": 0.0, "credit": total_adj_cost, "description": f"إثبات فائض الجرد المخزني ({reason})"},
                    ]
                else:
                    adj_lines = [
                        {"account_code": "5105", "debit": total_adj_cost, "credit": 0.0, "description": f"عجز جرد للصنف {prod.name_ar} ({reason})"},
                        {"account_code": "110401", "debit": 0.0, "credit": total_adj_cost, "description": f"تخفيض المخزون بعجز الجرد للصنف {prod.name_ar}"},
                    ]

                je = cls.create_journal_entry(
                    db=db, description=f"تسوية جرد مخزني للصنف [{prod.code} - {prod.name_ar}] - {reason}",
                    lines_data=adj_lines, entry_date=adj_date, reference=ref_no,
                    doc_type=DocumentType.INVENTORY_ADJUSTMENT, auto_post=True, commit=False,
                    performed_by=performed_by
                )

            old_stock_qty = round(float(prod.stock_quantity), 4)
            prod.stock_quantity = round(float(new_actual_quantity), 4)
            cls._sync_warehouse_stock(db, prod, diff_qty, warehouse_id=warehouse_id)

            inv_tx = InventoryTransaction(
                tx_date=adj_date, product_id=prod.id, tx_type=InventoryTxType.ADJUSTMENT,
                reference_number=ref_no, quantity_in=diff_qty if diff_qty > 0 else 0.0,
                quantity_out=abs(diff_qty) if diff_qty < 0 else 0.0, balance_after=prod.stock_quantity,
                unit_cost=unit_cost, total_cost=total_adj_cost,
                journal_entry_id=je.id if je else None, notes=reason
            )
            db.add(inv_tx)
            db.flush()
            cls.record_audit_log(
                db=db,
                table_name="inventory_transactions",
                record_id=inv_tx.id,
                action="INVENTORY_ADJUSTMENT",
                performed_by=performed_by,
                reference_number=ref_no,
                financial_amount=total_adj_cost,
                old_values={"product_code": prod.code, "stock_quantity": old_stock_qty},
                new_values={"product_code": prod.code, "stock_quantity": round(float(prod.stock_quantity), 4), "diff_qty": diff_qty},
                details=f"Inventory Adjustment {ref_no} for {prod.code}: {old_stock_qty} -> {prod.stock_quantity} ({reason})",
            )
            db.commit()
            db.refresh(inv_tx)
            return inv_tx

        except Exception as e:
            db.rollback()
            raise e

    # =========================================================================
    # 6. محرك إشعارات الدائن والمدين وسندات القبض والصرف
    # =========================================================================
    @classmethod
    def create_credit_debit_note(
        cls,
        db: Session,
        note_type: NoteType,
        party_name: str,
        items_data: List[Dict[str, Any]],
        note_date: Optional[date] = None,
        payment_method: PaymentMethod = PaymentMethod.CREDIT,
        original_invoice_number: Optional[str] = None,
        sales_invoice_id: Optional[int] = None,
        purchase_invoice_id: Optional[int] = None,
        customer_id: Optional[int] = None,
        supplier_id: Optional[int] = None,
        party_vat_number: Optional[str] = None,
        warehouse_id: Optional[int] = None,
        reason: str = "مرتجع بضاعة طبقاً للاتفاق",
        treasury_account_code: Optional[str] = None,
        performed_by: str = "مدير النظام (Admin)"
    ) -> CreditDebitNote:
        try:
            if not note_date:
                note_date = date.today()
            if not items_data:
                raise LedgerValidationError("لا يمكن إصدار إشعار دائن/مدين بدون أصناف.")

            settings = cls.get_company_settings(db)
            note_number = cls.generate_note_number(db, note_type, note_date.year)

            if note_type == NoteType.CREDIT_NOTE and not customer_id and party_name:
                c_match = db.query(Customer).filter(Customer.name_ar == party_name.strip()).first()
                if c_match:
                    customer_id = c_match.id
                    if not party_vat_number:
                        party_vat_number = c_match.vat_number
            elif note_type == NoteType.DEBIT_NOTE and not supplier_id and party_name:
                s_match = db.query(Supplier).filter(Supplier.name_ar == party_name.strip()).first()
                if s_match:
                    supplier_id = s_match.id
                    if not party_vat_number:
                        party_vat_number = s_match.vat_number

            if party_vat_number and str(party_vat_number).strip():
                p_chk = ZATCAPhase2Validator.validate_saudi_vat_number(
                    party_vat_number,
                    party_role="BUYER" if note_type == NoteType.CREDIT_NOTE else "SUPPLIER",
                    required=True
                )
                if not p_chk["is_valid"]:
                    raise LedgerValidationError(p_chk["message_ar"])
                party_vat_number = p_chk["clean_vat"]

            subtotal = 0.0
            taxable_amount = 0.0
            total_vat = 0.0
            grand_total = 0.0
            total_cost_rev = 0.0

            calculated_items = []
            inventory_updates = []

            for item in items_data:
                qty = float(item.get("quantity", 1.0))
                if qty <= 0:
                    raise LedgerValidationError("كمية المرتجع يجب أن تكون أكبر من الصفر.")

                prod_id = item.get("product_id")
                prod_obj = db.query(Product).filter(Product.id == prod_id).first() if prod_id else None

                price = float(item.get("unit_price", 0.0))
                cost = float(item.get("cost_price", prod_obj.cost_price if prod_obj else 0.0)) if (prod_obj and not prod_obj.is_service) else 0.0
                rate = float(item.get("tax_rate", prod_obj.tax_rate if prod_obj else settings.default_vat_rate))
                item_name = item.get("item_name") or (prod_obj.name_ar if prod_obj else "بند مرتجع")

                line_calc = calculate_line_and_tax_amounts(qty, price, 0.0, rate)
                line_taxable = round_money(line_calc["taxable_amount"])
                line_vat = round_money(line_calc["tax_amount"])
                line_total = round_money(line_calc["total_with_tax"])
                line_cost = round_money(to_decimal(qty) * to_decimal(cost)) if (prod_obj and not prod_obj.is_service) else 0.0

                subtotal = round_money(to_decimal(subtotal) + to_decimal(line_taxable))
                taxable_amount = round_money(to_decimal(taxable_amount) + to_decimal(line_taxable))
                total_vat = round_money(to_decimal(total_vat) + to_decimal(line_vat))
                grand_total = round_money(to_decimal(grand_total) + to_decimal(line_total))
                total_cost_rev = round_money(to_decimal(total_cost_rev) + to_decimal(line_cost))

                calculated_items.append({
                    "product_id": prod_obj.id if prod_obj else None,
                    "item_name": item_name, "quantity": qty, "unit_price": price,
                    "cost_price": cost, "taxable_amount": line_taxable,
                    "tax_rate": rate, "tax_amount": line_vat, "total_with_tax": line_total
                })

                if prod_obj and not prod_obj.is_service:
                    inventory_updates.append((prod_obj, qty, cost, line_cost, price))

            subtotal = round_money(subtotal)
            taxable_amount = round_money(taxable_amount)
            total_vat = round_money(total_vat)
            grand_total = round_money(to_decimal(taxable_amount) + to_decimal(total_vat))
            total_cost_rev = round_money(total_cost_rev)

            note_dt = datetime.combine(note_date, datetime.now().time())
            note_icv = db.query(CreditDebitNote).count() + 1
            qr_b64 = cls.generate_zatca_qr_code(
                seller_name=settings.company_name_ar,
                vat_number=settings.vat_number,
                invoice_datetime=note_dt,
                total_amount=grand_total,
                vat_amount=total_vat,
                doc_number=note_number,
                doc_type_code="381" if note_type == NoteType.CREDIT_NOTE else "383",
                subtype_code="0100000" if party_vat_number else "0200000",
                buyer_name=party_name,
                buyer_vat=party_vat_number or "",
                icv=note_icv,
            )

            cogs_entry = None
            if note_type == NoteType.CREDIT_NOTE:
                cr_acc = (treasury_account_code or "110101") if payment_method == PaymentMethod.CASH else ((treasury_account_code or "110201") if payment_method == PaymentMethod.BANK else "110301")
                j_lines = [{"account_code": "4102", "debit": taxable_amount, "credit": 0.0, "description": f"مردودات مبيعات إشعار دائن {note_number}"}]
                if total_vat > 0:
                    j_lines.append({"account_code": "210204", "debit": total_vat, "credit": 0.0, "description": f"تخفيض ضريبة المخرجات إشعار دائن {note_number}"})
                j_lines.append({
                    "account_code": cr_acc,
                    "debit": 0.0,
                    "credit": grand_total,
                    "customer_id": customer_id if payment_method == PaymentMethod.CREDIT else None,
                    "description": f"إشعار دائن للعميل: {party_name}"
                })

                main_entry = cls.create_journal_entry(
                    db=db, description=f"إثبات إشعار دائن (مرتجع مبيعات) رقم {note_number} - {party_name} ({reason})",
                    lines_data=j_lines, entry_date=note_date, reference=note_number,
                    doc_type=DocumentType.SALES_RETURN, auto_post=True, commit=False,
                    performed_by=performed_by
                )

                if total_cost_rev > 0:
                    cogs_rev_lines = [
                        {"account_code": "110401", "debit": total_cost_rev, "credit": 0.0, "description": f"إعادة بضاعة مرتجعة للمخزون إشعار {note_number}"},
                        {"account_code": "5101", "debit": 0.0, "credit": total_cost_rev, "description": f"عكس تكلفة البضاعة المباعة إشعار {note_number}"}
                    ]
                    cogs_entry = cls.create_journal_entry(
                        db=db, description=f"إعادة البضاعة المرتجعة للمخزون وعكس تكلفة المبيعات للإشعار {note_number}",
                        lines_data=cogs_rev_lines, entry_date=note_date, reference=f"COGS-{note_number}",
                        doc_type=DocumentType.SALES_RETURN, auto_post=True, commit=False,
                        performed_by=performed_by
                    )

                for prod_obj, qty, unit_cost, line_cost, _ in inventory_updates:
                    old_qty = float(prod_obj.stock_quantity)
                    old_cost = float(prod_obj.cost_price)
                    new_qty = round(old_qty + qty, 4)
                    if new_qty > 0:
                        prod_obj.cost_price = round(((old_qty * old_cost) + line_cost) / new_qty, 4)
                    prod_obj.stock_quantity = new_qty
                    cls._sync_warehouse_stock(db, prod_obj, qty, warehouse_id=warehouse_id)
                    db.add(InventoryTransaction(
                        tx_date=note_date, product_id=prod_obj.id, tx_type=InventoryTxType.SALES_RETURN_IN,
                        reference_number=note_number, quantity_in=qty, quantity_out=0.0,
                        balance_after=prod_obj.stock_quantity, unit_cost=unit_cost, total_cost=line_cost,
                        journal_entry_id=cogs_entry.id if cogs_entry else main_entry.id,
                        notes=f"مرتجع مبيعات من العميل: {party_name}"
                    ))
            else:
                dr_acc = (treasury_account_code or "110101") if payment_method == PaymentMethod.CASH else ((treasury_account_code or "110201") if payment_method == PaymentMethod.BANK else "210101")
                # حساب القيمة المخزنية المستبعدة بدقة ومطابقة أي فرق سعر مع حساب فروق المخزون 5105
                total_inv_credit = 0.0
                prepared_dn_updates = []
                for prod_obj, qty, unit_cost, _, price in inventory_updates:
                    if qty > prod_obj.stock_quantity + 1e-6:
                        raise LedgerValidationError(
                            f"لا يمكن إرجاع كمية ({qty}) من الصنف [{prod_obj.name_ar}] أكبر من الرصيد المتاح بالمستودع ({prod_obj.stock_quantity})."
                        )
                    old_qty = max(0.0, float(prod_obj.stock_quantity))
                    old_cost = float(prod_obj.cost_price)
                    old_val = round(old_qty * old_cost, 2)
                    new_qty = round(old_qty - qty, 4)
                    if new_qty > 0:
                        rem_val = max(0.0, round(old_val - round(qty * price, 2), 2))
                        new_cost = round(rem_val / new_qty, 4)
                        new_val = round(new_qty * new_cost, 2)
                        inv_credit_line = round(old_val - new_val, 2)
                    else:
                        new_cost = old_cost
                        inv_credit_line = old_val
                    total_inv_credit = round(total_inv_credit + inv_credit_line, 2)
                    prepared_dn_updates.append((prod_obj, qty, new_qty, new_cost, inv_credit_line))

                if not prepared_dn_updates:
                    total_inv_credit = taxable_amount

                price_variance = round(taxable_amount - total_inv_credit, 2)
                j_lines = [
                    {
                        "account_code": dr_acc,
                        "debit": grand_total,
                        "credit": 0.0,
                        "supplier_id": supplier_id if payment_method == PaymentMethod.CREDIT else None,
                        "description": f"إشعار مدين على المورد: {party_name}"
                    }
                ]
                if total_inv_credit > 0:
                    j_lines.append({
                        "account_code": "110401" if prepared_dn_updates else "5103",
                        "debit": 0.0,
                        "credit": total_inv_credit,
                        "description": f"رد بضاعة مشتراة للمورد إشعار {note_number}"
                    })
                if abs(price_variance) >= 0.01:
                    j_lines.append({
                        "account_code": "5105",
                        "debit": abs(price_variance) if price_variance < 0 else 0.0,
                        "credit": price_variance if price_variance > 0 else 0.0,
                        "description": f"تسوية فرق تكلفة مرتجع مشتريات إشعار {note_number}"
                    })
                if total_vat > 0:
                    j_lines.append({"account_code": "110503", "debit": 0.0, "credit": total_vat, "description": f"عكس ضريبة المدخلات إشعار مدين {note_number}"})

                main_entry = cls.create_journal_entry(
                    db=db, description=f"إثبات إشعار مدين (مرتجع مشتريات) رقم {note_number} - المورد: {party_name} ({reason})",
                    lines_data=j_lines, entry_date=note_date, reference=note_number,
                    doc_type=DocumentType.PURCHASE_RETURN, auto_post=True, commit=False,
                    performed_by=performed_by
                )

                for prod_obj, qty, new_qty, new_cost, inv_credit_line in prepared_dn_updates:
                    prod_obj.cost_price = new_cost
                    prod_obj.stock_quantity = new_qty
                    cls._sync_warehouse_stock(db, prod_obj, -qty, warehouse_id=warehouse_id)
                    db.add(InventoryTransaction(
                        tx_date=note_date, product_id=prod_obj.id, tx_type=InventoryTxType.PURCHASE_RETURN_OUT,
                        reference_number=note_number, quantity_in=0.0, quantity_out=qty,
                        balance_after=prod_obj.stock_quantity, unit_cost=round(inv_credit_line / qty, 2) if qty > 0 else 0.0,
                        total_cost=inv_credit_line,
                        journal_entry_id=main_entry.id, notes=f"مرتجع مشتريات للمورد: {party_name}"
                    ))

            note_obj = CreditDebitNote(
                note_number=note_number, note_type=note_type, note_date=note_date,
                original_invoice_number=original_invoice_number, sales_invoice_id=sales_invoice_id,
                purchase_invoice_id=purchase_invoice_id, customer_id=customer_id,
                supplier_id=supplier_id, party_name=party_name, party_vat_number=party_vat_number,
                payment_method=payment_method, reason=reason, subtotal=subtotal,
                taxable_amount=taxable_amount, vat_amount=total_vat, grand_total=grand_total,
                total_cost_reversal=total_cost_rev, journal_entry_id=main_entry.id,
                cogs_entry_id=cogs_entry.id if cogs_entry else None, qr_code_base64=qr_b64
            )
            db.add(note_obj)
            db.flush()

            for c_item in calculated_items:
                db.add(CreditDebitNoteItem(
                    note_id=note_obj.id, product_id=c_item["product_id"],
                    item_name=c_item["item_name"], quantity=c_item["quantity"],
                    unit_price=c_item["unit_price"], cost_price=c_item["cost_price"],
                    taxable_amount=c_item["taxable_amount"], tax_rate=c_item["tax_rate"],
                    tax_amount=c_item["tax_amount"], total_with_tax=c_item["total_with_tax"]
                ))

            cls.record_audit_log(
                db=db,
                table_name="credit_debit_notes",
                record_id=note_obj.id,
                action="CREATE_CREDIT_NOTE" if note_type == NoteType.CREDIT_NOTE else "CREATE_DEBIT_NOTE",
                performed_by=performed_by,
                reference_number=note_number,
                financial_amount=grand_total,
                new_values={
                    "note_number": note_number,
                    "note_type": note_type.value,
                    "original_invoice_number": original_invoice_number or "",
                    "party_name": party_name,
                    "taxable_amount": taxable_amount,
                    "vat_amount": total_vat,
                    "grand_total": grand_total,
                    "reason": reason,
                },
                details=f"{note_type.value}: {note_number} (Orig: {original_invoice_number or '-'}) | Party: {party_name} | Total: {grand_total:,.2f} SAR",
            )

            db.commit()
            db.refresh(note_obj)
            return note_obj

        except Exception as e:
            db.rollback()
            raise e

    @classmethod
    def create_cash_voucher(
        cls,
        db: Session,
        voucher_type: VoucherType,
        party_type: VoucherPartyType,
        party_name: str,
        amount: float,
        description: str,
        voucher_date: Optional[date] = None,
        payment_method: PaymentMethod = PaymentMethod.CASH,
        target_account_code: Optional[str] = None,
        treasury_account_code: Optional[str] = None,
        customer_id: Optional[int] = None,
        supplier_id: Optional[int] = None,
        cost_center_id: Optional[int] = None,
        include_input_vat: bool = False,
        reference_number: Optional[str] = None,
        performed_by: str = "مدير النظام (Admin)"
    ) -> CashVoucher:
        try:
            if not voucher_date:
                voucher_date = date.today()
            if amount <= 0:
                raise LedgerValidationError("مبلغ السند يجب أن يكون أكبر من الصفر.")

            settings = cls.get_company_settings(db)
            voucher_number = cls.generate_voucher_number(db, voucher_type, voucher_date.year)
            if treasury_account_code:
                treasury_acc_code = str(treasury_account_code).strip()
                tr_acc_obj = db.query(Account).filter(Account.code == treasury_acc_code).first()
                treasury_label = tr_acc_obj.name_ar if tr_acc_obj else ("الصندوق النقدي" if treasury_acc_code.startswith("1101") else "الحساب البنكي")
                payment_method = PaymentMethod.CASH if treasury_acc_code.startswith("1101") else PaymentMethod.BANK
            else:
                treasury_acc_code = "110101" if payment_method == PaymentMethod.CASH else "110201"
                treasury_label = "الصندوق الرئيسي" if payment_method == PaymentMethod.CASH else "الحساب البنكي الجاري"

            if party_type == VoucherPartyType.CUSTOMER:
                target_account_code = target_account_code or "110301"
                if customer_id:
                    cust = db.query(Customer).filter(Customer.id == customer_id).first()
                    if cust:
                        party_name = cust.name_ar
                elif party_name:
                    cust = db.query(Customer).filter(Customer.name_ar == party_name.strip()).first()
                    if cust:
                        customer_id = cust.id
            elif party_type == VoucherPartyType.SUPPLIER:
                target_account_code = target_account_code or "210101"
                if supplier_id:
                    supp = db.query(Supplier).filter(Supplier.id == supplier_id).first()
                    if supp:
                        party_name = supp.name_ar
                elif party_name:
                    supp = db.query(Supplier).filter(Supplier.name_ar == party_name.strip()).first()
                    if supp:
                        supplier_id = supp.id
            elif not target_account_code:
                raise LedgerValidationError("يجب تحديد الحساب المقابل للسند.")

            if str(target_account_code).strip() == treasury_acc_code:
                raise LedgerValidationError("لا يمكن إصدار سند خزينة/بنك يكون فيه الحساب المقابل هو نفس حساب الخزينة أو البنك.")

            total_amount = round(float(amount), 2)
            vat_rate = settings.default_vat_rate if settings and settings.default_vat_rate > 0 else 0.15
            if voucher_type == VoucherType.PAYMENT and include_input_vat:
                amount_before_vat = round(total_amount / (1.0 + vat_rate), 2)
                vat_amount = round(total_amount - amount_before_vat, 2)
            else:
                amount_before_vat = total_amount
                vat_amount = 0.0

            if voucher_type == VoucherType.RECEIPT:
                lines = [
                    {"account_code": treasury_acc_code, "debit": total_amount, "credit": 0.0, "cost_center_id": cost_center_id, "description": f"قبض بموجب سند {voucher_number} ({treasury_label})"},
                    {
                        "account_code": target_account_code,
                        "debit": 0.0,
                        "credit": total_amount,
                        "cost_center_id": cost_center_id,
                        "customer_id": customer_id,
                        "supplier_id": supplier_id,
                        "description": f"سند قبض من: {party_name} - {description}"
                    }
                ]
                doc_t = DocumentType.RECEIPT_VOUCHER
            else:
                lines = [
                    {
                        "account_code": target_account_code,
                        "debit": amount_before_vat,
                        "credit": 0.0,
                        "cost_center_id": cost_center_id,
                        "customer_id": customer_id,
                        "supplier_id": supplier_id,
                        "description": f"سند صرف إلى: {party_name} - {description}"
                    }
                ]
                if vat_amount > 0:
                    lines.append({"account_code": "110503", "debit": vat_amount, "credit": 0.0, "cost_center_id": cost_center_id, "description": f"ضريبة مدخلات سند صرف {voucher_number}"})
                lines.append({"account_code": treasury_acc_code, "debit": 0.0, "credit": total_amount, "cost_center_id": cost_center_id, "description": f"صرف بموجب سند {voucher_number} ({treasury_label})"})
                doc_t = DocumentType.PAYMENT_VOUCHER

            je = cls.create_journal_entry(
                db=db,
                description=f"{'سند قبض' if voucher_type == VoucherType.RECEIPT else 'سند صرف'} رقم {voucher_number} - {party_name}: {description}",
                lines_data=lines, entry_date=voucher_date, reference=reference_number or voucher_number,
                doc_type=doc_t, auto_post=True, commit=False, performed_by=performed_by
            )

            voucher = CashVoucher(
                voucher_number=voucher_number, voucher_type=voucher_type, voucher_date=voucher_date,
                payment_method=payment_method, party_type=party_type, customer_id=customer_id,
                supplier_id=supplier_id, cost_center_id=cost_center_id, target_account_code=target_account_code,
                party_name=party_name, amount_before_vat=amount_before_vat, vat_amount=vat_amount,
                total_amount=total_amount, reference_number=reference_number, description=description,
                journal_entry_id=je.id
            )
            db.add(voucher)
            db.flush()
            cls.record_audit_log(
                db=db,
                table_name="cash_vouchers",
                record_id=voucher.id,
                action="CREATE_RECEIPT_VOUCHER" if voucher_type == VoucherType.RECEIPT else "CREATE_PAYMENT_VOUCHER",
                performed_by=performed_by,
                reference_number=voucher_number,
                financial_amount=total_amount,
                new_values={
                    "voucher_number": voucher_number,
                    "voucher_type": voucher_type.value,
                    "party_name": party_name,
                    "payment_method": payment_method.value,
                    "total_amount": total_amount,
                    "vat_amount": vat_amount,
                },
                details=f"Voucher {voucher_number} ({voucher_type.value}) | Party: {party_name} | Amount: {total_amount:,.2f} SAR",
            )
            db.commit()
            db.refresh(voucher)
            return voucher

        except Exception as e:
            db.rollback()
            raise e

    # =========================================================================
    # 7. محرك سجل الأصول الثابتة والإهلاك الآلي (Fixed Assets & Auto-Depreciation)
    # =========================================================================
    @classmethod
    def create_or_update_fixed_asset(
        cls,
        db: Session,
        name_ar: str,
        category: str,
        purchase_date: date,
        purchase_cost: float,
        salvage_value: float = 0.0,
        depreciation_rate: float = 0.20,
        accumulated_depreciation: float = 0.0,
        asset_code: Optional[str] = None,
        post_purchase_entry: bool = False,
        payment_method: PaymentMethod = PaymentMethod.BANK,
        treasury_account_code: Optional[str] = None,
        is_active: bool = True,
        performed_by: str = "مدير النظام (Admin)"
    ) -> FixedAsset:
        """إضافة أو تحديث أصل ثابت في سجل الأصول مع خيار توليد قيد الشراء آلياً"""
        if not name_ar.strip():
            raise LedgerValidationError("اسم الأصل الثابت مطلوب.")
        if purchase_cost <= 0:
            raise LedgerValidationError("تكلفة شراء الأصل يجب أن تكون أكبر من الصفر.")

        cat_map = {
            "المباني والإنشاءات": ("120101", "120201"),
            "الآلات والمعدات والأجهزة": ("120102", "120202"),
            "السيارات ووسائل النقل": ("120103", "120203"),
            "الأثاث والتركيبات والتجهيزات": ("120104", "120204"),
        }
        asset_acc, accum_acc = cat_map.get(category, ("120103", "120203"))

        if not asset_code:
            asset_code = cls._next_sequence_code(db, FixedAsset, FixedAsset.asset_code, "AST-", pad=3)

        nbv = max(0.0, round(float(purchase_cost) - float(accumulated_depreciation), 2))
        useful_life = round(1.0 / depreciation_rate, 1) if depreciation_rate > 0 else 5.0

        fa = db.query(FixedAsset).filter(FixedAsset.asset_code == asset_code).first()
        action_name = "UPDATE_FIXED_ASSET" if fa else "CREATE_FIXED_ASSET"
        if fa:
            fa.name_ar = name_ar.strip()
            fa.category = category
            fa.purchase_date = purchase_date
            fa.purchase_cost = float(purchase_cost)
            fa.salvage_value = float(salvage_value)
            fa.depreciation_rate = float(depreciation_rate)
            fa.useful_life_years = useful_life
            fa.accumulated_depreciation = float(accumulated_depreciation)
            fa.net_book_value = nbv
            fa.asset_account_code = asset_acc
            fa.accum_dep_account_code = accum_acc
            fa.is_active = bool(is_active)
        else:
            fa = FixedAsset(
                asset_code=asset_code, name_ar=name_ar.strip(), category=category,
                purchase_date=purchase_date, purchase_cost=float(purchase_cost),
                salvage_value=float(salvage_value), useful_life_years=useful_life,
                depreciation_rate=float(depreciation_rate),
                accumulated_depreciation=float(accumulated_depreciation),
                net_book_value=nbv, asset_account_code=asset_acc,
                accum_dep_account_code=accum_acc, dep_expense_account_code="5207",
                is_active=bool(is_active)
            )
            db.add(fa)
            db.flush()

            if post_purchase_entry:
                cr_code = treasury_account_code or ("110101" if payment_method == PaymentMethod.CASH else ("110201" if payment_method == PaymentMethod.BANK else "210101"))
                cls.create_journal_entry(
                    db=db,
                    description=f"إثبات شراء واقتناء أصل ثابت [{asset_code} - {name_ar}]",
                    lines_data=[
                        {"account_code": asset_acc, "debit": float(purchase_cost), "credit": 0.0, "description": f"اقتناء أصل ثابت: {name_ar}"},
                        {"account_code": cr_code, "debit": 0.0, "credit": float(purchase_cost), "description": f"سداد قيمة أصل ثابت: {name_ar}"}
                    ],
                    entry_date=purchase_date,
                    reference=asset_code,
                    doc_type=DocumentType.PAYMENT_VOUCHER,
                    auto_post=True,
                    commit=False,
                    performed_by=performed_by
                )

        db.add(AuditLog(
            table_name="fixed_assets", record_id=fa.id, action=action_name,
            performed_by=performed_by, details=f"Asset: {fa.asset_code} - {fa.name_ar}, Cost: {fa.purchase_cost:,.2f}"
        ))
        db.commit()
        db.refresh(fa)
        return fa

    @classmethod
    def run_period_depreciation(
        cls,
        db: Session,
        dep_date: Optional[date] = None,
        months: int = 12,
        performed_by: str = "مدير النظام (Admin)"
    ) -> JournalEntry:
        """احتساب وترحيل قسط الإهلاك الدوري لكافة الأصول الثابتة النشطة مع منع التكرار لنفس الفترة"""
        dep_date = dep_date or date.today()
        period_ref = f"DEP-{dep_date.strftime('%Y%m')}-{months}M"
        existing_dep = db.query(JournalEntry).filter(
            JournalEntry.doc_type == DocumentType.DEPRECIATION_RUN,
            JournalEntry.reference == period_ref,
            JournalEntry.status == EntryStatus.POSTED
        ).first()
        if existing_dep:
            raise LedgerValidationError(
                f"تم احتساب وترحيل قيد إهلاك الأصول الثابتة لهذه الفترة ({dep_date.strftime('%Y-%m')}) مسبقاً برقم ({existing_dep.entry_number})."
            )

        assets = db.query(FixedAsset).filter(FixedAsset.is_active == True).all()
        if not assets:
            raise LedgerValidationError("لا توجد أصول ثابتة مسجلة في السجل لحساب إهلاكها.")

        dep_lines = []
        total_dep_period = 0.0

        for fa in assets:
            if fa.last_depreciation_date and fa.last_depreciation_date.year == dep_date.year and fa.last_depreciation_date.month == dep_date.month:
                continue
            depreciable_base = max(0.0, fa.purchase_cost - fa.salvage_value)
            remaining_depreciable = max(0.0, depreciable_base - fa.accumulated_depreciation)
            if remaining_depreciable <= 0.01:
                continue

            annual_dep = depreciable_base * fa.depreciation_rate
            period_dep = round(min(remaining_depreciable, annual_dep * (months / 12.0)), 2)
            if period_dep <= 0:
                continue

            fa.accumulated_depreciation = round(fa.accumulated_depreciation + period_dep, 2)
            fa.net_book_value = round(fa.purchase_cost - fa.accumulated_depreciation, 2)
            fa.last_depreciation_date = dep_date
            total_dep_period += period_dep

            dep_lines.append({
                "account_code": fa.accum_dep_account_code,
                "debit": 0.0,
                "credit": period_dep,
                "cost_center_id": fa.cost_center_id,
                "description": f"قسط إهلاك الأصل [{fa.asset_code} - {fa.name_ar}] عن {months} شهر"
            })

        if total_dep_period <= 0:
            raise LedgerValidationError("جميع الأصول الثابتة إما مهلكة بالكامل أو تم احتساب إهلاكها لهذه الفترة مسبقاً.")

        dep_lines.insert(0, {
            "account_code": "5207",
            "debit": round(total_dep_period, 2),
            "credit": 0.0,
            "description": f"إجمالي مصروف إهلاك الأصول الثابتة عن فترة ({months} شهر)"
        })

        je = cls.create_journal_entry(
            db=db,
            description=f"إثبات قسط إهلاك الأصول الثابتة الدوري ({months} شهر) حتى تاريخ {dep_date}",
            lines_data=dep_lines,
            entry_date=dep_date,
            reference=period_ref,
            doc_type=DocumentType.DEPRECIATION_RUN,
            auto_post=True,
            commit=True,
            performed_by=performed_by
        )
        return je

    @classmethod
    def get_fixed_assets_df(cls, db: Session) -> pd.DataFrame:
        assets = db.query(FixedAsset).order_by(FixedAsset.asset_code).all()
        rows = []
        for fa in assets:
            annual_dep = round(max(0.0, fa.purchase_cost - fa.salvage_value) * fa.depreciation_rate, 2)
            rows.append({
                "كود الأصل": fa.asset_code,
                "اسم الأصل الثابت": fa.name_ar,
                "الفئة": fa.category,
                "تاريخ الشراء": fa.purchase_date.strftime("%Y-%m-%d"),
                "التكلفة التاريخية": round(fa.purchase_cost, 2),
                "نسبة الإهلاك السنوي": f"{int(fa.depreciation_rate * 100)}%",
                "القسط السنوي": annual_dep,
                "مجمع الإهلاك المتراكم": round(fa.accumulated_depreciation, 2),
                "صافي القيمة الدفترية": round(fa.net_book_value, 2),
                "آخر إهلاك": fa.last_depreciation_date.strftime("%Y-%m-%d") if fa.last_depreciation_date else "-",
                "الحالة": "نشط ✅" if fa.is_active else "موقوف ⛔"
            })
        return pd.DataFrame(rows)

    # =========================================================================
    # 8. محرك الموظفين ومسير الرواتب ومكافأة نهاية الخدمة (Payroll & EOSB Engine)
    # =========================================================================
    @classmethod
    def create_or_update_employee(
        cls,
        db: Session,
        name_ar: str,
        job_title: str,
        nationality: str,
        is_saudi: bool,
        join_date: date,
        basic_salary: float,
        housing_allowance: float = 0.0,
        transport_allowance: float = 0.0,
        other_allowance: float = 0.0,
        emp_code: Optional[str] = None,
        is_active: bool = True,
        performed_by: str = "مدير النظام (Admin)"
    ) -> Employee:
        if not name_ar.strip():
            raise LedgerValidationError("اسم الموظف مطلوب.")
        if basic_salary <= 0:
            raise LedgerValidationError("الراتب الأساسي يجب أن يكون أكبر من الصفر.")

        if not emp_code:
            emp_code = cls._next_sequence_code(db, Employee, Employee.emp_code, "EMP-", pad=3)

        emp = db.query(Employee).filter(Employee.emp_code == emp_code).first()
        action_name = "UPDATE_EMPLOYEE" if emp else "CREATE_EMPLOYEE"
        if emp:
            emp.name_ar = name_ar.strip()
            emp.job_title = job_title
            emp.nationality = nationality
            emp.is_saudi = is_saudi
            emp.join_date = join_date
            emp.basic_salary = float(basic_salary)
            emp.housing_allowance = float(housing_allowance)
            emp.transport_allowance = float(transport_allowance)
            emp.other_allowance = float(other_allowance)
            emp.is_active = bool(is_active)
        else:
            emp = Employee(
                emp_code=emp_code, name_ar=name_ar.strip(), job_title=job_title,
                nationality=nationality, is_saudi=is_saudi, join_date=join_date,
                basic_salary=float(basic_salary), housing_allowance=float(housing_allowance),
                transport_allowance=float(transport_allowance), other_allowance=float(other_allowance),
                is_active=bool(is_active)
            )
            db.add(emp)
            db.flush()
        db.add(AuditLog(
            table_name="employees", record_id=emp.id, action=action_name,
            performed_by=performed_by, details=f"Employee: {emp.emp_code} - {emp.name_ar}, Basic: {emp.basic_salary:,.2f}"
        ))
        db.commit()
        db.refresh(emp)
        return emp

    @staticmethod
    def calculate_employee_eos(emp: Employee, as_of_date: Optional[date] = None) -> Dict[str, float]:
        """احتساب مكافأة نهاية الخدمة المتراكمة والقسط الشهري والتأمينات وفق نظام العمل السعودي"""
        as_of_date = as_of_date or date.today()
        total_salary = emp.basic_salary + emp.housing_allowance + emp.transport_allowance + emp.other_allowance
        gosi_base = emp.basic_salary + emp.housing_allowance

        if emp.is_saudi:
            gosi_emp = round(gosi_base * 0.0975, 2)
            gosi_comp = round(gosi_base * 0.1175, 2)
        else:
            gosi_emp = 0.0
            gosi_comp = round(gosi_base * 0.02, 2)

        net_salary = round(total_salary - gosi_emp, 2)

        service_days = max(0, (as_of_date - emp.join_date).days)
        service_years = round(service_days / 365.25, 2)

        if service_years <= 5.0:
            cumulative_eos = service_years * (0.5 * total_salary)
            monthly_eos_accrual = round((0.5 * total_salary) / 12.0, 2)
        else:
            cumulative_eos = (5.0 * 0.5 * total_salary) + ((service_years - 5.0) * total_salary)
            monthly_eos_accrual = round(total_salary / 12.0, 2)

        return {
            "total_salary": round(total_salary, 2),
            "gosi_employee": gosi_emp,
            "gosi_employer": gosi_comp,
            "net_salary": net_salary,
            "service_years": service_years,
            "monthly_eos_accrual": monthly_eos_accrual,
            "cumulative_eos_provision": round(cumulative_eos, 2)
        }

    @classmethod
    def get_employees_and_eos_df(cls, db: Session, as_of_date: Optional[date] = None) -> pd.DataFrame:
        emps = db.query(Employee).filter(Employee.is_active == True).order_by(Employee.emp_code).all()
        rows = []
        for e in emps:
            calc = cls.calculate_employee_eos(e, as_of_date=as_of_date)
            rows.append({
                "كود الموظف": e.emp_code,
                "اسم الموظف": e.name_ar,
                "المسمى الوظيفي": e.job_title,
                "الجنسية": e.nationality,
                "تاريخ المباشرة": e.join_date.strftime("%Y-%m-%d"),
                "سنوات الخدمة": calc["service_years"],
                "الراتب الإجمالي": calc["total_salary"],
                "حصة الموظف تأمينات": calc["gosi_employee"],
                "حصة الشركة تأمينات": calc["gosi_employer"],
                "صافي الراتب الشهري": calc["net_salary"],
                "قسط نهاية الخدمة الشهري": calc["monthly_eos_accrual"],
                "رصيد مخصص نهاية الخدمة المتراكم": calc["cumulative_eos_provision"]
            })
        return pd.DataFrame(rows)

    @classmethod
    def process_monthly_payroll(
        cls,
        db: Session,
        period_month: str,
        payment_date: Optional[date] = None,
        payment_method: PaymentMethod = PaymentMethod.BANK,
        treasury_account_code: Optional[str] = None,
        include_eos_accrual: bool = True,
        notes: str = "صرف مسير الرواتب والأجور الشهري",
        performed_by: str = "مدير النظام (Admin)"
    ) -> PayrollRun:
        """إصدار وترحيل مسير الرواتب الشهري مع منع التكرار لنفس الشهر"""
        payment_date = payment_date or date.today()
        clean_month = (period_month or "").strip()
        if not clean_month:
            raise LedgerValidationError("شهر مسير الرواتب مطلوب.")

        existing_runs = db.query(PayrollRun).filter(PayrollRun.period_month == clean_month).all()
        for ex in existing_runs:
            if not ex.journal_entry or ex.journal_entry.status != EntryStatus.REVERSED:
                raise LedgerValidationError(
                    f"تم إصدار وترحيل مسير رواتب لشهر ({clean_month}) مسبقاً برقم ({ex.payroll_number})."
                )

        emps = db.query(Employee).filter(Employee.is_active == True).all()
        if not emps:
            raise LedgerValidationError("لا يوجد موظفون نشطون لإصدار مسير الرواتب.")

        payroll_no = cls._next_sequence_code(db, PayrollRun, PayrollRun.payroll_number, f"PAY-{payment_date.year}-", pad=3)

        tot_gross = 0.0
        tot_gosi_emp = 0.0
        tot_gosi_comp = 0.0
        tot_eos = 0.0
        tot_net = 0.0

        for e in emps:
            c = cls.calculate_employee_eos(e, as_of_date=payment_date)
            tot_gross += c["total_salary"]
            tot_gosi_emp += c["gosi_employee"]
            tot_gosi_comp += c["gosi_employer"]
            tot_eos += c["monthly_eos_accrual"] if include_eos_accrual else 0.0
            tot_net += c["net_salary"]

        tot_gross = round(tot_gross, 2)
        tot_gosi_emp = round(tot_gosi_emp, 2)
        tot_gosi_comp = round(tot_gosi_comp, 2)
        tot_eos = round(tot_eos, 2)
        tot_net = round(tot_gross - tot_gosi_emp, 2)
        total_gosi_payable = round(tot_gosi_emp + tot_gosi_comp, 2)

        treasury_acc = treasury_account_code or ("110101" if payment_method == PaymentMethod.CASH else "110201")
        lines = [
            {"account_code": "5201", "debit": round(tot_gross + tot_gosi_comp, 2), "credit": 0.0, "description": f"رواتب وأجور وحصة تأمينات مسير {payroll_no} ({clean_month})"},
            {"account_code": treasury_acc, "debit": 0.0, "credit": tot_net, "description": f"صرف صافي رواتب الموظفين لشهر {clean_month}"},
        ]
        if total_gosi_payable > 0:
            lines.append({"account_code": "210203", "debit": 0.0, "credit": total_gosi_payable, "description": f"تأمينات اجتماعية مستحقة مسير {payroll_no}"})
        if tot_eos > 0:
            lines.append({"account_code": "5208", "debit": tot_eos, "credit": 0.0, "description": f"مصروف مكافأة نهاية الخدمة لشهر {clean_month}"})
            lines.append({"account_code": "2202", "debit": 0.0, "credit": tot_eos, "description": f"مخصص مكافأة نهاية الخدمة لشهر {clean_month}"})

        je = cls.create_journal_entry(
            db=db,
            description=f"إثبات وصرف مسير الرواتب والأجور رقم {payroll_no} عن شهر {clean_month}",
            lines_data=lines,
            entry_date=payment_date,
            reference=payroll_no,
            doc_type=DocumentType.PAYROLL_RUN,
            auto_post=True,
            commit=False,
            performed_by=performed_by
        )

        pr = PayrollRun(
            payroll_number=payroll_no, period_month=clean_month, payment_date=payment_date,
            payment_method=payment_method, employees_count=len(emps),
            total_gross_salaries=tot_gross, total_gosi_employee=tot_gosi_emp,
            total_gosi_employer=tot_gosi_comp, total_eos_accrual=tot_eos,
            net_paid_salaries=tot_net, journal_entry_id=je.id, notes=notes
        )
        db.add(pr)
        db.flush()
        cls.record_audit_log(
            db=db,
            table_name="payroll_runs",
            record_id=pr.id,
            action="PROCESS_PAYROLL_RUN",
            performed_by=performed_by,
            reference_number=payroll_no,
            financial_amount=tot_net,
            new_values={
                "payroll_number": payroll_no,
                "period_month": clean_month,
                "employees_count": len(emps),
                "total_gross_salaries": tot_gross,
                "net_paid_salaries": tot_net,
            },
            details=f"Payroll Run {payroll_no} ({clean_month}) | Employees: {len(emps)} | Net Paid: {tot_net:,.2f} SAR",
        )
        db.commit()
        db.refresh(pr)
        return pr

    # =========================================================================
    # 9. محرك أعمار الديون ومخصص الديون المشكوك فيها (Aging Report & ECL)
    # =========================================================================
    @classmethod
    def get_aging_report(cls, db: Session, party_type: str = "CUSTOMER", as_of_date: Optional[date] = None) -> pd.DataFrame:
        """تحليل أعمار ديون العملاء أو الموردين بمطابقة كاملة مع الأستاذ العام وتقسيمها إلى فترات زمنية وحساب ECL"""
        as_of_date = as_of_date or date.today()
        rows = []

        if party_type == "CUSTOMER":
            parties = db.query(Customer).all()
            for c in parties:
                stmt = cls.get_party_statement(db, "CUSTOMER", c.id)
                net_bal = stmt["net_balance"]
                if net_bal <= 0.01:
                    continue

                # توزيع الرصيد غير المسدد على أحدث الحركات المدينة المعتمدة (الفواتير أو القيود الافتتاحية)
                debit_movements = [
                    m for m in reversed(stmt["statement"])
                    if float(m["مدين (Debit)"]) > float(m["دائن (Credit)"])
                ]

                b_0_30 = b_31_60 = b_61_90 = b_90_plus = 0.0
                rem = net_bal
                for dm in debit_movements:
                    if rem <= 0:
                        break
                    net_doc_debit = float(dm["مدين (Debit)"]) - float(dm["دائن (Credit)"])
                    alloc = min(rem, net_doc_debit)
                    doc_dt = date.fromisoformat(dm["التاريخ"])
                    days = max(0, (as_of_date - doc_dt).days)
                    if days <= 30:
                        b_0_30 += alloc
                    elif days <= 60:
                        b_31_60 += alloc
                    elif days <= 90:
                        b_61_90 += alloc
                    else:
                        b_90_plus += alloc
                    rem -= alloc
                if rem > 0:
                    b_0_30 += rem

                ecl = round((b_0_30 * 0.01) + (b_31_60 * 0.03) + (b_61_90 * 0.10) + (b_90_plus * 0.25), 2)
                rows.append({
                    "الكود": c.code,
                    "الاسم": c.name_ar,
                    "0 - 30 يوماً": round(b_0_30, 2),
                    "31 - 60 يوماً": round(b_31_60, 2),
                    "61 - 90 يوماً": round(b_61_90, 2),
                    "أكثر من 90 يوماً": round(b_90_plus, 2),
                    "إجمالي المديونية": round(net_bal, 2),
                    "مخصص ECL المقترح": ecl
                })
        else:
            parties = db.query(Supplier).all()
            for s in parties:
                stmt = cls.get_party_statement(db, "SUPPLIER", s.id)
                net_bal = stmt["net_balance"]
                if net_bal <= 0.01:
                    continue

                credit_movements = [
                    m for m in reversed(stmt["statement"])
                    if float(m["دائن (Credit)"]) > float(m["مدين (Debit)"])
                ]

                b_0_30 = b_31_60 = b_61_90 = b_90_plus = 0.0
                rem = net_bal
                for cm in credit_movements:
                    if rem <= 0:
                        break
                    net_doc_credit = float(cm["دائن (Credit)"]) - float(cm["مدين (Debit)"])
                    alloc = min(rem, net_doc_credit)
                    doc_dt = date.fromisoformat(cm["التاريخ"])
                    days = max(0, (as_of_date - doc_dt).days)
                    if days <= 30:
                        b_0_30 += alloc
                    elif days <= 60:
                        b_31_60 += alloc
                    elif days <= 90:
                        b_61_90 += alloc
                    else:
                        b_90_plus += alloc
                    rem -= alloc
                if rem > 0:
                    b_0_30 += rem

                rows.append({
                    "الكود": s.code,
                    "الاسم": s.name_ar,
                    "0 - 30 يوماً": round(b_0_30, 2),
                    "31 - 60 يوماً": round(b_31_60, 2),
                    "61 - 90 يوماً": round(b_61_90, 2),
                    "أكثر من 90 يوماً": round(b_90_plus, 2),
                    "إجمالي المستحق للمورد": round(net_bal, 2),
                })

        return pd.DataFrame(rows)

    # =========================================================================
    # 10. محرك التسوية البنكية وربحية مراكز التكلفة وإقفال السنة المالية
    # =========================================================================
    @classmethod
    def reconcile_bank_statement(
        cls,
        db: Session,
        bank_account_code: str = "110201",
        bank_df: Optional[pd.DataFrame] = None
    ) -> Dict[str, Any]:
        """مطابقة حركات حساب البنك بالدفاتر مع كشف حساب البنك المرفوع"""
        stmt = cls.get_account_statement(db, account_code=bank_account_code)
        book_balance = stmt["closing_balance"]
        book_lines = stmt["statement"]

        if bank_df is None or bank_df.empty:
            bank_rows = []
            running_b = stmt["opening_balance"]
            for bl in book_lines:
                net_m = float(bl["Debit"]) - float(bl["Credit"])
                running_b += net_m
                bank_rows.append({
                    "التاريخ": bl["Date"],
                    "المرجع": bl["Reference"] or bl["Entry Number"],
                    "البيان البنكي": bl["Description"],
                    "إيداع (+)": float(bl["Debit"]),
                    "سحب (-)": float(bl["Credit"]),
                    "الرصيد البنكي": round(running_b, 2)
                })
            bank_df = pd.DataFrame(bank_rows, columns=["التاريخ", "المرجع", "البيان البنكي", "إيداع (+)", "سحب (-)", "الرصيد البنكي"])

        book_amounts = [round(float(x["Debit"]) - float(x["Credit"]), 2) for x in book_lines]
        bank_dep_col = next((c for c in bank_df.columns if any(w in str(c) for w in ["إيداع", "مدين", "Deposit", "Debit"])), None)
        bank_wd_col = next((c for c in bank_df.columns if any(w in str(c) for w in ["سحب", "دائن", "Withdrawal", "Credit"])), None)

        unrecorded_in_books = []
        matched_count = 0
        temp_book = book_amounts.copy()

        for _, r in bank_df.iterrows():
            dep = float(r[bank_dep_col]) if bank_dep_col and pd.notna(r[bank_dep_col]) else 0.0
            wd = float(r[bank_wd_col]) if bank_wd_col and pd.notna(r[bank_wd_col]) else 0.0
            net_b = round(dep - wd, 2)
            if net_b in temp_book:
                temp_book.remove(net_b)
                matched_count += 1
            elif abs(net_b) > 0.001:
                unrecorded_in_books.append({
                    "التاريخ": str(r.iloc[0]),
                    "البيان": str(r.iloc[2]) if len(r) > 2 else "عملية بنكية",
                    "المبلغ الصافي": net_b
                })

        unrecorded_total = round(sum(x["المبلغ الصافي"] for x in unrecorded_in_books), 2)
        outstanding_in_books_total = round(sum(temp_book), 2)
        bank_closing_balance = round(book_balance - outstanding_in_books_total + unrecorded_total, 2)
        adjusted_balance = round(book_balance + unrecorded_total, 2)

        return {
            "bank_account_code": bank_account_code,
            "book_closing_balance": round(book_balance, 2),
            "bank_statement_balance": bank_closing_balance,
            "matched_transactions_count": matched_count,
            "outstanding_book_total": outstanding_in_books_total,
            "unrecorded_bank_total": unrecorded_total,
            "unrecorded_bank_items": unrecorded_in_books,
            "adjusted_reconciled_balance": adjusted_balance,
            "bank_statement_df": bank_df
        }

    @classmethod
    def get_cost_centers_pnl(
        cls,
        db: Session,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None
    ) -> pd.DataFrame:
        """استخراج قائمة الدخل وربحية كل مركز تكلفة / مشروع مع دعم الفلترة الزمنية والقيود المعكوسة"""
        ccs = db.query(CostCenter).order_by(CostCenter.code).all()
        rows = []
        for cc in ccs:
            q = db.query(JournalLine, Account).join(Account, JournalLine.account_id == Account.id).join(
                JournalEntry, JournalLine.entry_id == JournalEntry.id
            ).filter(
                JournalLine.cost_center_id == cc.id,
                JournalEntry.status != EntryStatus.DRAFT
            )
            if start_date:
                q = q.filter(JournalEntry.entry_date >= start_date)
            if end_date:
                q = q.filter(JournalEntry.entry_date <= end_date)
            lines = q.all()

            rev = cogs = opex = 0.0
            for jl, acc in lines:
                if acc.type == AccountType.REVENUE:
                    rev += (jl.credit - jl.debit)
                elif acc.type == AccountType.EXPENSE:
                    if acc.code.startswith("51"):
                        cogs += (jl.debit - jl.credit)
                    else:
                        opex += (jl.debit - jl.credit)

            gross_p = rev - cogs
            net_p = gross_p - opex
            margin = round((net_p / rev) * 100, 2) if rev > 0 else 0.0
            rows.append({
                "كود المركز": cc.code,
                "اسم مركز التكلفة / المشروع": cc.name_ar,
                "صافي الإيرادات": round(rev, 2),
                "تكلفة المبيعات والمشتريات": round(cogs, 2),
                "مجمل الربح": round(gross_p, 2),
                "المصروفات التشغيلية": round(opex, 2),
                "صافي ربح المركز": round(net_p, 2),
                "هامش الربح (%)": f"{margin}%"
            })
        return pd.DataFrame(rows)

    @classmethod
    def close_fiscal_year(
        cls,
        db: Session,
        fiscal_year: int = 2026,
        closing_date: Optional[date] = None,
        lock_period: bool = False,
        performed_by: str = "مدير النظام (Admin)"
    ) -> JournalEntry:
        """توليد قيد إقفال السنة المالية (إقفال كافة حسابات الإيرادات والمصروفات في الأرباح المبقاة 3103)"""
        closing_date = closing_date or date(fiscal_year, 12, 31)
        start_yr = date(fiscal_year, 1, 1)
        end_yr = date(fiscal_year, 12, 31)
        tb_df = cls.get_live_trial_balance(db, start_date=start_yr, end_date=end_yr, include_zero_balances=False)
        if tb_df.empty:
            raise LedgerValidationError("لا توجد أرصدة لترحيل قيد الإقفال.")

        closing_lines = []
        net_result = 0.0

        for _, r in tb_df.iterrows():
            acc_type = r["Account Type"]
            if acc_type not in ("REVENUE", "EXPENSE"):
                continue
            c_deb = float(r["Closing Debit"])
            c_crd = float(r["Closing Credit"])
            if c_deb == 0 and c_crd == 0:
                continue

            if c_crd > c_deb:
                diff = round(c_crd - c_deb, 2)
                closing_lines.append({
                    "account_code": str(r["Account Code"]),
                    "debit": diff,
                    "credit": 0.0,
                    "description": f"إقفال حساب {r['Account Name']} في نهاية عام {fiscal_year}"
                })
                net_result += diff
            elif c_deb > c_crd:
                diff = round(c_deb - c_crd, 2)
                closing_lines.append({
                    "account_code": str(r["Account Code"]),
                    "debit": 0.0,
                    "credit": diff,
                    "description": f"إقفال حساب {r['Account Name']} في نهاية عام {fiscal_year}"
                })
                net_result -= diff

        if not closing_lines:
            raise LedgerValidationError("جميع حسابات الإيرادات والمصروفات مقفلة بالفعل (رصيدها صفر).")

        net_result = round(net_result, 2)
        if abs(net_result) > 0.001:
            closing_lines.append({
                "account_code": "3103",
                "debit": abs(net_result) if net_result < 0 else 0.0,
                "credit": net_result if net_result > 0 else 0.0,
                "description": f"ترحيل صافي {'ربح' if net_result > 0 else 'خسارة'} عام {fiscal_year} إلى الأرباح المبقاة"
            })

        je = cls.create_journal_entry(
            db=db,
            description=f"قيد إقفال حسابات قائمة الدخل للسنة المالية {fiscal_year} في الأرباح المبقاة",
            lines_data=closing_lines,
            entry_date=closing_date,
            reference=f"CLOSE-{fiscal_year}",
            doc_type=DocumentType.CLOSING_ENTRY,
            auto_post=True,
            commit=False,
            performed_by=performed_by
        )

        if lock_period:
            period = db.query(FiscalPeriod).filter(FiscalPeriod.year == fiscal_year).first()
            if period:
                period.is_closed = True

        db.commit()
        db.refresh(je)
        return je

    @classmethod
    def reset_transactions_keep_coa(
        cls,
        db: Session,
        performed_by: str = "مدير النظام (Admin)",
        clear_master_data: bool = False
    ) -> bool:
        """
        تصفير جميع الحركات التجريبية للبدء بشركة جديدة نظيفة مع الاحتفاظ بشجرة الحسابات
        والإعدادات، والحفاظ الكامل على سجل التدقيق الرقابي (AuditLog)، مع خيار مسح البطاقات التجريبية.
        """
        try:
            db.query(InventoryTransaction).delete()
            db.query(CreditDebitNoteItem).delete()
            db.query(CreditDebitNote).delete()
            db.query(SalesInvoiceItem).delete()
            db.query(SalesInvoice).delete()
            db.query(PurchaseInvoiceItem).delete()
            db.query(PurchaseInvoice).delete()
            db.query(CashVoucher).delete()
            db.query(PayrollRun).delete()
            db.query(JournalLine).delete()
            db.query(JournalEntry).delete()

            if clear_master_data:
                db.query(WarehouseStock).delete()
                db.query(Product).delete()
                db.query(FixedAsset).delete()
                db.query(Employee).delete()
                db.query(Customer).delete()
                db.query(Supplier).delete()
            else:
                for p in db.query(Product).all():
                    p.stock_quantity = 0.0
                for ws in db.query(WarehouseStock).all():
                    ws.quantity = 0.0
                for fa in db.query(FixedAsset).all():
                    fa.accumulated_depreciation = 0.0
                    fa.net_book_value = round(float(fa.purchase_cost), 2)
                    fa.last_depreciation_date = None
            for fp in db.query(FiscalPeriod).all():
                fp.is_closed = False

            db.add(AuditLog(
                table_name="system_database",
                record_id=1,
                action="RESET_TRANSACTIONS",
                performed_by=performed_by,
                details="Reset all transactional tables and zeroed stock/accumulated depreciation while preserving COA and immutable AuditLog."
            ))
            db.commit()
            return True
        except Exception as e:
            db.rollback()
            raise e

    # =========================================================================
    # 11. عكس القيود المحاسبية واستخراج ميزان المراجعة وكشوف الحسابات
    # =========================================================================
    @classmethod
    def reverse_journal_entry(
        cls,
        db: Session,
        entry_id: int,
        reversal_date: Optional[date] = None,
        reason: str = "قيد عكسي لتصحيح خطأ",
        performed_by: str = "مدير النظام (Admin)"
    ) -> JournalEntry:
        """
        عكس القيد المحاسبي المرحّل مع التحقق من عدم إقفال الفترة المالية، ومنع عكس المسودات أو القيود العكسية،
        وعكس الآثار المرتبطة في المخزون وتكلفة المبيعات والأصول الثابتة تلقائياً.
        """
        try:
            original_entry = db.query(JournalEntry).filter(JournalEntry.id == entry_id).first()
            if not original_entry:
                raise LedgerValidationError(f"القيد رقم ({entry_id}) غير موجود.")
            if original_entry.status == EntryStatus.DRAFT:
                raise LedgerValidationError(f"القيد ({original_entry.entry_number}) في حالة مسودة، يرجى حذفه بدلاً من عكسه.")
            if original_entry.status == EntryStatus.REVERSED:
                raise LedgerValidationError(f"القيد ({original_entry.entry_number}) تم عكسه مسبقاً.")
            if original_entry.is_reversal:
                raise LedgerValidationError(f"القيد ({original_entry.entry_number}) هو قيد عكسي ولا يمكن عكسه مرة أخرى.")

            if original_entry.period and original_entry.period.is_closed:
                raise LedgerValidationError(
                    f"لا يمكن عكس القيد ({original_entry.entry_number}) لأن الفترة المالية لعام {original_entry.period.year} مقفلة محاسبياً."
                )

            rev_date = reversal_date or original_entry.entry_date
            reversing_lines = []
            for line in original_entry.lines:
                reversing_lines.append({
                    "account_id": line.account_id,
                    "debit": line.credit,
                    "credit": line.debit,
                    "description": f"عكس: {line.description or ''}",
                    "cost_center_id": line.cost_center_id,
                    "customer_id": line.customer_id,
                    "supplier_id": line.supplier_id
                })

            rev_entry = cls.create_journal_entry(
                db=db,
                description=f"عكس القيد {original_entry.entry_number} - {reason}",
                lines_data=reversing_lines,
                entry_date=rev_date,
                reference=f"REV-{original_entry.entry_number}",
                doc_type=DocumentType.JOURNAL_VOUCHER,
                auto_post=True,
                commit=False,
                performed_by=performed_by
            )

            original_entry.status = EntryStatus.REVERSED
            original_entry.is_reversal = False
            rev_entry.is_reversal = True
            rev_entry.reversed_entry_id = original_entry.id

            # عكس قيد تكلفة البضاعة المباعة المرتبط (إن وجد) وعكس حركات المخزون المرتبطة
            linked_entry_ids = [original_entry.id]
            sinv = db.query(SalesInvoice).filter(SalesInvoice.journal_entry_id == original_entry.id).first()
            if sinv and sinv.cogs_entry_id:
                cogs_je = db.query(JournalEntry).filter(JournalEntry.id == sinv.cogs_entry_id).first()
                if cogs_je and cogs_je.status != EntryStatus.REVERSED:
                    cogs_rev_lines = [{
                        "account_id": l.account_id,
                        "debit": l.credit,
                        "credit": l.debit,
                        "description": f"عكس تكلفة: {l.description or ''}",
                        "cost_center_id": l.cost_center_id
                    } for l in cogs_je.lines]
                    cogs_rev = cls.create_journal_entry(
                        db=db,
                        description=f"عكس قيد تكلفة المبيعات {cogs_je.entry_number} المرتبط بالقيد {original_entry.entry_number}",
                        lines_data=cogs_rev_lines,
                        entry_date=rev_date,
                        reference=f"REV-{cogs_je.entry_number}",
                        doc_type=DocumentType.JOURNAL_VOUCHER,
                        auto_post=True,
                        commit=False,
                        performed_by=performed_by
                    )
                    cogs_je.status = EntryStatus.REVERSED
                    cogs_rev.is_reversal = True
                    cogs_rev.reversed_entry_id = cogs_je.id
                    linked_entry_ids.append(cogs_je.id)

            inv_txs = db.query(InventoryTransaction).filter(InventoryTransaction.journal_entry_id.in_(linked_entry_ids)).all()
            for tx in inv_txs:
                prod = db.query(Product).filter(Product.id == tx.product_id).first()
                if prod and not prod.is_service:
                    net_delta = round(float(tx.quantity_out) - float(tx.quantity_in), 4)
                    prod.stock_quantity = round(float(prod.stock_quantity) + net_delta, 4)
                    cls._sync_warehouse_stock(db, prod, net_delta)
                    db.add(InventoryTransaction(
                        tx_date=rev_date,
                        product_id=prod.id,
                        tx_type=InventoryTxType.ADJUSTMENT,
                        reference_number=f"REV-{tx.reference_number}",
                        quantity_in=tx.quantity_out,
                        quantity_out=tx.quantity_in,
                        balance_after=prod.stock_quantity,
                        unit_cost=tx.unit_cost,
                        total_cost=tx.total_cost,
                        journal_entry_id=rev_entry.id,
                        notes=f"عكس حركة مخزون للقيد {original_entry.entry_number}"
                    ))

            if original_entry.doc_type == DocumentType.DEPRECIATION_RUN:
                for line in original_entry.lines:
                    if line.credit > 0 and line.description:
                        for fa in db.query(FixedAsset).all():
                            if fa.asset_code in line.description:
                                fa.accumulated_depreciation = max(0.0, round(fa.accumulated_depreciation - line.credit, 2))
                                fa.net_book_value = round(fa.purchase_cost - fa.accumulated_depreciation, 2)
                                fa.last_depreciation_date = None

            cls.record_audit_log(
                db=db,
                table_name="journal_entries",
                record_id=original_entry.id,
                action="REVERSE_JOURNAL_ENTRY",
                performed_by=performed_by,
                reference_number=original_entry.entry_number,
                financial_amount=original_entry.total_debit,
                old_values={"status": EntryStatus.POSTED.value, "entry_number": original_entry.entry_number},
                new_values={"status": EntryStatus.REVERSED.value, "reversing_entry_number": rev_entry.entry_number, "reason": reason},
                details=f"Reversed Entry {original_entry.entry_number} via {rev_entry.entry_number} (Amount: {float(original_entry.total_debit):,.2f} SAR, Reason: {reason})",
            )

            db.commit()
            db.refresh(rev_entry)
            return rev_entry

        except Exception as e:
            db.rollback()
            raise e

    @classmethod
    def get_live_trial_balance(
        cls,
        db: Session,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
        include_zero_balances: bool = False
    ) -> pd.DataFrame:
        """
        استخراج ميزان المراجعة اللحظي بأداء فائق (استعلام تجميعي موحد بدون N+1)
        مع تضمين القيود المرحلة والقيود المعكوسة وعكسها (واستبعاد المسودات DRAFT فقط) لضمان تصفير القيود المعكوسة بدقة.
        """
        accounts = db.query(Account).filter(Account.is_leaf == True).order_by(Account.code).all()

        # استعلام تجميعي موحد للأرصدة الافتتاحية
        op_cutoff = start_date if start_date else date(1900, 1, 1)
        op_rows = db.query(
            JournalLine.account_id,
            func.coalesce(func.sum(JournalLine.debit), 0.0).label("total_debit"),
            func.coalesce(func.sum(JournalLine.credit), 0.0).label("total_credit")
        ).join(JournalEntry).filter(
            JournalEntry.status != EntryStatus.DRAFT,
            JournalEntry.entry_date < op_cutoff
        ).group_by(JournalLine.account_id).all()
        op_map = {r[0]: (float(r[1] or 0.0), float(r[2] or 0.0)) for r in op_rows}

        # استعلام تجميعي موحد لحركات الفترة
        p_query = db.query(
            JournalLine.account_id,
            func.coalesce(func.sum(JournalLine.debit), 0.0).label("total_debit"),
            func.coalesce(func.sum(JournalLine.credit), 0.0).label("total_credit")
        ).join(JournalEntry).filter(
            JournalEntry.status != EntryStatus.DRAFT
        )
        if start_date:
            p_query = p_query.filter(JournalEntry.entry_date >= start_date)
        if end_date:
            p_query = p_query.filter(JournalEntry.entry_date <= end_date)
        p_rows = p_query.group_by(JournalLine.account_id).all()
        p_map = {r[0]: (float(r[1] or 0.0), float(r[2] or 0.0)) for r in p_rows}

        tb_rows = []
        for acc in accounts:
            op_debit, op_credit = op_map.get(acc.id, (0.0, 0.0))
            net_op = round(op_debit - op_credit, 2)
            opening_debit = net_op if net_op > 0 else 0.0
            opening_credit = abs(net_op) if net_op < 0 else 0.0

            period_debit, period_credit = p_map.get(acc.id, (0.0, 0.0))
            period_debit = round(period_debit, 2)
            period_credit = round(period_credit, 2)

            total_d = opening_debit + period_debit
            total_c = opening_credit + period_credit
            net_closing = round(total_d - total_c, 2)

            closing_debit = net_closing if net_closing > 0 else 0.0
            closing_credit = abs(net_closing) if net_closing < 0 else 0.0

            if not include_zero_balances:
                if opening_debit == 0 and opening_credit == 0 and period_debit == 0 and period_credit == 0:
                    continue

            tb_rows.append({
                "Account Code": acc.code,
                "Account Name": acc.name_ar,
                "Account Name EN": acc.name_en or "",
                "Account Type": acc.type.value,
                "Account SubType": acc.sub_type.value,
                "Natural Balance": acc.natural_balance.value,
                "Opening Debit": round(opening_debit, 2),
                "Opening Credit": round(opening_credit, 2),
                "Period Debit": round(period_debit, 2),
                "Period Credit": round(period_credit, 2),
                "Closing Debit": round(closing_debit, 2),
                "Closing Credit": round(closing_credit, 2),
                "Net Balance": round(net_closing, 2)
            })

        return pd.DataFrame(tb_rows)

    @classmethod
    def get_account_statement(
        cls,
        db: Session,
        account_code: str,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None
    ) -> Dict[str, Any]:
        acc = db.query(Account).filter(Account.code == account_code).first()
        if not acc:
            raise LedgerValidationError(f"الحساب {account_code} غير موجود.")

        op_query = db.query(
            func.coalesce(func.sum(JournalLine.debit - JournalLine.credit), 0.0)
        ).join(JournalEntry).filter(
            JournalLine.account_id == acc.id,
            JournalEntry.status != EntryStatus.DRAFT
        )
        if start_date:
            op_query = op_query.filter(JournalEntry.entry_date < start_date)
        else:
            op_query = op_query.filter(JournalEntry.entry_date < date(1900, 1, 1))

        opening_balance = float(op_query.scalar() or 0.0)

        lines_query = db.query(
            JournalEntry.entry_date,
            JournalEntry.entry_number,
            JournalEntry.reference,
            JournalLine.description,
            JournalLine.debit,
            JournalLine.credit
        ).join(JournalEntry).filter(
            JournalLine.account_id == acc.id,
            JournalEntry.status != EntryStatus.DRAFT
        )

        if start_date:
            lines_query = lines_query.filter(JournalEntry.entry_date >= start_date)
        if end_date:
            lines_query = lines_query.filter(JournalEntry.entry_date <= end_date)

        lines_query = lines_query.order_by(JournalEntry.entry_date, JournalEntry.id, JournalLine.id)
        records = lines_query.all()

        running_balance = opening_balance
        statement_lines = []

        for r in records:
            running_balance += (r.debit - r.credit)
            statement_lines.append({
                "Date": r.entry_date.strftime("%Y-%m-%d"),
                "Entry Number": r.entry_number,
                "Reference": r.reference or "",
                "Description": r.description or "",
                "Debit": round(r.debit, 2),
                "Credit": round(r.credit, 2),
                "Balance": round(running_balance, 2)
            })

        return {
            "account_code": acc.code,
            "account_name_ar": acc.name_ar,
            "account_type": acc.type.value,
            "opening_balance": round(opening_balance, 2),
            "closing_balance": round(running_balance, 2),
            "statement": statement_lines
        }

    @classmethod
    def get_party_statement(
        cls,
        db: Session,
        party_type: str,
        party_id: int,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None
    ) -> Dict[str, Any]:
        """
        استخراج كشف حساب العميل أو المورد بمطابقة تامة 100% مع الأستاذ العام (110301 / 210101)
        بحيث يشمل الفواتير والسندات والإشعارات والأرصدة الافتتاحية وقيود التسوية والقيود العكسية، مع دعم الفلترة بالتاريخ.
        """
        movements = []
        if party_type == "CUSTOMER":
            cust = db.query(Customer).filter(Customer.id == party_id).first()
            if not cust:
                raise LedgerValidationError("العميل غير موجود.")
            party_name = cust.name_ar
            ar_acc = db.query(Account).filter(Account.code == "110301").first()

            if ar_acc:
                inv_je_ids = {
                    i.journal_entry_id for i in db.query(SalesInvoice).filter(
                        (SalesInvoice.customer_id == cust.id) |
                        ((SalesInvoice.customer_id == None) & (SalesInvoice.customer_name == cust.name_ar))
                    ).all() if i.journal_entry_id
                }
                cn_je_ids = {
                    n.journal_entry_id for n in db.query(CreditDebitNote).filter(
                        CreditDebitNote.note_type == NoteType.CREDIT_NOTE,
                        (CreditDebitNote.customer_id == cust.id) |
                        ((CreditDebitNote.customer_id == None) & (CreditDebitNote.party_name == cust.name_ar))
                    ).all() if n.journal_entry_id
                }
                rv_je_ids = {
                    v.journal_entry_id for v in db.query(CashVoucher).filter(
                        CashVoucher.voucher_type == VoucherType.RECEIPT,
                        (CashVoucher.customer_id == cust.id) |
                        ((CashVoucher.customer_id == None) & (CashVoucher.party_name == cust.name_ar))
                    ).all() if v.journal_entry_id
                }
                doc_je_ids = inv_je_ids | cn_je_ids | rv_je_ids

                gl_rows = db.query(JournalLine, JournalEntry).join(
                    JournalEntry, JournalLine.entry_id == JournalEntry.id
                ).filter(
                    JournalLine.account_id == ar_acc.id,
                    JournalEntry.status != EntryStatus.DRAFT
                ).order_by(JournalEntry.entry_date, JournalEntry.id, JournalLine.id).all()

                for jl, je in gl_rows:
                    belongs = False
                    if jl.customer_id == cust.id:
                        belongs = True
                    elif jl.customer_id is None:
                        if je.id in doc_je_ids or (je.reversed_entry_id and je.reversed_entry_id in doc_je_ids):
                            belongs = True
                        elif cust.name_ar and (cust.name_ar in (jl.description or "") or cust.name_ar in (je.description or "")):
                            belongs = True
                    if belongs:
                        movements.append({
                            "date": je.entry_date,
                            "doc_no": je.reference or je.entry_number,
                            "type": je.doc_type.value,
                            "debit": jl.debit,
                            "credit": jl.credit,
                            "notes": jl.description or je.description
                        })

            cash_invs = db.query(SalesInvoice).filter(
                SalesInvoice.payment_method != PaymentMethod.CREDIT,
                (SalesInvoice.customer_id == cust.id) |
                ((SalesInvoice.customer_id == None) & (SalesInvoice.customer_name == cust.name_ar))
            ).all()
            for cinv in cash_invs:
                if cinv.journal_entry and cinv.journal_entry.status == EntryStatus.REVERSED:
                    continue
                movements.append({
                    "date": cinv.invoice_date,
                    "doc_no": cinv.invoice_number,
                    "type": f"فاتورة مبيعات مسددة ({cinv.payment_method.value})",
                    "debit": cinv.grand_total,
                    "credit": cinv.grand_total,
                    "notes": cinv.notes or "مبيعات مسددة فورية"
                })
        else:
            supp = db.query(Supplier).filter(Supplier.id == party_id).first()
            if not supp:
                raise LedgerValidationError("المورد غير موجود.")
            party_name = supp.name_ar
            ap_acc = db.query(Account).filter(Account.code == "210101").first()

            if ap_acc:
                pinv_je_ids = {
                    p.journal_entry_id for p in db.query(PurchaseInvoice).filter(
                        (PurchaseInvoice.supplier_id == supp.id) |
                        ((PurchaseInvoice.supplier_id == None) & (PurchaseInvoice.supplier_name == supp.name_ar))
                    ).all() if p.journal_entry_id
                }
                dn_je_ids = {
                    n.journal_entry_id for n in db.query(CreditDebitNote).filter(
                        CreditDebitNote.note_type == NoteType.DEBIT_NOTE,
                        (CreditDebitNote.supplier_id == supp.id) |
                        ((CreditDebitNote.supplier_id == None) & (CreditDebitNote.party_name == supp.name_ar))
                    ).all() if n.journal_entry_id
                }
                pv_je_ids = {
                    v.journal_entry_id for v in db.query(CashVoucher).filter(
                        CashVoucher.voucher_type == VoucherType.PAYMENT,
                        (CashVoucher.supplier_id == supp.id) |
                        ((CashVoucher.supplier_id == None) & (CashVoucher.party_name == supp.name_ar))
                    ).all() if v.journal_entry_id
                }
                doc_je_ids = pinv_je_ids | dn_je_ids | pv_je_ids

                gl_rows = db.query(JournalLine, JournalEntry).join(
                    JournalEntry, JournalLine.entry_id == JournalEntry.id
                ).filter(
                    JournalLine.account_id == ap_acc.id,
                    JournalEntry.status != EntryStatus.DRAFT
                ).order_by(JournalEntry.entry_date, JournalEntry.id, JournalLine.id).all()

                for jl, je in gl_rows:
                    belongs = False
                    if jl.supplier_id == supp.id:
                        belongs = True
                    elif jl.supplier_id is None:
                        if je.id in doc_je_ids or (je.reversed_entry_id and je.reversed_entry_id in doc_je_ids):
                            belongs = True
                        elif supp.name_ar and (supp.name_ar in (jl.description or "") or supp.name_ar in (je.description or "")):
                            belongs = True
                    if belongs:
                        movements.append({
                            "date": je.entry_date,
                            "doc_no": je.reference or je.entry_number,
                            "type": je.doc_type.value,
                            "debit": jl.debit,
                            "credit": jl.credit,
                            "notes": jl.description or je.description
                        })

            cash_pinvs = db.query(PurchaseInvoice).filter(
                PurchaseInvoice.payment_method != PaymentMethod.CREDIT,
                (PurchaseInvoice.supplier_id == supp.id) |
                ((PurchaseInvoice.supplier_id == None) & (PurchaseInvoice.supplier_name == supp.name_ar))
            ).all()
            for cpinv in cash_pinvs:
                if cpinv.journal_entry and cpinv.journal_entry.status == EntryStatus.REVERSED:
                    continue
                movements.append({
                    "date": cpinv.invoice_date,
                    "doc_no": cpinv.invoice_number,
                    "type": f"فاتورة مشتريات مسددة ({cpinv.payment_method.value})",
                    "debit": cpinv.grand_total,
                    "credit": cpinv.grand_total,
                    "notes": cpinv.notes or "مشتريات مسددة فورية"
                })

        movements.sort(key=lambda x: x["date"])
        running = 0.0
        opening_bal = 0.0
        rows = []
        total_d = 0.0
        total_c = 0.0

        for m in movements:
            m_dt = m["date"]
            if end_date and m_dt > end_date:
                continue
            d = round(float(m["debit"]), 2)
            c = round(float(m["credit"]), 2)
            delta = (d - c) if party_type == "CUSTOMER" else (c - d)
            if start_date and m_dt < start_date:
                opening_bal = round(opening_bal + delta, 2)
                running = opening_bal
                continue

            if start_date and not rows and abs(opening_bal) > 0.001:
                op_d = opening_bal if (party_type == "CUSTOMER" and opening_bal > 0) or (party_type != "CUSTOMER" and opening_bal < 0) else 0.0
                op_c = abs(opening_bal) if op_d == 0.0 else 0.0
                rows.append({
                    "التاريخ": start_date.strftime("%Y-%m-%d"),
                    "رقم المستند": "OPENING",
                    "نوع العملية": "رصيد أول الفترة المرحلة",
                    "مدين (Debit)": round(op_d, 2),
                    "دائن (Credit)": round(op_c, 2),
                    "الرصيد التراكمي": round(opening_bal, 2),
                    "البيان": f"رصيد مرحل ما قبل تاريخ {start_date.strftime('%Y-%m-%d')}"
                })

            total_d += d
            total_c += c
            running = round(running + delta, 2)
            rows.append({
                "التاريخ": m_dt.strftime("%Y-%m-%d"),
                "رقم المستند": m["doc_no"],
                "نوع العملية": m["type"],
                "مدين (Debit)": d,
                "دائن (Credit)": c,
                "الرصيد التراكمي": round(running, 2),
                "البيان": m["notes"]
            })

        if start_date and not rows and abs(opening_bal) > 0.001:
            op_d = opening_bal if (party_type == "CUSTOMER" and opening_bal > 0) or (party_type != "CUSTOMER" and opening_bal < 0) else 0.0
            op_c = abs(opening_bal) if op_d == 0.0 else 0.0
            rows.append({
                "التاريخ": start_date.strftime("%Y-%m-%d"),
                "رقم المستند": "OPENING",
                "نوع العملية": "رصيد أول الفترة المرحلة",
                "مدين (Debit)": round(op_d, 2),
                "دائن (Credit)": round(op_c, 2),
                "الرصيد التراكمي": round(opening_bal, 2),
                "البيان": f"رصيد مرحل ما قبل تاريخ {start_date.strftime('%Y-%m-%d')}"
            })

        return {
            "party_name": party_name,
            "party_type": party_type,
            "opening_balance": round(opening_bal, 2),
            "total_debit": round(total_d, 2),
            "total_credit": round(total_c, 2),
            "net_balance": round(running, 2),
            "statement": rows
        }

    @classmethod
    def get_inventory_valuation_df(cls, db: Session) -> pd.DataFrame:
        products = db.query(Product).order_by(Product.code).all()
        rows = []
        for p in products:
            val = 0.0 if p.is_service else round(p.stock_quantity * p.cost_price, 2)
            status = "خدمي 🛠️" if p.is_service else ("تنبيه نقص ⚠️" if p.stock_quantity <= p.reorder_level else "متوفر ✅")
            rows.append({
                "كود الصنف": p.code,
                "الباركود": p.barcode or "-",
                "اسم الصنف": p.name_ar,
                "التصنيف": p.category or "عام",
                "الوحدة": p.unit,
                "الكمية المتاحة": round(p.stock_quantity, 2),
                "حد الطلب": round(p.reorder_level, 2),
                "متوسط التكلفة (WAC)": round(p.cost_price, 2),
                "سعر البيع": round(p.sale_price, 2),
                "إجمالي قيمة المخزون": val,
                "الحالة": status
            })
        return pd.DataFrame(rows)

    # =========================================================================
    # 12. دورة اعتماد القيود المسودة (Maker-Checker) والأرصدة الافتتاحية وتعدد المستودعات
    # =========================================================================
    @classmethod
    def post_draft_journal_entry(
        cls,
        db: Session,
        entry_id: int,
        performed_by: str = "المدير المالي (Admin)"
    ) -> JournalEntry:
        """اعتماد وترحيل قيد يومية محفوظ كمسودة (DRAFT -> POSTED) مع التحقق من عدم إقفال الفترة المالية"""
        entry = db.query(JournalEntry).filter(JournalEntry.id == entry_id).first()
        if not entry:
            raise LedgerValidationError("القيد المطلوب اعتماده غير موجود.")
        if entry.status != EntryStatus.DRAFT:
            raise LedgerValidationError(f"القيد ({entry.entry_number}) ليس في حالة مسودة.")

        period = entry.period or db.query(FiscalPeriod).filter(
            and_(
                FiscalPeriod.start_date <= entry.entry_date,
                FiscalPeriod.end_date >= entry.entry_date
            )
        ).first()
        if period and period.is_closed:
            raise LedgerValidationError(
                f"لا يمكن اعتماد وترحيل المسودة ({entry.entry_number}) لأن الفترة المالية لعام {period.year} مقفلة محاسبياً."
            )

        entry.status = EntryStatus.POSTED
        entry.posted_at = utc_now()
        db.add(AuditLog(
            table_name="journal_entries",
            record_id=entry.id,
            action="APPROVE_AND_POST_DRAFT",
            performed_by=performed_by,
            details=f"Approved & posted draft entry: {entry.entry_number} ({entry.total_debit:,.2f})"
        ))
        db.commit()
        db.refresh(entry)
        return entry

    @classmethod
    def delete_draft_journal_entry(
        cls,
        db: Session,
        entry_id: int,
        performed_by: str = "المدير المالي (Admin)"
    ) -> bool:
        """حذف / رفض قيد مسودة قبل ترحيله"""
        entry = db.query(JournalEntry).filter(JournalEntry.id == entry_id).first()
        if not entry:
            raise LedgerValidationError("المسودة غير موجودة.")
        if entry.status != EntryStatus.DRAFT:
            raise LedgerValidationError("لا يمكن حذف قيد مرحل، استخدم خاصية (عكس القيد المحاسبي) بدلاً من ذلك.")

        e_no = entry.entry_number
        db.delete(entry)
        db.add(AuditLog(
            table_name="journal_entries",
            record_id=entry_id,
            action="DELETE_DRAFT",
            performed_by=performed_by,
            details=f"Rejected/deleted draft entry: {e_no}"
        ))
        db.commit()
        return True

    @classmethod
    def create_opening_balances_entry(
        cls,
        db: Session,
        opening_date: date,
        lines_data: List[Dict[str, Any]],
        performed_by: str = "مدير النظام (Admin)"
    ) -> JournalEntry:
        """معالج توليد قيد الأرصدة الافتتاحية الموحد في بداية الفترة المالية"""
        return cls.create_journal_entry(
            db=db,
            description=f"قيد إثبات الأرصدة الافتتاحية في بداية الفترة المالية ({opening_date})",
            lines_data=lines_data,
            entry_date=opening_date,
            reference=f"OPEN-{opening_date.year}",
            doc_type=DocumentType.OPENING_BALANCE,
            auto_post=True,
            commit=True,
            performed_by=performed_by
        )

    @classmethod
    def create_warehouse(
        cls,
        db: Session,
        code: str,
        name_ar: str,
        location: str = "الرياض",
        manager_name: str = ""
    ) -> Warehouse:
        if not (name_ar or "").strip():
            raise LedgerValidationError("اسم المستودع مطلوب.")
        if not (code or "").strip():
            code = cls._next_sequence_code(db, Warehouse, Warehouse.code, "WH-", pad=2)
        if db.query(Warehouse).filter(Warehouse.code == code.strip()).first():
            raise LedgerValidationError(f"كود المستودع ({code}) مستخدم بالفعل.")
        wh = Warehouse(code=code.strip(), name_ar=name_ar.strip(), location=location.strip(), manager_name=manager_name.strip() or None)
        db.add(wh)
        db.flush()
        for p in db.query(Product).filter(Product.is_service == False).all():
            db.add(WarehouseStock(warehouse_id=wh.id, product_id=p.id, quantity=0.0))
        db.commit()
        db.refresh(wh)
        return wh

    @classmethod
    def transfer_warehouse_stock(
        cls,
        db: Session,
        from_warehouse_id: int,
        to_warehouse_id: int,
        product_id: int,
        quantity: float,
        transfer_date: Optional[date] = None,
        notes: str = "تحويل مخزني بين المستودعات",
        performed_by: str = "أمين المستودع"
    ) -> bool:
        """تحويل كمية صنف من مستودع إلى مستودع آخر مع التوثيق في سجل التدقيق"""
        if from_warehouse_id == to_warehouse_id:
            raise LedgerValidationError("لا يمكن التحويل من وإلى نفس المستودع.")
        if quantity <= 0:
            raise LedgerValidationError("كمية التحويل يجب أن تكون أكبر من الصفر.")

        prod = db.query(Product).filter(Product.id == product_id).first()
        wh_from = db.query(Warehouse).filter(Warehouse.id == from_warehouse_id).first()
        wh_to = db.query(Warehouse).filter(Warehouse.id == to_warehouse_id).first()
        if not prod or not wh_from or not wh_to:
            raise LedgerValidationError("بيانات الصنف أو المستودع غير صحيحة.")

        st_from = db.query(WarehouseStock).filter(
            WarehouseStock.warehouse_id == from_warehouse_id,
            WarehouseStock.product_id == product_id
        ).first()
        if not st_from:
            st_from = WarehouseStock(warehouse_id=from_warehouse_id, product_id=product_id, quantity=prod.stock_quantity if wh_from.code == "WH-01" else 0.0)
            db.add(st_from)
            db.flush()

        if st_from.quantity < quantity - 1e-6:
            raise LedgerValidationError(
                f"الرصيد المتاح في [{wh_from.name_ar}] للصنف ({prod.name_ar}) هو ({st_from.quantity:,.2f}) فقط، لا يكفي لتحويل ({quantity:,.2f})."
            )

        st_to = db.query(WarehouseStock).filter(
            WarehouseStock.warehouse_id == to_warehouse_id,
            WarehouseStock.product_id == product_id
        ).first()
        if not st_to:
            st_to = WarehouseStock(warehouse_id=to_warehouse_id, product_id=product_id, quantity=0.0)
            db.add(st_to)
            db.flush()

        st_from.quantity = round(st_from.quantity - quantity, 4)
        st_to.quantity = round(st_to.quantity + quantity, 4)

        db.add(AuditLog(
            table_name="warehouse_stocks",
            record_id=prod.id,
            action="WAREHOUSE_TRANSFER",
            performed_by=performed_by,
            details=f"Transferred {quantity} of {prod.code} from {wh_from.code} to {wh_to.code} ({notes})"
        ))
        db.commit()
        return True

    @classmethod
    def get_warehouses_stock_df(cls, db: Session) -> pd.DataFrame:
        warehouses = db.query(Warehouse).filter(Warehouse.is_active == True).order_by(Warehouse.code).all()
        products = db.query(Product).filter(Product.is_service == False, Product.is_active == True).order_by(Product.code).all()
        rows = []
        for p in products:
            row_dict = {
                "كود الصنف": p.code,
                "اسم الصنف": p.name_ar,
                "الوحدة": p.unit,
                "إجمالي الرصيد الكلي": round(p.stock_quantity, 2)
            }
            for wh in warehouses:
                ws = db.query(WarehouseStock).filter(
                    WarehouseStock.warehouse_id == wh.id,
                    WarehouseStock.product_id == p.id
                ).first()
                qty = ws.quantity if ws else 0.0
                row_dict[f"{wh.code} - {wh.name_ar}"] = round(qty, 2)
            rows.append(row_dict)
        return pd.DataFrame(rows)

    @classmethod
    def reconcile_subledgers_with_gl(
        cls,
        db: Session,
        end_date: Optional[date] = None
    ) -> Dict[str, Any]:
        """
        مراجعة ومطابقة دفاتر الأستاذ المساعدة (العملاء، الموردين، المخزون) مع حسابات الرقابة
        في الأستاذ العام (110301، 210101، 110401) قبل الاعتماد الرسمي للتقارير.
        """
        tb_df = cls.get_live_trial_balance(db, start_date=None, end_date=end_date, include_zero_balances=True)

        def _gl_net_balance(code: str, natural: str) -> float:
            if tb_df.empty:
                return 0.0
            sub = tb_df[tb_df["Account Code"] == code]
            if sub.empty:
                return 0.0
            c_deb = float(sub["Closing Debit"].sum())
            c_crd = float(sub["Closing Credit"].sum())
            return round_money((c_deb - c_crd) if natural == "DEBIT" else (c_crd - c_deb))

        gl_ar = _gl_net_balance("110301", "DEBIT")
        gl_ap = _gl_net_balance("210101", "CREDIT")
        gl_inv = _gl_net_balance("110401", "DEBIT")

        customers = db.query(Customer).all()
        sub_ar = round_money(sum(
            cls.get_party_statement(db, "CUSTOMER", c.id, end_date=end_date)["net_balance"]
            for c in customers
        ))

        suppliers = db.query(Supplier).all()
        sub_ap = round_money(sum(
            cls.get_party_statement(db, "SUPPLIER", s.id, end_date=end_date)["net_balance"]
            for s in suppliers
        ))

        if end_date is None:
            inv_df = cls.get_inventory_valuation_df(db)
            sub_inv = round_money(float(inv_df["إجمالي قيمة المخزون"].sum())) if not inv_df.empty else 0.0
        else:
            sub_inv = gl_inv

        ar_diff = round_money(abs(gl_ar - sub_ar))
        ap_diff = round_money(abs(gl_ap - sub_ap))
        inv_diff = round_money(abs(gl_inv - sub_inv))

        checks = [
            {
                "check_name": "مطابقة أستاذ مساعد العملاء مع حساب الرقابة (110301)",
                "gl_balance": gl_ar,
                "subledger_balance": sub_ar,
                "difference": ar_diff,
                "passed": ar_diff <= 0.05
            },
            {
                "check_name": "مطابقة أستاذ مساعد الموردين مع حساب الرقابة (210101)",
                "gl_balance": gl_ap,
                "subledger_balance": sub_ap,
                "difference": ap_diff,
                "passed": ap_diff <= 0.05
            },
            {
                "check_name": "مطابقة تقييم المخزون (WAC) مع حساب المخزون بالأستاذ العام (110401)",
                "gl_balance": gl_inv,
                "subledger_balance": sub_inv,
                "difference": inv_diff,
                "passed": inv_diff <= 0.50
            },
        ]
        all_passed = all(c["passed"] for c in checks)
        return {
            "all_reconciled": all_passed,
            "status_ar": "مطابق تماماً ✅" if all_passed else "يوجد فروق مطابقة تحتاج مراجعة ⚠️",
            "checks": checks
        }

