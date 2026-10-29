"""
MizanPro - ZATCA Phase 2 Base64 TLV QR Code Generator & Decoder Utility
أداة توليد وفك تشفير رمز الاستجابة السريعة (QR Code) بصيغة TLV Base64 لهيئة الزكاة والضريبة والجمارك
====================================================================================================
توفر هذه الوحدة أداة معيارية موحدة لتوليد وفك تشفير والتحقق من رموز الاستجابة السريعة (QR Codes)
المشفرة بصيغة (Tag-Length-Value Base64) لكافة الفواتير الضريبية (المبيعات، المشتريات، الإشعارات الدائنة والمدينة):
- Tag 1: اسم البائع (Seller Name - UTF-8)
- Tag 2: الرقم الضريبي للبائع (VAT Registration Number - 15 digits starting and ending with '3')
- Tag 3: الطابع الزمني للفاتورة (Invoice Timestamp - ISO-8601 YYYY-MM-DDTHH:MM:SSZ)
- Tag 4: إجمالي الفاتورة شامل ضريبة القيمة المضافة (Invoice Total with VAT - 0.00 ROUND_HALF_UP)
- Tag 5: إجمالي ضريبة القيمة المضافة (VAT Total Amount - 0.00 ROUND_HALF_UP)
- Tag 6: تجزئة الفاتورة الإلكترونية (SHA-256 Hash of Canonical UBL 2.1 XML - Phase 2)
- Tag 7: التوقيع الرقمي المشفر (ECDSA Digital Signature - Phase 2)
- Tag 8: المفتاح العام للتشفير (ECDSA secp256k1 Public Key DER - Phase 2)
- Tag 9: ختم شهادة التشفير الضريبية (Cryptographic Stamp CSID Signature - Phase 2)
"""

import base64
import re
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Union

from models import (
    CashVoucher,
    CompanySettings,
    CreditDebitNote,
    InvoiceType,
    NoteType,
    PurchaseInvoice,
    SalesInvoice,
    VoucherType,
    quantize_money,
    round_money,
    to_decimal,
)
from zatca_phase2_validator import (
    ZATCA_GENESIS_PIH,
    ZATCA_TLV_TAG_SPECS,
    ZATCAPhase2Validator,
)


class ZATCATLVEncodingError(ValueError):
    """استثناء مخصص لأخطاء التحقق أو الترميز الثنائي لباركود الفاتورة الإلكترونية (ZATCA TLV QR)"""
    pass


def encode_tlv_tag(tag: int, value: Union[str, bytes]) -> bytes:
    """
    ترميز حقل واحد بصيغة TLV الثنائية القياسية لهيئة الزكاة والضريبة والجمارك:
    [Tag (1 Byte)] + [Length (1..3 Bytes BER-TLV)] + [Value (UTF-8 or Raw Bytes)]
    """
    if not (1 <= int(tag) <= 255):
        raise ZATCATLVEncodingError(f"رقم الحقل (Tag={tag}) خارج النطاق المسموح (1..255).")

    if isinstance(value, str):
        value_bytes = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray)):
        value_bytes = bytes(value)
    else:
        value_bytes = str(value).encode("utf-8")

    return ZATCAPhase2Validator._encode_tlv_field(int(tag), value_bytes)


def format_zatca_timestamp(timestamp: Union[str, datetime, date, None] = None) -> str:
    """
    تحويل وتوحيد الطابع الزمني للفاتورة إلى صيغة ISO-8601 القياسية المعتمدة لدى ZATCA:
    YYYY-MM-DDTHH:MM:SSZ
    """
    if timestamp is None:
        now_utc = datetime.now(timezone.utc)
        return now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    if isinstance(timestamp, datetime):
        return timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")

    if isinstance(timestamp, date):
        return datetime(timestamp.year, timestamp.month, timestamp.day, 12, 0, 0).strftime("%Y-%m-%dT%H:%M:%SZ")

    ts_str = str(timestamp).strip()
    if not ts_str:
        raise ZATCATLVEncodingError("الطابع الزمني للفاتورة (Timestamp - Tag 3) لا يمكن أن يكون فارغاً.")

    # إذا كان التاريخ فقط بصيغة YYYY-MM-DD
    if re.match(r"^\d{4}-\d{2}-\d{2}$", ts_str):
        return f"{ts_str}T12:00:00Z"

    # إذا كان بصيغة YYYY-MM-DD HH:MM:SS أو YYYY-MM-DDTHH:MM:SS
    normalized = ts_str.replace(" ", "T")
    if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?$", normalized):
        return normalized[:19] + "Z"

    if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$", normalized):
        if normalized.endswith("Z"):
            return normalized[:19] + "Z"
        return normalized

    raise ZATCATLVEncodingError(
        f"صيغة الطابع الزمني ('{ts_str}') غير صالحة لمعيار ZATCA ISO-8601 (المطلوب: YYYY-MM-DDTHH:MM:SSZ)."
    )


def _parse_iso_to_datetime(iso_str: str) -> datetime:
    """تحويل سلسلة ISO-8601 الموحدة إلى كائن datetime لتمريره لمحرك UBL 2.1 XML"""
    clean = iso_str.strip().replace(" ", "T")[:19]
    try:
        return datetime.strptime(clean, "%Y-%m-%dT%H:%M:%S")
    except ValueError as exc:
        raise ZATCATLVEncodingError(f"تعذر تحليل الطابع الزمني '{iso_str}': {exc}") from exc


def format_zatca_amount(amount: Union[Decimal, float, int, str]) -> str:
    """
    تنسيق المبالغ المالية والضريبية بدقة منزلتين عشريتين (0.00) باستخدام التقريب المحاسبي
    القياسي (Decimal ROUND_HALF_UP) وفق متطلبات حقلي Tag 4 و Tag 5 في ZATCA.
    """
    if amount is None or (isinstance(amount, str) and not amount.strip()):
        raise ZATCATLVEncodingError("المبلغ المالي في باركود ZATCA لا يمكن أن يكون فارغاً.")
    try:
        dec_val = quantize_money(amount)
    except Exception as exc:
        raise ZATCATLVEncodingError(f"قيمة المبلغ المالي ('{amount}') غير صالحة.") from exc
    return f"{dec_val:.2f}"


def generate_zatca_tlv_qr_base64(
    seller_name: str,
    vat_number: str,
    timestamp: Union[str, datetime, date],
    invoice_total: Union[Decimal, float, int, str],
    vat_total: Optional[Union[Decimal, float, int, str]] = None,
    phase2: bool = True,
    doc_number: str = "INV-2026-0001",
    doc_type_code: str = "388",
    subtype_code: str = "0200000",
    buyer_name: str = "عميل نقدي",
    buyer_vat: str = "",
    icv: int = 1,
    pih: str = ZATCA_GENESIS_PIH,
    billing_reference: Optional[str] = None,
    reason: Optional[str] = None,
) -> str:
    """
    توليد سلسلة Base64 لرمز الاستجابة السريعة (QR Code) بصيغة TLV المتوافقة مع ZATCA Phase 2:
    - يتحقق بصرامة من:
      1. اسم البائع (Tag 1 - UTF-8 غير فارغ)
      2. الرقم الضريبي السعودي للبائع (Tag 2 - 15 رقماً يبدأ وينتهي بـ 3)
      3. الطابع الزمني القياسي (Tag 3 - ISO-8601)
      4. إجمالي الفاتورة مع الضريبة (Tag 4 - منزلتان عشريتان ROUND_HALF_UP)
      5. إجمالي ضريبة القيمة المضافة (Tag 5 - منزلتان عشريتان؛ وإذا لم يُمرر يُحسب تلقائياً بنسبة 15% من الإجمالي)
      6. حقول التشفير للمرحلة الثانية (Tags 6..9: تجزئة XML SHA-256، توقيع ECDSA، المفتاح العام، وختم CSID)
    """
    clean_seller = (seller_name or "").strip()
    if len(clean_seller) < 2:
        raise ZATCATLVEncodingError("اسم البائع (Seller Name - Tag 1) إلزامي ويجب ألا يقل عن حرفين.")

    vat_check = ZATCAPhase2Validator.validate_saudi_vat_number(vat_number, party_role="SELLER", required=True)
    if not vat_check["is_valid"]:
        raise ZATCATLVEncodingError(vat_check["message_ar"])
    clean_vat = vat_check["clean_vat"]

    iso_ts = format_zatca_timestamp(timestamp)
    inv_dt = _parse_iso_to_datetime(iso_ts)

    total_str = format_zatca_amount(invoice_total)
    total_dec = quantize_money(total_str)
    if total_dec < Decimal("0.00"):
        raise ZATCATLVEncodingError("إجمالي الفاتورة (Invoice Total - Tag 4) لا يمكن أن يكون سالباً.")

    if vat_total is None:
        # استخراج الضريبة الضمنية 15% من الإجمالي الشامل للضريبة وفق قاعدة التقريب ROUND_HALF_UP
        net_est = quantize_money(to_decimal(total_dec) / Decimal("1.15"))
        vat_dec = quantize_money(total_dec - net_est)
    else:
        vat_str = format_zatca_amount(vat_total)
        vat_dec = quantize_money(vat_str)

    if vat_dec < Decimal("0.00") or vat_dec > total_dec:
        raise ZATCATLVEncodingError(
            f"مبلغ ضريبة القيمة المضافة ({vat_dec:.2f}) غير منطقي مقارنة بإجمالي الفاتورة ({total_dec:.2f})."
        )

    if phase2:
        artifacts = ZATCAPhase2Validator.generate_phase2_crypto_artifacts(
            seller_name=clean_seller,
            seller_vat=clean_vat,
            invoice_datetime=inv_dt,
            total_amount=total_dec,
            vat_amount=vat_dec,
            doc_number=doc_number,
            doc_type_code=doc_type_code,
            subtype_code=subtype_code,
            buyer_name=buyer_name,
            buyer_vat=buyer_vat,
            icv=icv,
            pih=pih,
            billing_reference=billing_reference,
            reason=reason,
        )
        return artifacts["tlv_base64"]

    # المرحلة الأولى فقط (Tags 1..5) عند طلب phase2=False صراحةً
    tlv_bytes = (
        encode_tlv_tag(1, clean_seller)
        + encode_tlv_tag(2, clean_vat)
        + encode_tlv_tag(3, iso_ts)
        + encode_tlv_tag(4, f"{total_dec:.2f}")
        + encode_tlv_tag(5, f"{vat_dec:.2f}")
    )
    return base64.b64encode(tlv_bytes).decode("utf-8")


def decode_zatca_tlv_qr_base64(tlv_base64: Optional[str]) -> Dict[str, Any]:
    """
    فك تشفير سلسلة Base64 لباركود ZATCA TLV وإرجاع كافة الحقول المستخرجة (Tags 1..9)
    مع أسماء الحقول المباشرة (seller_name, vat_number, timestamp, invoice_total, vat_total)
    والتمثيل الست عشري (Hex Dump) وحالة التحقق.
    """
    decoded = ZATCAPhase2Validator.decode_zatca_tlv(tlv_base64)
    tags = decoded.get("tags", {})

    seller_name = tags.get(1, {}).get("value", "")
    vat_number = tags.get(2, {}).get("value", "")
    timestamp = tags.get(3, {}).get("value", "")
    invoice_total = tags.get(4, {}).get("value", "")
    vat_total = tags.get(5, {}).get("value", "")
    xml_hash_b64 = tags.get(6, {}).get("value", "")
    ecdsa_signature = tags.get(7, {}).get("value", "")
    public_key_b64 = tags.get(8, {}).get("value", "")
    csid_stamp_b64 = tags.get(9, {}).get("value", "")

    raw_hex = ""
    if decoded.get("is_valid_tlv") and tlv_base64:
        try:
            raw_hex = base64.b64decode(str(tlv_base64).strip()).hex().upper()
        except Exception:
            raw_hex = ""

    return {
        "is_valid_tlv": decoded.get("is_valid_tlv", False),
        "error": decoded.get("error"),
        "raw_byte_length": decoded.get("raw_byte_length", 0),
        "raw_hex": raw_hex,
        "has_phase1_tags": decoded.get("has_phase1_tags", False),
        "has_phase2_tags": decoded.get("has_phase2_tags", False),
        "seller_name": seller_name,
        "vat_number": vat_number,
        "timestamp": timestamp,
        "invoice_total": invoice_total,
        "vat_total": vat_total,
        "xml_hash_b64": xml_hash_b64,
        "ecdsa_signature": ecdsa_signature,
        "public_key_b64": public_key_b64,
        "csid_stamp_b64": csid_stamp_b64,
        "tags": tags,
    }


class ZATCATLVQRGenerator:
    """
    الواجهة الموحدة لتوليد وفك تشفير وفحص رموز الاستجابة السريعة (ZATCA Phase 2 Base64 TLV QR Codes)
    لجميع أنواع الفواتير والمستندات الضريبية في النظام.
    """

    @staticmethod
    def generate_base64(
        seller_name: str,
        vat_number: str,
        timestamp: Union[str, datetime, date],
        invoice_total: Union[Decimal, float, int, str],
        vat_total: Optional[Union[Decimal, float, int, str]] = None,
        phase2: bool = True,
        doc_number: str = "INV-2026-0001",
        doc_type_code: str = "388",
        subtype_code: str = "0200000",
        buyer_name: str = "عميل نقدي",
        buyer_vat: str = "",
        icv: int = 1,
        pih: str = ZATCA_GENESIS_PIH,
        billing_reference: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> str:
        return generate_zatca_tlv_qr_base64(
            seller_name=seller_name,
            vat_number=vat_number,
            timestamp=timestamp,
            invoice_total=invoice_total,
            vat_total=vat_total,
            phase2=phase2,
            doc_number=doc_number,
            doc_type_code=doc_type_code,
            subtype_code=subtype_code,
            buyer_name=buyer_name,
            buyer_vat=buyer_vat,
            icv=icv,
            pih=pih,
            billing_reference=billing_reference,
            reason=reason,
        )

    @staticmethod
    def decode_base64(tlv_base64: Optional[str]) -> Dict[str, Any]:
        return decode_zatca_tlv_qr_base64(tlv_base64)

    @classmethod
    def generate_for_invoice(
        cls,
        invoice_obj: Any,
        settings: Optional[CompanySettings] = None,
        icv: int = 1,
        pih: str = ZATCA_GENESIS_PIH,
    ) -> Dict[str, Any]:
        """
        توليد حزمة باركود ZATCA Phase 2 TLV Base64 لأي فاتورة في النظام
        (SalesInvoice, PurchaseInvoice, CreditDebitNote, CashVoucher أو dict).
        """
        comp_name = (settings.company_name_ar if settings else "شركة ميزان برو التجارية").strip()
        comp_vat = (settings.vat_number if settings else "300000000000003").strip()

        if isinstance(invoice_obj, SalesInvoice):
            seller_name = comp_name
            vat_number = comp_vat
            inv_dt = invoice_obj.created_at or datetime.combine(invoice_obj.invoice_date, datetime.min.time())
            invoice_total = quantize_money(invoice_obj.grand_total)
            vat_total = quantize_money(invoice_obj.vat_amount)
            doc_number = invoice_obj.invoice_number
            doc_type_code = "388"
            subtype_code = "0100000" if invoice_obj.invoice_type == InvoiceType.STANDARD else "0200000"
            buyer_name = (invoice_obj.customer_name or "عميل نقدي").strip()
            buyer_vat = (invoice_obj.customer_vat_number or "").strip()
            billing_ref = None
            reason = None
        elif isinstance(invoice_obj, PurchaseInvoice):
            supp_vat_raw = (invoice_obj.supplier_vat_number or "").strip()
            supp_vat_chk = ZATCAPhase2Validator.validate_saudi_vat_number(supp_vat_raw, party_role="SUPPLIER", required=False)
            seller_name = (invoice_obj.supplier_name or comp_name).strip()
            vat_number = supp_vat_chk["clean_vat"] if (supp_vat_raw and supp_vat_chk["is_valid"]) else comp_vat
            inv_dt = invoice_obj.created_at or datetime.combine(invoice_obj.invoice_date, datetime.min.time())
            invoice_total = quantize_money(invoice_obj.grand_total)
            vat_total = quantize_money(invoice_obj.vat_amount)
            doc_number = invoice_obj.invoice_number
            doc_type_code = "388"
            subtype_code = "0100000"
            buyer_name = comp_name
            buyer_vat = comp_vat
            billing_ref = invoice_obj.supplier_invoice_number
            reason = None
        elif isinstance(invoice_obj, CreditDebitNote):
            is_credit = (invoice_obj.note_type == NoteType.CREDIT_NOTE)
            seller_name = comp_name
            vat_number = comp_vat
            inv_dt = invoice_obj.created_at or datetime.combine(invoice_obj.note_date, datetime.min.time())
            invoice_total = quantize_money(invoice_obj.grand_total)
            vat_total = quantize_money(invoice_obj.vat_amount)
            doc_number = invoice_obj.note_number
            doc_type_code = "381" if is_credit else "383"
            party_vat = (invoice_obj.party_vat_number or "").strip()
            subtype_code = "0100000" if party_vat else "0200000"
            buyer_name = (invoice_obj.party_name or "").strip()
            buyer_vat = party_vat
            billing_ref = invoice_obj.original_invoice_number
            reason = invoice_obj.reason
        elif isinstance(invoice_obj, CashVoucher):
            is_receipt = (invoice_obj.voucher_type == VoucherType.RECEIPT)
            seller_name = comp_name
            vat_number = comp_vat
            inv_dt = invoice_obj.created_at or datetime.combine(invoice_obj.voucher_date, datetime.min.time())
            invoice_total = quantize_money(invoice_obj.total_amount)
            vat_total = quantize_money(invoice_obj.vat_amount)
            doc_number = invoice_obj.voucher_number
            doc_type_code = "386" if is_receipt else "380"
            subtype_code = "0200000"
            buyer_name = (invoice_obj.party_name or "").strip()
            buyer_vat = ""
            billing_ref = invoice_obj.reference_number
            reason = invoice_obj.description
        elif isinstance(invoice_obj, dict):
            seller_name = str(invoice_obj.get("seller_name") or comp_name).strip()
            vat_number = str(invoice_obj.get("vat_number") or comp_vat).strip()
            raw_ts = invoice_obj.get("timestamp") or invoice_obj.get("invoice_datetime") or invoice_obj.get("invoice_date")
            iso_ts = format_zatca_timestamp(raw_ts)
            inv_dt = _parse_iso_to_datetime(iso_ts)
            invoice_total = quantize_money(invoice_obj.get("invoice_total", invoice_obj.get("grand_total", 0.0)))
            raw_vat = invoice_obj.get("vat_total", invoice_obj.get("vat_amount"))
            if raw_vat is None:
                net_est = quantize_money(to_decimal(invoice_total) / Decimal("1.15"))
                vat_total = quantize_money(invoice_total - net_est)
            else:
                vat_total = quantize_money(raw_vat)
            doc_number = str(invoice_obj.get("doc_number", invoice_obj.get("invoice_number", "INV-2026-0001")))
            doc_type_code = str(invoice_obj.get("doc_type_code", "388"))
            subtype_code = str(invoice_obj.get("subtype_code", "0200000"))
            buyer_name = str(invoice_obj.get("buyer_name", "عميل نقدي"))
            buyer_vat = str(invoice_obj.get("buyer_vat", ""))
            billing_ref = invoice_obj.get("billing_reference")
            reason = invoice_obj.get("reason")
        else:
            raise ZATCATLVEncodingError(f"نوع الفاتورة غير مدعوم لتوليد باركود ZATCA: {type(invoice_obj)}")

        iso_timestamp = format_zatca_timestamp(inv_dt)
        parsed_dt = _parse_iso_to_datetime(iso_timestamp)

        artifacts = ZATCAPhase2Validator.generate_phase2_crypto_artifacts(
            seller_name=seller_name,
            seller_vat=vat_number,
            invoice_datetime=parsed_dt,
            total_amount=invoice_total,
            vat_amount=vat_total,
            doc_number=doc_number,
            doc_type_code=doc_type_code,
            subtype_code=subtype_code,
            buyer_name=buyer_name,
            buyer_vat=buyer_vat,
            icv=icv,
            pih=pih,
            billing_reference=billing_ref,
            reason=reason,
        )
        tlv_b64 = artifacts["tlv_base64"]
        decoded = decode_zatca_tlv_qr_base64(tlv_b64)
        validation = ZATCAPhase2Validator.validate_zatca_qr_code(
            tlv_base64=tlv_b64,
            expected_seller_name=seller_name,
            expected_seller_vat=vat_number,
            expected_total=invoice_total,
            expected_vat=vat_total,
            require_phase2=True,
        )

        return {
            "qr_code_base64": tlv_b64,
            "tlv_base64": tlv_b64,
            "seller_name": seller_name,
            "vat_number": vat_number,
            "timestamp": iso_timestamp,
            "invoice_total": f"{invoice_total:.2f}",
            "vat_total": f"{vat_total:.2f}",
            "doc_number": doc_number,
            "uuid": artifacts["uuid"],
            "icv": icv,
            "pih": pih,
            "invoice_hash_b64": artifacts["invoice_hash_b64"],
            "ecdsa_signature_b64": artifacts["ecdsa_signature_b64"],
            "public_key_b64": artifacts["public_key_b64"],
            "csid_stamp_b64": artifacts["csid_stamp_b64"],
            "ubl_xml": artifacts["ubl_xml"],
            "decoded": decoded,
            "validation": validation,
        }

    @classmethod
    def inspect_tlv_binary_segments(cls, tlv_base64: str) -> List[Dict[str, Any]]:
        """
        تحليل سلسلة TLV Base64 إلى جدول تقني مفصل بايت ببايت (Tag Hex, Length Byte, UTF-8/Base64 Value, Raw Hex)
        لعرضه في واجهة الفحص والتدقيق الضريبي.
        """
        decoded = decode_zatca_tlv_qr_base64(tlv_base64)
        if not decoded.get("is_valid_tlv"):
            return []

        rows: List[Dict[str, Any]] = []
        for tag_num, tag_info in sorted(decoded["tags"].items(), key=lambda x: x[0]):
            spec = ZATCA_TLV_TAG_SPECS.get(tag_num, {"name_ar": f"Tag {tag_num}", "code": f"TAG-{tag_num}", "phase": "Custom"})
            b_len = int(tag_info.get("byte_length", 0))
            rows.append({
                "tag_number": tag_num,
                "tag_hex": f"0x{tag_num:02X}",
                "length_bytes": b_len,
                "length_hex": f"0x{b_len:02X}" if b_len < 128 else (f"0x81{b_len:02X}" if b_len < 256 else f"0x82{b_len:04X}"),
                "code": spec["code"],
                "phase": spec["phase"],
                "name_ar": spec["name_ar"],
                "value": tag_info.get("value", ""),
                "hex_preview": tag_info.get("hex_preview", ""),
            })
        return rows
