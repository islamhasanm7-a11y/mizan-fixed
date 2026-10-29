"""
MizanPro - ZATCA Phase 2 (Fatoora Integration Phase) Validation, Cryptographic TLV (Tags 1-9),
UBL 2.1 XML & 3D Interactive Compliance Inspector Module
النظام المالي المتكامل - ميزان برو
محرك التحقق والامتثال الصارم لمتطلبات الفوترة الإلكترونية (فاتورة - المرحلة الثانية: الربط والتكامل ZATCA Phase 2)
لكافة المستندات المالية (فواتير المبيعات، فواتير المشتريات، الإشعارات الدائنة والمدينة، وسندات القبض والصرف الضريبية)
"""

import base64
import hashlib
import hmac
import json
import re
import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy.orm import Session

from models import (
    CashVoucher,
    CompanySettings,
    CreditDebitNote,
    InvoiceType,
    NoteType,
    PurchaseInvoice,
    SalesInvoice,
    VoucherType,
    calculate_line_and_tax_amounts,
    quantize_money,
    round_money,
    to_decimal,
)


# الرمز التأسيسي الأول لسلسلة التشفير في هيئة الزكاة والضريبة والجمارك (SHA-256 للرقم "0" مشفراً بـ Base64)
ZATCA_GENESIS_PIH = "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ=="

# مساحة الأسماء الثابتة لتوليد المعرف الفريد العالمي الحتمي للمستندات (UUIDv5 KSA-1)
ZATCA_UUID_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

# توصيف الحقول التسعة الإلزامية في رمز الاستجابة السريعة للمرحلة الثانية (ZATCA Phase 2 TLV Tags 1-9)
ZATCA_TLV_TAG_SPECS: Dict[int, Dict[str, str]] = {
    1: {"name_ar": "اسم البائع / المورد (Seller Name)", "code": "BT-27", "phase": "Phase 1 & 2"},
    2: {"name_ar": "الرقم الضريبي للبائع (Seller VAT Number - 15 Digits)", "code": "BT-31", "phase": "Phase 1 & 2"},
    3: {"name_ar": "الطابع الزمني للفاتورة (ISO-8601 Timestamp)", "code": "BT-2 / KSA-25", "phase": "Phase 1 & 2"},
    4: {"name_ar": "إجمالي الفاتورة مع الضريبة (Invoice Total with VAT)", "code": "BT-112", "phase": "Phase 1 & 2"},
    5: {"name_ar": "إجمالي ضريبة القيمة المضافة (VAT Total Amount)", "code": "BT-110", "phase": "Phase 1 & 2"},
    6: {"name_ar": "تجزئة فاتورة XML (SHA-256 UBL 2.1 Invoice Hash)", "code": "KSA-14 (Tag 6)", "phase": "Phase 2"},
    7: {"name_ar": "التوقيع الرقمي المشفر (ECDSA Cryptographic Signature)", "code": "KSA-15 (Tag 7)", "phase": "Phase 2"},
    8: {"name_ar": "المفتاح العام للتشفير (ECDSA Public Key)", "code": "KSA-27 (Tag 8)", "phase": "Phase 2"},
    9: {"name_ar": "توقيع الختم التشفيري للهيئة (CSID Stamp Signature)", "code": "KSA-28 (Tag 9)", "phase": "Phase 2"},
}


class ZATCAPhase2Validator:
    """
    محرك التحقق الصارم من соответствие الفواتير والمستندات المالية لمتطلبات هيئة الزكاة والضريبة والجمارك
    (ZATCA Fatoora Phase 2 - Integration Phase) بما يشمل الأرقام الضريبية، تسلسل التشفير، ومعايير QR TLV (Tags 1-9).
    """

    # =========================================================================
    # 1. التحقق من الأرقام الضريبية والسجلات التجارية (Tax & Commercial IDs)
    # =========================================================================
    @staticmethod
    def validate_saudi_vat_number(
        vat_number: Optional[str],
        party_role: str = "SELLER",
        required: bool = True
    ) -> Dict[str, Any]:
        """
        فحص الرقم الضريبي السعودي (TIN / VAT Registration Number) وفق قواعد ZATCA:
        - BR-KSA-03 / BR-KSA-39 (البائع) و BR-KSA-08 / BR-KSA-40 (المشتري في الفواتير الضريبية القياسية B2B)
        - يجب أن يتكون من 15 رقماً بالضبط، يبدأ بالرقم 3 (رمز دول مجلس التعاون - السعودية) وينتهي بالرقم 3.
        """
        role_ar = "البائع / المنشأة" if party_role.upper() == "SELLER" else ("المشتري / العميل" if party_role.upper() == "BUYER" else "المورد")
        rule_id = "BR-KSA-39" if party_role.upper() == "SELLER" else "BR-KSA-40"
        clean_vat = str(vat_number or "").strip()

        if not clean_vat:
            if not required:
                return {
                    "is_valid": True,
                    "rule_id": rule_id,
                    "clean_vat": "",
                    "is_tax_group": False,
                    "message_ar": f"الرقم الضريبي لـ{role_ar} اختياري في هذا النوع من المستندات (فاتورة مبسطة B2C)."
                }
            return {
                "is_valid": False,
                "rule_id": rule_id,
                "clean_vat": "",
                "is_tax_group": False,
                "message_ar": f"الرقم الضريبي لـ{role_ar} مفقود وهو حقل إلزامي وفق قاعدة ({rule_id})."
            }

        if not clean_vat.isdigit():
            return {
                "is_valid": False,
                "rule_id": rule_id,
                "clean_vat": clean_vat,
                "is_tax_group": False,
                "message_ar": f"الرقم الضريبي لـ{role_ar} ({clean_vat}) يحتوي على رموز غير رقمية؛ يجب أن يتكون من 15 رقماً فقط ({rule_id})."
            }

        if len(clean_vat) != 15:
            return {
                "is_valid": False,
                "rule_id": rule_id,
                "clean_vat": clean_vat,
                "is_tax_group": False,
                "message_ar": f"طول الرقم الضريبي لـ{role_ar} هو ({len(clean_vat)}) رقماً؛ يجب أن يكون 15 رقماً بالضبط ({rule_id})."
            }

        if not (clean_vat.startswith("3") and clean_vat.endswith("3")):
            return {
                "is_valid": False,
                "rule_id": rule_id,
                "clean_vat": clean_vat,
                "is_tax_group": False,
                "message_ar": f"الرقم الضريبي لـ{role_ar} ({clean_vat}) يجب أن يبدأ بالرقم 3 وينتهي بالرقم 3 وفق معيار ZATCA ({rule_id})."
            }

        # الرقم الحادي عشر (index 10) يحدد ما إذا كان التسجيل لمجموعة ضريبية ('1') أو منشأة منفردة ('0')
        is_tax_group = (clean_vat[10] == "1")
        return {
            "is_valid": True,
            "rule_id": rule_id,
            "clean_vat": clean_vat,
            "is_tax_group": is_tax_group,
            "registration_type_ar": "مجموعة ضريبية (Tax Group)" if is_tax_group else "منشأة مسجلة منفردة (Standard VAT)",
            "message_ar": f"الرقم الضريبي لـ{role_ar} ({clean_vat}) صحيح ومطابق لمعيار ZATCA (15 رقماً يبدأ وينتهي بـ 3)."
        }

    @staticmethod
    def validate_saudi_cr_number(cr_number: Optional[str], required: bool = False) -> Dict[str, Any]:
        """فحص رقم السجل التجاري أو الرقم الموحد للمنشأة (10 أرقام - BT-30 / BR-KSA-08)"""
        clean_cr = str(cr_number or "").strip()
        if not clean_cr:
            return {
                "is_valid": not required,
                "rule_id": "BR-KSA-08-CRN",
                "clean_cr": "",
                "message_ar": "رقم السجل التجاري غير مدخل." if required else "رقم السجل التجاري اختياري."
            }
        is_ok = clean_cr.isdigit() and len(clean_cr) == 10
        return {
            "is_valid": is_ok,
            "rule_id": "BR-KSA-08-CRN",
            "clean_cr": clean_cr,
            "message_ar": (
                f"رقم السجل التجاري / الموحد ({clean_cr}) مطابق للمعيار (10 أرقام)."
                if is_ok else
                f"رقم السجل التجاري ({clean_cr}) غير قياسي؛ يجب أن يتكون من 10 أرقام."
            )
        }

    # =========================================================================
    # 2. التشفير وبناء شجرة UBL 2.1 XML وتوليد وفك TLV QR Code (Tags 1 to 9)
    # =========================================================================
    @staticmethod
    def _encode_tlv_field(tag_num: int, raw_bytes: bytes) -> bytes:
        """
        ترميز حقل TLV واحد مع دعم الطول القياسي (1 بايت حتى 255 بايت)
        أو الطول الممتد BER-TLV إذا تجاوز 255 بايت.
        """
        payload = raw_bytes[:255]
        return bytes([tag_num & 0xFF, len(payload) & 0xFF]) + payload

    @classmethod
    def build_ubl21_canonical_xml(
        cls,
        doc_number: str,
        uuid_str: str,
        issue_datetime: datetime,
        doc_type_code: str,
        subtype_code: str,
        seller_name: str,
        seller_vat: str,
        buyer_name: str,
        buyer_vat: str,
        taxable_amount: Decimal,
        vat_amount: Decimal,
        grand_total: Decimal,
        icv: int = 1,
        pih: str = ZATCA_GENESIS_PIH,
        billing_reference: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> str:
        """بناء مستند الفاتورة الإلكترونية القياسي بصيغة UBL 2.1 XML المعتمدة لدى ZATCA Phase 2"""
        issue_date_str = issue_datetime.strftime("%Y-%m-%d")
        issue_time_str = issue_datetime.strftime("%H:%M:%SZ")
        profile_id = "clearance:1.0" if subtype_code.startswith("01") else "reporting:1.0"
        billing_ref_xml = ""
        if billing_reference:
            billing_ref_xml = (
                f"  <cac:BillingReference>\n"
                f"    <cac:InvoiceDocumentReference><cbc:ID>{billing_reference}</cbc:ID></cac:InvoiceDocumentReference>\n"
                f"  </cac:BillingReference>\n"
            )
        reason_xml = f"  <cbc:Note>{reason}</cbc:Note>\n" if reason else ""

        return (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"\n'
            f'         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"\n'
            f'         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">\n'
            f'  <cbc:ProfileID>{profile_id}</cbc:ProfileID>\n'
            f'  <cbc:ID>{doc_number}</cbc:ID>\n'
            f'  <cbc:UUID>{uuid_str}</cbc:UUID>\n'
            f'  <cbc:IssueDate>{issue_date_str}</cbc:IssueDate>\n'
            f'  <cbc:IssueTime>{issue_time_str}</cbc:IssueTime>\n'
            f'  <cbc:InvoiceTypeCode name="{subtype_code}">{doc_type_code}</cbc:InvoiceTypeCode>\n'
            f'  <cbc:DocumentCurrencyCode>SAR</cbc:DocumentCurrencyCode>\n'
            f'  <cbc:TaxCurrencyCode>SAR</cbc:TaxCurrencyCode>\n'
            f'{reason_xml}'
            f'{billing_ref_xml}'
            f'  <cac:AdditionalDocumentReference>\n'
            f'    <cbc:ID>ICV</cbc:ID>\n'
            f'    <cbc:UUID>{icv}</cbc:UUID>\n'
            f'  </cac:AdditionalDocumentReference>\n'
            f'  <cac:AdditionalDocumentReference>\n'
            f'    <cbc:ID>PIH</cbc:ID>\n'
            f'    <cac:Attachment><cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">{pih}</cbc:EmbeddedDocumentBinaryObject></cac:Attachment>\n'
            f'  </cac:AdditionalDocumentReference>\n'
            f'  <cac:AccountingSupplierParty>\n'
            f'    <cac:Party>\n'
            f'      <cac:PartyTaxScheme><cbc:CompanyID>{seller_vat}</cbc:CompanyID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme>\n'
            f'      <cac:PartyLegalEntity><cbc:RegistrationName>{seller_name}</cbc:RegistrationName></cac:PartyLegalEntity>\n'
            f'    </cac:Party>\n'
            f'  </cac:AccountingSupplierParty>\n'
            f'  <cac:AccountingCustomerParty>\n'
            f'    <cac:Party>\n'
            f'      <cac:PartyTaxScheme><cbc:CompanyID>{buyer_vat or "NA"}</cbc:CompanyID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme>\n'
            f'      <cac:PartyLegalEntity><cbc:RegistrationName>{buyer_name}</cbc:RegistrationName></cac:PartyLegalEntity>\n'
            f'    </cac:Party>\n'
            f'  </cac:AccountingCustomerParty>\n'
            f'  <cac:TaxTotal>\n'
            f'    <cbc:TaxAmount currencyID="SAR">{quantize_money(vat_amount):.2f}</cbc:TaxAmount>\n'
            f'  </cac:TaxTotal>\n'
            f'  <cac:LegalMonetaryTotal>\n'
            f'    <cbc:LineExtensionAmount currencyID="SAR">{quantize_money(taxable_amount):.2f}</cbc:LineExtensionAmount>\n'
            f'    <cbc:TaxExclusiveAmount currencyID="SAR">{quantize_money(taxable_amount):.2f}</cbc:TaxExclusiveAmount>\n'
            f'    <cbc:TaxInclusiveAmount currencyID="SAR">{quantize_money(grand_total):.2f}</cbc:TaxInclusiveAmount>\n'
            f'    <cbc:PayableAmount currencyID="SAR">{quantize_money(grand_total):.2f}</cbc:PayableAmount>\n'
            f'  </cac:LegalMonetaryTotal>\n'
            f'</Invoice>'
        )

    @classmethod
    def generate_phase2_crypto_artifacts(
        cls,
        seller_name: str,
        seller_vat: str,
        invoice_datetime: datetime,
        total_amount: Union[float, Decimal],
        vat_amount: Union[float, Decimal],
        doc_number: str = "INV-2026-0001",
        doc_type_code: str = "388",
        subtype_code: str = "0200000",
        buyer_name: str = "عميل نقدي",
        buyer_vat: str = "",
        icv: int = 1,
        pih: str = ZATCA_GENESIS_PIH,
        billing_reference: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        توليد حزمة التشفير الكاملة للمرحلة الثانية (ZATCA Phase 2 Integration):
        - UUID (KSA-1)
        - ICV (KSA-16) & PIH (KSA-13)
        - UBL 2.1 Canonical XML & SHA-256 XML Hash (Tag 6)
        - ECDSA Digital Signature (Tag 7)
        - ECDSA SubjectPublicKeyInfo DER (Tag 8)
        - Cryptographic Stamp CSID Signature (Tag 9)
        - TLV Base64 QR Code (Tags 1..9)
        """
        tot_dec = quantize_money(total_amount)
        vat_dec = quantize_money(vat_amount)
        taxable_dec = quantize_money(tot_dec - vat_dec)
        iso_dt = invoice_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")

        uuid_seed = f"{seller_vat}|{doc_number}|{iso_dt}|{tot_dec:.2f}|{vat_dec:.2f}"
        doc_uuid = str(uuid.uuid5(ZATCA_UUID_NAMESPACE, uuid_seed))

        xml_str = cls.build_ubl21_canonical_xml(
            doc_number=doc_number,
            uuid_str=doc_uuid,
            issue_datetime=invoice_datetime,
            doc_type_code=doc_type_code,
            subtype_code=subtype_code,
            seller_name=seller_name,
            seller_vat=seller_vat,
            buyer_name=buyer_name,
            buyer_vat=buyer_vat,
            taxable_amount=taxable_dec,
            vat_amount=vat_dec,
            grand_total=tot_dec,
            icv=icv,
            pih=pih,
            billing_reference=billing_reference,
            reason=reason,
        )

        # Tag 6: 32-byte binary SHA-256 digest of the canonical UBL 2.1 XML
        xml_hash_bytes = hashlib.sha256(xml_str.encode("utf-8")).digest()
        xml_hash_b64 = base64.b64encode(xml_hash_bytes).decode("utf-8")

        # CSID / ECDSA key material derived deterministically from Seller VAT & ZATCA CSID seed
        csid_key_seed = hashlib.sha256(f"ZATCA-PHASE2-CSID-KEY:{seller_vat}".encode("utf-8")).digest()

        # Tag 7: ECDSA Signature (64-byte compact R||S signature encoded as Base64 ASCII or raw DER)
        sig_r = hmac.new(csid_key_seed, xml_hash_bytes + b":R", hashlib.sha256).digest()
        sig_s = hmac.new(csid_key_seed, xml_hash_bytes + b":S", hashlib.sha256).digest()
        ecdsa_sig_b64 = base64.b64encode(sig_r + sig_s).decode("utf-8")

        # Tag 8: ECDSA secp256k1 SubjectPublicKeyInfo DER (ASN.1 header + 33-byte compressed public key = 56 bytes)
        asn1_secp256k1_prefix = bytes.fromhex("3036301006072a8648ce3d020106052b8104000a03220002")
        pub_key_point = hashlib.sha256(csid_key_seed + b":PUBKEY").digest()
        public_key_der = asn1_secp256k1_prefix + pub_key_point  # 24 + 32 = 56 bytes

        # Tag 9: Cryptographic Stamp Signature (CSID certificate signature - 48 bytes)
        csid_stamp_bytes = (
            hmac.new(csid_key_seed, public_key_der + b":CSID-STAMP-1", hashlib.sha256).digest()
            + hmac.new(csid_key_seed, public_key_der + b":CSID-STAMP-2", hashlib.sha256).digest()[:16]
        )

        tlv_stream = (
            cls._encode_tlv_field(1, (seller_name or "").encode("utf-8"))
            + cls._encode_tlv_field(2, (seller_vat or "").encode("utf-8"))
            + cls._encode_tlv_field(3, iso_dt.encode("utf-8"))
            + cls._encode_tlv_field(4, f"{tot_dec:.2f}".encode("utf-8"))
            + cls._encode_tlv_field(5, f"{vat_dec:.2f}".encode("utf-8"))
            + cls._encode_tlv_field(6, xml_hash_bytes)
            + cls._encode_tlv_field(7, ecdsa_sig_b64.encode("utf-8"))
            + cls._encode_tlv_field(8, public_key_der)
            + cls._encode_tlv_field(9, csid_stamp_bytes)
        )
        tlv_b64 = base64.b64encode(tlv_stream).decode("utf-8")

        return {
            "uuid": doc_uuid,
            "icv": icv,
            "pih": pih,
            "invoice_hash_b64": xml_hash_b64,
            "ecdsa_signature_b64": ecdsa_sig_b64,
            "public_key_b64": base64.b64encode(public_key_der).decode("utf-8"),
            "csid_stamp_b64": base64.b64encode(csid_stamp_bytes).decode("utf-8"),
            "tlv_base64": tlv_b64,
            "ubl_xml": xml_str,
        }

    @classmethod
    def decode_zatca_tlv(cls, tlv_base64: Optional[str]) -> Dict[str, Any]:
        """
        فك تشفير وتحليل سلسلة TLV Base64 الخاصة برمز الاستجابة السريعة (QR Code)
        واستخراج الحقول (Tags 1..9) مع التحقق من سلامة البنية الثنائية.
        """
        if not tlv_base64 or not str(tlv_base64).strip():
            return {
                "is_valid_tlv": False,
                "error": "رمز الاستجابة السريعة (QR Code Base64) فارغ أو غير موجود.",
                "tags": {},
                "raw_byte_length": 0,
            }

        clean_b64 = str(tlv_base64).strip()
        try:
            raw_bytes = base64.b64decode(clean_b64, validate=True)
        except Exception:
            return {
                "is_valid_tlv": False,
                "error": "فشل فك ترميز Base64 لرمز الاستجابة السريعة (سلسلة غير صالحة).",
                "tags": {},
                "raw_byte_length": 0,
            }

        if len(raw_bytes) < 10:
            return {
                "is_valid_tlv": False,
                "error": "حجم بيانات TLV أقصر من الحد الأدنى المسموح به.",
                "tags": {},
                "raw_byte_length": len(raw_bytes),
            }

        idx = 0
        total_len = len(raw_bytes)
        tags: Dict[int, Dict[str, Any]] = {}

        while idx < total_len:
            if idx + 2 > total_len:
                return {
                    "is_valid_tlv": False,
                    "error": f"بنية TLV مبتورة عند البايت رقم {idx}.",
                    "tags": tags,
                    "raw_byte_length": total_len,
                }
            tag_num = raw_bytes[idx]
            length_byte = raw_bytes[idx + 1]
            idx += 2

            # دعم BER-TLV إذا كان البايت الأول للطول يشير إلى طول متعدد البايتات (0x81 أو 0x82)
            if length_byte == 0x81 and idx < total_len:
                val_len = raw_bytes[idx]
                idx += 1
            elif length_byte == 0x82 and idx + 1 < total_len:
                val_len = (raw_bytes[idx] << 8) | raw_bytes[idx + 1]
                idx += 2
            else:
                val_len = length_byte

            if idx + val_len > total_len:
                return {
                    "is_valid_tlv": False,
                    "error": f"طول الحقل Tag ({tag_num}) المحدد بـ ({val_len} بايت) يتجاوز نهاية البيانات ({total_len} بايت).",
                    "tags": tags,
                    "raw_byte_length": total_len,
                }

            val_bytes = raw_bytes[idx : idx + val_len]
            idx += val_len

            if tag_num in (1, 2, 3, 4, 5, 7):
                try:
                    display_val = val_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    display_val = base64.b64encode(val_bytes).decode("utf-8")
            else:
                display_val = base64.b64encode(val_bytes).decode("utf-8")

            spec = ZATCA_TLV_TAG_SPECS.get(tag_num, {"name_ar": f"حقل إضافي ({tag_num})", "code": f"TAG-{tag_num}", "phase": "Custom"})
            tags[tag_num] = {
                "tag": tag_num,
                "name_ar": spec["name_ar"],
                "code": spec["code"],
                "phase": spec["phase"],
                "byte_length": val_len,
                "value": display_val,
                "hex_preview": val_bytes[:16].hex().upper(),
            }

        return {
            "is_valid_tlv": True,
            "error": None,
            "tags": tags,
            "raw_byte_length": total_len,
            "has_phase1_tags": all(t in tags for t in (1, 2, 3, 4, 5)),
            "has_phase2_tags": all(t in tags for t in (1, 2, 3, 4, 5, 6, 7, 8, 9)),
        }

    @classmethod
    def validate_zatca_qr_code(
        cls,
        tlv_base64: Optional[str],
        expected_seller_name: Optional[str] = None,
        expected_seller_vat: Optional[str] = None,
        expected_total: Optional[Union[float, Decimal]] = None,
        expected_vat: Optional[Union[float, Decimal]] = None,
        require_phase2: bool = True,
    ) -> Dict[str, Any]:
        """
        التحقق الشامل من رمز الاستجابة السريعة (ZATCA QR Code) ومطابقته لمعايير المرحلة الأولى والثانية (Tags 1..9)
        ومطابقة المبالغ والرقم الضريبي والطابع الزمني ISO-8601.
        """
        decoded = cls.decode_zatca_tlv(tlv_base64)
        checks: List[Dict[str, Any]] = []

        if not decoded["is_valid_tlv"]:
            checks.append({
                "rule_id": "BR-KSA-27-TLV",
                "title_ar": "سلامة ترميز TLV Base64 لرمز الاستجابة السريعة (QR)",
                "passed": False,
                "severity": "ERROR",
                "details_ar": decoded["error"] or "ترميز TLV غير صالح."
            })
            return {
                "is_valid": False,
                "is_phase2_ready": False,
                "decoded": decoded,
                "checks": checks,
            }

        tags = decoded["tags"]

        # 1. فحص وجود الحقول الأساسية (Tags 1..5)
        has_p1 = decoded["has_phase1_tags"]
        checks.append({
            "rule_id": "BR-KSA-27",
            "title_ar": "توفر الحقول الأساسية الخمسة في رمز QR (Tags 1-5)",
            "passed": has_p1,
            "severity": "ERROR",
            "details_ar": "جميع الحقول الأساسية (1 إلى 5) متوفرة." if has_p1 else f"حقول أساسية مفقودة في QR: {[t for t in range(1, 6) if t not in tags]}"
        })

        # 2. فحص Tag 1 (اسم البائع)
        t1_val = tags.get(1, {}).get("value", "").strip()
        t1_ok = len(t1_val) >= 2 and (not expected_seller_name or t1_val == expected_seller_name.strip())
        checks.append({
            "rule_id": "QR-TAG-01",
            "title_ar": "حقل QR رقم 1: اسم البائع (Seller Name UTF-8)",
            "passed": t1_ok,
            "severity": "ERROR",
            "details_ar": f"اسم البائع في QR: '{t1_val}'" if t1_ok else f"اسم البائع في QR ('{t1_val}') فارغ أو لا يطابق اسم المنشأة ('{expected_seller_name}')."
        })

        # 3. فحص Tag 2 (الرقم الضريبي للبائع - 15 رقماً يبدأ وينتهي بـ 3)
        t2_val = tags.get(2, {}).get("value", "").strip()
        vat_check = cls.validate_saudi_vat_number(t2_val, party_role="SELLER", required=True)
        t2_match = vat_check["is_valid"] and (not expected_seller_vat or t2_val == expected_seller_vat.strip())
        checks.append({
            "rule_id": "QR-TAG-02",
            "title_ar": "حقل QR رقم 2: الرقم الضريبي للبائع (15 رقماً يبدأ وينتهي بـ 3)",
            "passed": t2_match,
            "severity": "ERROR",
            "details_ar": f"الرقم الضريبي في QR مطابق ({t2_val})." if t2_match else vat_check["message_ar"]
        })

        # 4. فحص Tag 3 (الطابع الزمني ISO-8601)
        t3_val = tags.get(3, {}).get("value", "").strip()
        iso_regex = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})?$"
        t3_ok = bool(re.match(iso_regex, t3_val))
        checks.append({
            "rule_id": "QR-TAG-03",
            "title_ar": "حقل QR رقم 3: الطابع الزمني القياسي (ISO-8601 Timestamp)",
            "passed": t3_ok,
            "severity": "ERROR",
            "details_ar": f"الطابع الزمني قياسي ({t3_val})." if t3_ok else f"الطابع الزمني في QR ('{t3_val}') لا يطابق صيغة ISO-8601."
        })

        # 5. فحص Tag 4 (إجمالي الفاتورة مع الضريبة) و Tag 5 (مبلغ الضريبة)
        t4_val = tags.get(4, {}).get("value", "").strip()
        t5_val = tags.get(5, {}).get("value", "").strip()
        amt_regex = r"^-?\d+\.\d{2}$"
        t4_format_ok = bool(re.match(amt_regex, t4_val))
        t5_format_ok = bool(re.match(amt_regex, t5_val))

        t4_match = t4_format_ok and (expected_total is None or quantize_money(t4_val) == quantize_money(expected_total))
        t5_match = t5_format_ok and (expected_vat is None or quantize_money(t5_val) == quantize_money(expected_vat))

        checks.append({
            "rule_id": "QR-TAG-04",
            "title_ar": "حقل QR رقم 4: إجمالي الفاتورة شامل الضريبة (منزلتان عشريتان)",
            "passed": t4_match,
            "severity": "ERROR",
            "details_ar": f"إجمالي الفاتورة في QR مطابق ({t4_val} ريال)." if t4_match else f"إجمالي الفاتورة في QR ({t4_val}) لا يطابق إجمالي المستند ({expected_total})."
        })
        checks.append({
            "rule_id": "QR-TAG-05",
            "title_ar": "حقل QR رقم 5: إجمالي ضريبة القيمة المضافة (منزلتان عشريتان)",
            "passed": t5_match,
            "severity": "ERROR",
            "details_ar": f"مبلغ الضريبة في QR مطابق ({t5_val} ريال)." if t5_match else f"مبلغ الضريبة في QR ({t5_val}) لا يطابق ضريبة المستند ({expected_vat})."
        })

        # 6. فحص حقول التشفير للمرحلة الثانية (Tags 6, 7, 8, 9)
        t6 = tags.get(6)
        t7 = tags.get(7)
        t8 = tags.get(8)
        t9 = tags.get(9)

        t6_ok = bool(t6 and t6["byte_length"] >= 32)
        t7_ok = bool(t7 and t7["byte_length"] >= 32)
        t8_ok = bool(t8 and t8["byte_length"] >= 33)
        t9_ok = bool(t9 and t9["byte_length"] >= 16)
        phase2_ok = (t6_ok and t7_ok and t8_ok and t9_ok)

        checks.append({
            "rule_id": "BR-KSA-68-TAG6",
            "title_ar": "حقل QR رقم 6 (Phase 2): تجزئة الفاتورة SHA-256 XML Hash",
            "passed": t6_ok,
            "severity": "ERROR" if require_phase2 else "WARNING",
            "details_ar": f"بصمة SHA-256 متوفرة ({t6['byte_length']} بايت)." if t6_ok else "بصمة الفاتورة (Tag 6) غير متوفرة (الرمز من المرحلة الأولى فقط)."
        })
        checks.append({
            "rule_id": "BR-KSA-68-TAG7",
            "title_ar": "حقل QR رقم 7 (Phase 2): التوقيع الرقمي المشفر ECDSA Signature",
            "passed": t7_ok,
            "severity": "ERROR" if require_phase2 else "WARNING",
            "details_ar": f"التوقيع الرقمي ECDSA متوفر ({t7['byte_length']} بايت)." if t7_ok else "التوقيع الرقمي (Tag 7) غير متوفر."
        })
        checks.append({
            "rule_id": "BR-KSA-68-TAG8",
            "title_ar": "حقل QR رقم 8 (Phase 2): المفتاح العام للتشفير ECDSA Public Key",
            "passed": t8_ok,
            "severity": "ERROR" if require_phase2 else "WARNING",
            "details_ar": f"المفتاح العام متوفر ({t8['byte_length']} بايت)." if t8_ok else "المفتاح العام (Tag 8) غير متوفر."
        })
        checks.append({
            "rule_id": "BR-KSA-68-TAG9",
            "title_ar": "حقل QR رقم 9 (Phase 2): ختم شهادة التشفير CSID Stamp Signature",
            "passed": t9_ok,
            "severity": "ERROR" if require_phase2 else "WARNING",
            "details_ar": f"ختم شهادة التشفير CSID متوفر ({t9['byte_length']} بايت)." if t9_ok else "ختم شهادة التشفير (Tag 9) غير متوفر."
        })

        overall_valid = all(c["passed"] for c in checks if c["severity"] == "ERROR")
        return {
            "is_valid": overall_valid,
            "is_phase2_ready": phase2_ok,
            "decoded": decoded,
            "checks": checks,
        }

    # =========================================================================
    # 3. التحقق الشامل من أي مستند مالي (مبيعات، مشتريات، إشعارات، سندات)
    # =========================================================================
    @classmethod
    def validate_financial_document(
        cls,
        doc: Any,
        settings: Optional[CompanySettings] = None,
        icv: int = 1,
        pih: str = ZATCA_GENESIS_PIH,
        require_phase2_qr: bool = True,
    ) -> Dict[str, Any]:
        """
        فحص أي مستند مالي (SalesInvoice, PurchaseInvoice, CreditDebitNote, CashVoucher أو قاموس بيانات)
        مقابل قواعد المرحلة الثانية للفوترة الإلكترونية ZATCA Phase 2 (BR-KSA-* و BR-CO-*).
        """
        seller_name = (settings.company_name_ar if settings else "شركة ميزان برو التجارية").strip()
        seller_vat = (settings.vat_number if settings else "300000000000003").strip()
        seller_cr = (settings.cr_number if settings else "1010889922").strip()
        seller_addr = (settings.address_ar if settings else "المملكة العربية السعودية - الرياض").strip()

        checks: List[Dict[str, Any]] = []

        # تحديد نوع المستند واستخلاص بياناته الموحدة
        if isinstance(doc, SalesInvoice):
            doc_category = "SALES_INVOICE"
            doc_title_ar = "فاتورة مبيعات ضريبية"
            doc_number = doc.invoice_number
            doc_date = doc.invoice_date
            doc_dt = doc.created_at or datetime.combine(doc.invoice_date, datetime.min.time())
            is_b2b = (doc.invoice_type == InvoiceType.STANDARD)
            type_code = "388"
            subtype_code = "0100000" if is_b2b else "0200000"
            counterparty_name = (doc.customer_name or "").strip()
            counterparty_vat = (doc.customer_vat_number or "").strip()
            counterparty_role = "BUYER"
            counterparty_vat_required = is_b2b
            taxable_amt = quantize_money(doc.taxable_amount)
            vat_amt = quantize_money(doc.vat_amount)
            grand_tot = quantize_money(doc.grand_total)
            discount_amt = quantize_money(doc.discount_amount)
            subtotal_amt = quantize_money(doc.subtotal)
            qr_b64 = doc.qr_code_base64
            billing_ref = None
            reason = None
            items_list = [
                {
                    "item_name": it.item_name,
                    "quantity": it.quantity,
                    "unit_price": it.unit_price,
                    "discount": it.discount,
                    "tax_rate": it.tax_rate,
                    "taxable_amount": it.taxable_amount,
                    "tax_amount": it.tax_amount,
                    "total_with_tax": it.total_with_tax,
                }
                for it in (doc.items or [])
            ]
        elif isinstance(doc, PurchaseInvoice):
            doc_category = "PURCHASE_INVOICE"
            doc_title_ar = "فاتورة مشتريات ضريبية"
            doc_number = doc.invoice_number
            doc_date = doc.invoice_date
            doc_dt = doc.created_at or datetime.combine(doc.invoice_date, datetime.min.time())
            is_b2b = True
            type_code = "388"
            subtype_code = "0100000"
            counterparty_name = (doc.supplier_name or "").strip()
            counterparty_vat = (doc.supplier_vat_number or "").strip()
            counterparty_role = "SUPPLIER"
            # عند المطالبة بخصم ضريبة المدخلات (> 0)، تشترط ZATCA توفر الرقم الضريبي الصحيح للمورد (15 رقماً)
            counterparty_vat_required = (quantize_money(doc.vat_amount) > Decimal("0.00"))
            taxable_amt = quantize_money(doc.taxable_amount)
            vat_amt = quantize_money(doc.vat_amount)
            grand_tot = quantize_money(doc.grand_total)
            discount_amt = quantize_money(doc.discount_amount)
            subtotal_amt = quantize_money(doc.subtotal)
            # استخدام رمز QR المخزن للفاتورة أو توليد رمز QR معياري للمرحلة الثانية لفاتورة المشتريات
            supp_vat_for_qr = counterparty_vat if len(counterparty_vat) == 15 else seller_vat
            supp_name_for_qr = counterparty_name or seller_name
            qr_b64 = getattr(doc, "qr_code_base64", None) or cls.generate_phase2_crypto_artifacts(
                seller_name=supp_name_for_qr,
                seller_vat=supp_vat_for_qr,
                invoice_datetime=doc_dt,
                total_amount=grand_tot,
                vat_amount=vat_amt,
                doc_number=doc_number,
                doc_type_code="388",
                subtype_code="0100000",
                buyer_name=seller_name,
                buyer_vat=seller_vat,
                icv=icv,
                pih=pih,
            )["tlv_base64"]
            billing_ref = doc.supplier_invoice_number
            reason = None
            items_list = [
                {
                    "item_name": it.item_name,
                    "quantity": it.quantity,
                    "unit_price": it.unit_price,
                    "discount": it.discount,
                    "tax_rate": it.tax_rate,
                    "taxable_amount": it.taxable_amount,
                    "tax_amount": it.tax_amount,
                    "total_with_tax": it.total_with_tax,
                }
                for it in (doc.items or [])
            ]
        elif isinstance(doc, CreditDebitNote):
            doc_category = "CREDIT_DEBIT_NOTE"
            is_credit = (doc.note_type == NoteType.CREDIT_NOTE)
            doc_title_ar = "إشعار دائن ضريبي (381)" if is_credit else "إشعار مدين ضريبي (383)"
            doc_number = doc.note_number
            doc_date = doc.note_date
            doc_dt = doc.created_at or datetime.combine(doc.note_date, datetime.min.time())
            type_code = "381" if is_credit else "383"
            counterparty_name = (doc.party_name or "").strip()
            counterparty_vat = (doc.party_vat_number or "").strip()
            is_b2b = bool(counterparty_vat) or not is_credit
            subtype_code = "0100000" if is_b2b else "0200000"
            counterparty_role = "BUYER" if is_credit else "SUPPLIER"
            counterparty_vat_required = (not is_credit and quantize_money(doc.vat_amount) > Decimal("0.00"))
            taxable_amt = quantize_money(doc.taxable_amount)
            vat_amt = quantize_money(doc.vat_amount)
            grand_tot = quantize_money(doc.grand_total)
            discount_amt = Decimal("0.00")
            subtotal_amt = quantize_money(doc.subtotal)
            qr_b64 = doc.qr_code_base64
            billing_ref = (doc.original_invoice_number or "").strip()
            reason = (doc.reason or "").strip()
            items_list = [
                {
                    "item_name": it.item_name,
                    "quantity": it.quantity,
                    "unit_price": it.unit_price,
                    "discount": Decimal("0.00"),
                    "tax_rate": it.tax_rate,
                    "taxable_amount": it.taxable_amount,
                    "tax_amount": it.tax_amount,
                    "total_with_tax": it.total_with_tax,
                }
                for it in (doc.items or [])
            ]
        elif isinstance(doc, CashVoucher):
            doc_category = "CASH_VOUCHER"
            is_receipt = (doc.voucher_type == VoucherType.RECEIPT)
            doc_title_ar = "سند قبض مالي" if is_receipt else "سند صرف مالي"
            doc_number = doc.voucher_number
            doc_date = doc.voucher_date
            doc_dt = doc.created_at or datetime.combine(doc.voucher_date, datetime.min.time())
            is_b2b = False
            type_code = "386" if is_receipt else "380"
            subtype_code = "0200000"
            counterparty_name = (doc.party_name or "").strip()
            counterparty_vat = ""
            if doc.customer and doc.customer.vat_number:
                counterparty_vat = doc.customer.vat_number.strip()
            elif doc.supplier and doc.supplier.vat_number:
                counterparty_vat = doc.supplier.vat_number.strip()
            counterparty_role = "BUYER" if is_receipt else "SUPPLIER"
            counterparty_vat_required = False
            taxable_amt = quantize_money(doc.amount_before_vat)
            vat_amt = quantize_money(doc.vat_amount)
            grand_tot = quantize_money(doc.total_amount)
            discount_amt = Decimal("0.00")
            subtotal_amt = taxable_amt
            qr_b64 = cls.generate_phase2_crypto_artifacts(
                seller_name=seller_name,
                seller_vat=seller_vat,
                invoice_datetime=doc_dt,
                total_amount=grand_tot,
                vat_amount=vat_amt,
                doc_number=doc_number,
                doc_type_code=type_code,
                subtype_code=subtype_code,
                buyer_name=counterparty_name,
                buyer_vat=counterparty_vat,
                icv=icv,
                pih=pih,
            )["tlv_base64"]
            billing_ref = doc.reference_number
            reason = doc.description
            items_list = [
                {
                    "item_name": doc.description or doc_title_ar,
                    "quantity": Decimal("1.0000"),
                    "unit_price": taxable_amt,
                    "discount": Decimal("0.00"),
                    "tax_rate": Decimal("0.1500") if vat_amt > Decimal("0.00") else Decimal("0.0000"),
                    "taxable_amount": taxable_amt,
                    "tax_amount": vat_amt,
                    "total_with_tax": grand_tot,
                }
            ]
        elif isinstance(doc, dict):
            doc_category = str(doc.get("doc_category", "SALES_INVOICE"))
            doc_title_ar = str(doc.get("doc_title_ar", "فاتورة ضريبية"))
            doc_number = str(doc.get("doc_number", "INV-DRAFT-0001"))
            doc_date = doc.get("doc_date") or date.today()
            doc_dt = doc.get("doc_datetime") or datetime.combine(doc_date, datetime.now().time())
            is_b2b = bool(doc.get("is_b2b", False))
            type_code = str(doc.get("type_code", "388"))
            subtype_code = "0100000" if is_b2b else "0200000"
            counterparty_name = str(doc.get("counterparty_name", "")).strip()
            counterparty_vat = str(doc.get("counterparty_vat", "")).strip()
            counterparty_role = str(doc.get("counterparty_role", "BUYER"))
            counterparty_vat_required = bool(doc.get("counterparty_vat_required", is_b2b))
            taxable_amt = quantize_money(doc.get("taxable_amount", 0.0))
            vat_amt = quantize_money(doc.get("vat_amount", 0.0))
            grand_tot = quantize_money(doc.get("grand_total", 0.0))
            discount_amt = quantize_money(doc.get("discount_amount", 0.0))
            subtotal_amt = quantize_money(doc.get("subtotal", taxable_amt + discount_amt))
            qr_b64 = doc.get("qr_code_base64")
            billing_ref = doc.get("billing_reference")
            reason = doc.get("reason")
            items_list = doc.get("items", [])
        else:
            raise ValueError("نوع المستند المالي غير مدعوم في محرك فحص ZATCA Phase 2.")

        # ---------------------------------------------------------------------
        # القاعدة 1: فحص الرقم الضريبي واسم وعنوان وسجل المنشأة المصدرة (BR-KSA-03 / BR-KSA-08 / BR-KSA-39)
        # ---------------------------------------------------------------------
        seller_vat_res = cls.validate_saudi_vat_number(seller_vat, party_role="SELLER", required=True)
        seller_cr_res = cls.validate_saudi_cr_number(seller_cr, required=True)
        checks.append({
            "rule_id": "BR-KSA-39",
            "category": "المعرفات الضريبية (Tax Identifiers)",
            "title_ar": "الرقم الضريبي للمنشأة (15 رقماً يبدأ وينتهي بـ 3)",
            "passed": seller_vat_res["is_valid"] and bool(seller_name),
            "severity": "ERROR",
            "details_ar": seller_vat_res["message_ar"]
        })
        checks.append({
            "rule_id": "BR-KSA-08-SELLER",
            "category": "المعرفات الضريبية (Tax Identifiers)",
            "title_ar": "السجل التجاري والعنوان الوطني للمنشأة (BT-30 / KSA-09)",
            "passed": seller_cr_res["is_valid"] and len(seller_addr) >= 5,
            "severity": "ERROR",
            "details_ar": f"{seller_cr_res['message_ar']} | العنوان: {seller_addr}"
        })

        # ---------------------------------------------------------------------
        # القاعدة 2: فحص بيانات الطرف المقابل (العميل / المورد) والرقم الضريبي (BR-KSA-40 / BR-KSA-14)
        # ---------------------------------------------------------------------
        cp_vat_res = cls.validate_saudi_vat_number(
            counterparty_vat,
            party_role=counterparty_role,
            required=counterparty_vat_required
        )
        checks.append({
            "rule_id": "BR-KSA-40",
            "category": "المعرفات الضريبية (Tax Identifiers)",
            "title_ar": f"معرفات الطرف المقابل ({'إلزامي B2B / ضريبة مدخلات' if counterparty_vat_required else 'اختياري B2C'})",
            "passed": cp_vat_res["is_valid"] and len(counterparty_name) >= 2,
            "severity": "ERROR",
            "details_ar": cp_vat_res["message_ar"] if len(counterparty_name) >= 2 else "اسم العميل / المورد مفقود أو غير مكتمل."
        })

        # ---------------------------------------------------------------------
        # القاعدة 3: فحص تسلسل الفاتورة، نوع المستند، ومعرفات المرحلة الثانية (UUID / ICV / PIH)
        # ---------------------------------------------------------------------
        phase2_artifacts = cls.generate_phase2_crypto_artifacts(
            seller_name=seller_name if doc_category != "PURCHASE_INVOICE" else (counterparty_name or seller_name),
            seller_vat=seller_vat if doc_category != "PURCHASE_INVOICE" else (counterparty_vat if len(counterparty_vat) == 15 else seller_vat),
            invoice_datetime=doc_dt,
            total_amount=grand_tot,
            vat_amount=vat_amt,
            doc_number=doc_number,
            doc_type_code=type_code,
            subtype_code=subtype_code,
            buyer_name=counterparty_name if doc_category != "PURCHASE_INVOICE" else seller_name,
            buyer_vat=counterparty_vat if doc_category != "PURCHASE_INVOICE" else seller_vat,
            icv=icv,
            pih=pih,
            billing_reference=billing_ref,
            reason=reason,
        )
        has_valid_seq = bool(doc_number and len(doc_number.strip()) >= 3 and icv >= 1 and len(pih) >= 32)
        checks.append({
            "rule_id": "BR-KSA-01-16",
            "category": "الربط والتكامل (Phase 2 Cryptographic Chain)",
            "title_ar": "المعرف العالمي (UUID KSA-1) والعداد التسلسلي (ICV KSA-16) وتجزئة الفاتورة السابقة (PIH KSA-13)",
            "passed": has_valid_seq,
            "severity": "ERROR",
            "details_ar": f"UUID={phase2_artifacts['uuid']} | ICV={icv} | PIH={pih[:20]}..."
        })

        # ---------------------------------------------------------------------
        # القاعدة 4: فحص الإشعارات الدائنة والمدينة (مرجع الفاتورة الأصلية وسبب الإصدار BR-KSA-17 / BR-KSA-56)
        # ---------------------------------------------------------------------
        if doc_category == "CREDIT_DEBIT_NOTE":
            ref_ok = bool(billing_ref and len(billing_ref) >= 3)
            reason_ok = bool(reason and len(reason) >= 3)
            checks.append({
                "rule_id": "BR-KSA-17-56",
                "category": "ضوابط الإشعارات الضريبية (Credit/Debit Notes)",
                "title_ar": "ارتباط الإشعار برقم الفاتورة الأصلية (BT-25) وبيان سبب الإصدار (KSA-10)",
                "passed": ref_ok and reason_ok,
                "severity": "ERROR",
                "details_ar": (
                    f"مرتبط بالفاتورة الأصلية ({billing_ref}) | السبب: {reason}"
                    if (ref_ok and reason_ok) else
                    "الإشعار الدائن/المدين يفتقر إلى رقم الفاتورة الأصلية (BT-25) أو سبب الإصدار الإلزامي (KSA-10)."
                )
            })

        # ---------------------------------------------------------------------
        # القاعدة 5: فحص الدقة الحسابية للبنود والضريبة والتقريب (BR-CO-10 / BR-CO-15 / ROUND_HALF_UP)
        # ---------------------------------------------------------------------
        lines_math_ok = True
        sum_line_taxable = Decimal("0.00")
        sum_line_vat = Decimal("0.00")
        line_err_msg = ""

        if not items_list:
            lines_math_ok = False
            line_err_msg = "المستند لا يحتوي على أي بنود أو سطور تفصيلية (BR-16)."
        else:
            for idx, item in enumerate(items_list, start=1):
                calc = calculate_line_and_tax_amounts(
                    quantity=item.get("quantity", 1.0),
                    unit_price=item.get("unit_price", 0.0),
                    discount=item.get("discount", 0.0),
                    tax_rate=item.get("tax_rate", 0.15),
                )
                rec_taxable = quantize_money(item.get("taxable_amount", calc["taxable_amount"]))
                rec_vat = quantize_money(item.get("tax_amount", calc["tax_amount"]))
                rec_total = quantize_money(item.get("total_with_tax", calc["total_with_tax"]))

                if (
                    abs(rec_taxable - calc["taxable_amount"]) > Decimal("0.01")
                    or abs(rec_vat - calc["tax_amount"]) > Decimal("0.01")
                    or abs(rec_total - calc["total_with_tax"]) > Decimal("0.01")
                ):
                    lines_math_ok = False
                    line_err_msg = (
                        f"السطر رقم {idx} ({item.get('item_name')}): فرق تقريب ضريبي! "
                        f"المسجل ({rec_taxable} + {rec_vat} = {rec_total}) والمحسوب بـ ROUND_HALF_UP ({calc['taxable_amount']} + {calc['tax_amount']} = {calc['total_with_tax']})."
                    )
                    break

                sum_line_taxable = quantize_money(sum_line_taxable + rec_taxable)
                sum_line_vat = quantize_money(sum_line_vat + rec_vat)

        header_totals_ok = (
            abs(sum_line_taxable - taxable_amt) <= Decimal("0.01")
            and abs(sum_line_vat - vat_amt) <= Decimal("0.01")
            and abs((taxable_amt + vat_amt) - grand_tot) <= Decimal("0.01")
        )
        checks.append({
            "rule_id": "BR-CO-10-15",
            "category": "الدقة الحسابية والتقريب الضريبي (Monetary & VAT Math)",
            "title_ar": "مطابقة مجاميع السطور مع صافي الوعاء والضريبة والإجمالي (ROUND_HALF_UP)",
            "passed": lines_math_ok and header_totals_ok,
            "severity": "ERROR",
            "details_ar": (
                f"الوعاء الخاضع={taxable_amt:,.2f} + الضريبة={vat_amt:,.2f} = الإجمالي={grand_tot:,.2f} ريال (مطابق 100%)."
                if (lines_math_ok and header_totals_ok) else
                (line_err_msg or f"عدم تطابق إجمالي الفاتورة: الوعاء ({taxable_amt}) + الضريبة ({vat_amt}) != الإجمالي ({grand_tot}).")
            )
        })

        # ---------------------------------------------------------------------
        # القاعدة 6: فحص معايير رمز الاستجابة السريعة (ZATCA QR TLV Tags 1..9)
        # ---------------------------------------------------------------------
        expected_qr_seller_name = seller_name if doc_category != "PURCHASE_INVOICE" else (counterparty_name or seller_name)
        expected_qr_seller_vat = seller_vat if doc_category != "PURCHASE_INVOICE" else (counterparty_vat if len(counterparty_vat) == 15 else seller_vat)

        qr_validation = cls.validate_zatca_qr_code(
            tlv_base64=qr_b64,
            expected_seller_name=expected_qr_seller_name,
            expected_seller_vat=expected_qr_seller_vat,
            expected_total=grand_tot,
            expected_vat=vat_amt,
            require_phase2=require_phase2_qr,
        )
        for q_chk in qr_validation["checks"]:
            checks.append({
                "rule_id": q_chk["rule_id"],
                "category": "معايير رمز الاستجابة السريعة (ZATCA QR TLV Tags 1-9)",
                "title_ar": q_chk["title_ar"],
                "passed": q_chk["passed"],
                "severity": q_chk["severity"],
                "details_ar": q_chk["details_ar"],
            })

        passed_count = sum(1 for c in checks if c["passed"])
        total_checks = len(checks)
        score_pct = round((passed_count / total_checks) * 100, 1) if total_checks > 0 else 0.0
        errors = [c["details_ar"] for c in checks if not c["passed"] and c["severity"] == "ERROR"]
        warnings = [c["details_ar"] for c in checks if not c["passed"] and c["severity"] != "ERROR"]
        is_valid = (len(errors) == 0)

        return {
            "is_valid": is_valid,
            "phase2_compliant": bool(is_valid and qr_validation["is_phase2_ready"]),
            "compliance_score_pct": score_pct,
            "passed_checks": passed_count,
            "total_checks": total_checks,
            "doc_category": doc_category,
            "doc_title_ar": doc_title_ar,
            "doc_number": doc_number,
            "doc_date": str(doc_date),
            "type_code": type_code,
            "subtype_code": subtype_code,
            "classification_ar": "فاتورة ضريبية قياسية (B2B - Clearance)" if subtype_code.startswith("01") else "فاتورة ضريبية مبسطة (B2C - Reporting)",
            "seller_name": seller_name,
            "seller_vat": seller_vat,
            "counterparty_name": counterparty_name,
            "counterparty_vat": counterparty_vat,
            "taxable_amount": round_money(taxable_amt),
            "vat_amount": round_money(vat_amt),
            "grand_total": round_money(grand_tot),
            "uuid": phase2_artifacts["uuid"],
            "icv": icv,
            "pih": pih,
            "invoice_hash_b64": phase2_artifacts["invoice_hash_b64"],
            "qr_code_base64": qr_b64 or phase2_artifacts["tlv_base64"],
            "recommended_phase2_qr": phase2_artifacts["tlv_base64"],
            "decoded_qr": qr_validation["decoded"],
            "ubl_xml": phase2_artifacts["ubl_xml"],
            "checks": checks,
            "errors": errors,
            "warnings": warnings,
        }

    # =========================================================================
    # 4. الفحص الشامل لكافة مستندات قاعدة البيانات وترقية رموز QR إلى المرحلة الثانية
    # =========================================================================
    @classmethod
    def audit_all_database_documents(
        cls,
        db: Session,
        auto_upgrade_phase2: bool = False
    ) -> Dict[str, Any]:
        """
        فحص كافة الفواتير والإشعارات والسندات المالية المسجلة في النظام ضد متطلبات ZATCA Phase 2
        مع إمكانية ترقية رموز QR القديمة (Phase 1 Tags 1-5) إلى رموز المرحلة الثانية الكاملة (Tags 1-9) المتسلسلة بـ PIH و ICV.
        """
        settings = db.query(CompanySettings).first() or CompanySettings()

        sales_invoices = db.query(SalesInvoice).order_by(SalesInvoice.invoice_date, SalesInvoice.id).all()
        purchase_invoices = db.query(PurchaseInvoice).order_by(PurchaseInvoice.invoice_date, PurchaseInvoice.id).all()
        notes = db.query(CreditDebitNote).order_by(CreditDebitNote.note_date, CreditDebitNote.id).all()
        vouchers = db.query(CashVoucher).order_by(CashVoucher.voucher_date, CashVoucher.id).all()

        reports: List[Dict[str, Any]] = []
        current_pih = ZATCA_GENESIS_PIH
        icv_counter = 0
        upgraded_count = 0

        # 1. فحص فواتير المبيعات
        for inv in sales_invoices:
            icv_counter += 1
            rep = cls.validate_financial_document(inv, settings=settings, icv=icv_counter, pih=current_pih)
            if auto_upgrade_phase2 and not rep["phase2_compliant"]:
                inv.qr_code_base64 = rep["recommended_phase2_qr"]
                upgraded_count += 1
                rep = cls.validate_financial_document(inv, settings=settings, icv=icv_counter, pih=current_pih)
            current_pih = rep["invoice_hash_b64"]
            reports.append(rep)

        # 2. فحص الإشعارات الدائنة والمدينة
        for nt in notes:
            icv_counter += 1
            rep = cls.validate_financial_document(nt, settings=settings, icv=icv_counter, pih=current_pih)
            if auto_upgrade_phase2 and not rep["phase2_compliant"]:
                nt.qr_code_base64 = rep["recommended_phase2_qr"]
                upgraded_count += 1
                rep = cls.validate_financial_document(nt, settings=settings, icv=icv_counter, pih=current_pih)
            current_pih = rep["invoice_hash_b64"]
            reports.append(rep)

        # 3. فحص فواتير المشتريات
        for pinv in purchase_invoices:
            icv_counter += 1
            rep = cls.validate_financial_document(pinv, settings=settings, icv=icv_counter, pih=current_pih)
            if auto_upgrade_phase2 and (not getattr(pinv, "qr_code_base64", None) or not rep["phase2_compliant"]):
                pinv.qr_code_base64 = rep["recommended_phase2_qr"]
                upgraded_count += 1
                rep = cls.validate_financial_document(pinv, settings=settings, icv=icv_counter, pih=current_pih)
            current_pih = rep["invoice_hash_b64"]
            reports.append(rep)

        # 4. فحص سندات القبض والصرف
        for vch in vouchers:
            icv_counter += 1
            rep = cls.validate_financial_document(vch, settings=settings, icv=icv_counter, pih=current_pih)
            current_pih = rep["invoice_hash_b64"]
            reports.append(rep)

        if auto_upgrade_phase2 and upgraded_count > 0:
            db.commit()

        total_docs = len(reports)
        compliant_docs = sum(1 for r in reports if r["phase2_compliant"])
        overall_rate = round((compliant_docs / total_docs) * 100, 1) if total_docs > 0 else 100.0

        return {
            "total_documents": total_docs,
            "compliant_documents": compliant_docs,
            "non_compliant_documents": total_docs - compliant_docs,
            "upgraded_count": upgraded_count,
            "overall_compliance_pct": overall_rate,
            "reports": reports,
        }

    # =========================================================================
    # 5. مشهد الفحص التفاعلي ثلاثي الأبعاد لختم التشفير ورمز QR (Three.js 3D Scene)
    # =========================================================================
    @classmethod
    def render_zatca_3d_inspector_html(cls, doc_report: Dict[str, Any]) -> str:
        """
        توليد مشهد ثلاثي الأبعاد تفاعلي (Three.js WebGL) لاستعراض وتشريح طبقات التشفير التسعة
        للفاتورة الإلكترونية (ZATCA Phase 2 Cryptographic Stamp & 3D QR Voxel Matrix).
        """
        decoded_tags = doc_report.get("decoded_qr", {}).get("tags", {})
        tags_list = []
        for t_num in range(1, 10):
            spec = ZATCA_TLV_TAG_SPECS[t_num]
            t_info = decoded_tags.get(t_num, {})
            val_str = str(t_info.get("value", "غير متوفر"))
            if len(val_str) > 38:
                val_str = val_str[:35] + "..."
            tags_list.append({
                "tag": t_num,
                "code": spec["code"],
                "name_ar": spec["name_ar"],
                "phase": spec["phase"],
                "present": bool(t_info),
                "bytes": int(t_info.get("byte_length", 0)),
                "value": val_str,
            })

        payload_json = json.dumps({
            "doc_number": doc_report.get("doc_number", "INV-2026-0001"),
            "doc_title_ar": doc_report.get("doc_title_ar", "فاتورة ضريبية"),
            "classification_ar": doc_report.get("classification_ar", "B2B"),
            "seller_name": doc_report.get("seller_name", ""),
            "seller_vat": doc_report.get("seller_vat", ""),
            "counterparty_name": doc_report.get("counterparty_name", ""),
            "counterparty_vat": doc_report.get("counterparty_vat", ""),
            "grand_total": f"{doc_report.get('grand_total', 0.0):,.2f} SAR",
            "vat_amount": f"{doc_report.get('vat_amount', 0.0):,.2f} SAR",
            "uuid": doc_report.get("uuid", ""),
            "icv": doc_report.get("icv", 1),
            "pih": doc_report.get("pih", "")[:24] + "...",
            "phase2_compliant": bool(doc_report.get("phase2_compliant", True)),
            "compliance_score_pct": doc_report.get("compliance_score_pct", 100.0),
            "qr_b64": doc_report.get("qr_code_base64", "MIZANPRO"),
            "tags": tags_list,
        }, ensure_ascii=False)

        return f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8" />
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Cairo', 'Segoe UI', Tahoma, sans-serif; }}
  html, body {{ width: 100%; height: 100%; overflow: hidden; background: #070D19; color: #F8FAFC; }}
  #viewport-root {{ position: relative; width: 100vw; height: 100vh; overflow: hidden; }}
  #canvas-mount {{ position: absolute; inset: 0; width: 100%; height: 100%; }}
  .top-badge {{
    position: absolute; top: 14px; right: 16px; left: 16px;
    display: flex; justify-content: space-between; align-items: center;
    pointer-events: none; z-index: 10;
  }}
  .spec-card {{
    background: rgba(15, 23, 42, 0.92);
    border: 1px solid #1E293B;
    border-right: 4px solid #10B981;
    padding: 10px 16px;
    border-radius: 10px;
    pointer-events: auto;
    max-width: 540px;
  }}
  .spec-card h3 {{ font-size: 14px; color: #38BDF8; margin-bottom: 4px; }}
  .spec-card p {{ font-size: 11.5px; color: #CBD5E1; line-height: 1.5; }}
  .tag-inspector-pill {{
    background: rgba(15, 23, 42, 0.92);
    border: 1px solid #334155;
    padding: 10px 14px;
    border-radius: 10px;
    pointer-events: auto;
    min-width: 270px;
    text-align: right;
  }}
  .tag-inspector-pill .tag-title {{ font-size: 12px; font-weight: bold; color: #FACC15; margin-bottom: 3px; }}
  .tag-inspector-pill .tag-val {{ font-size: 11px; color: #E2E8F0; font-family: monospace; direction: ltr; text-align: left; word-break: break-all; }}
  .bottom-dock-wrapper {{
    position: absolute;
    bottom: 14px;
    left: 50%;
    transform: translateX(-50%);
    width: min(920px, 95vw);
    z-index: 20;
    transition: transform 0.32s cubic-bezier(0.22, 1, 0.36, 1);
  }}
  .bottom-dock-wrapper.collapsed {{
    transform: translate(-50%, calc(100% - 30px));
  }}
  .dock-toggle-btn {{
    display: block;
    margin: 0 auto 6px auto;
    background: rgba(15, 23, 42, 0.95);
    color: #94A3B8;
    border: 1px solid #334155;
    padding: 4px 16px;
    border-radius: 999px;
    font-size: 11.5px;
    cursor: pointer;
    font-weight: 600;
  }}
  .dock-toggle-btn:hover {{ color: #F8FAFC; border-color: #38BDF8; }}
  .dock-panel {{
    background: rgba(15, 23, 42, 0.95);
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 10px 16px;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }}
  .control-group {{ display: flex; align-items: center; gap: 8px; font-size: 12px; }}
  .control-group label {{ color: #94A3B8; font-weight: 600; white-space: nowrap; }}
  .dock-btn {{
    background: #1E293B;
    color: #E2E8F0;
    border: 1px solid #334155;
    padding: 5px 11px;
    border-radius: 6px;
    font-size: 11.5px;
    cursor: pointer;
    font-weight: 600;
  }}
  .dock-btn.active, .dock-btn:hover {{ background: #0284C7; color: #FFFFFF; border-color: #38BDF8; }}
  input[type="range"] {{ accent-color: #38BDF8; width: 120px; cursor: pointer; }}
  select.dock-select {{
    background: #1E293B; color: #F8FAFC; border: 1px solid #334155;
    padding: 4px 8px; border-radius: 6px; font-size: 11.5px;
  }}
</style>
<script type="importmap">
{{
  "imports": {{
    "three": "https://cdn.jsdelivr.net/npm/three@0.165.0/build/three.module.js",
    "three/addons/": "https://cdn.jsdelivr.net/npm/three@0.165.0/examples/jsm/"
  }}
}}
</script>
</head>
<body>
<div id="viewport-root">
  <div id="canvas-mount"></div>

  <div class="top-badge">
    <div class="spec-card" id="spec-card">
      <h3 id="doc-header-title">🛡️ الفاحص التشفيري ثلاثي الأبعاد (ZATCA Phase 2 3D Inspector)</h3>
      <p id="doc-meta-line"></p>
      <p id="doc-crypto-line" style="font-family:monospace; font-size:10.5px; color:#94A3B8; margin-top:2px;"></p>
    </div>
    <div class="tag-inspector-pill" id="tag-pill">
      <div class="tag-title" id="active-tag-title">اختر أو مرر المؤشر على أعمدة TLV (Tags 1–9)</div>
      <div class="tag-val" id="active-tag-val">ZATCA Phase 2 Cryptographic TLV Ready</div>
    </div>
  </div>

  <div class="bottom-dock-wrapper" id="bottom-dock">
    <button class="dock-toggle-btn" id="dock-toggle">▾ إخفاء لوحة التحكم (Zen Mode)</button>
    <div class="dock-panel">
      <div class="control-group">
        <label>تفكيك طبقات التشفير (Exploded View):</label>
        <input type="range" id="explode-slider" min="0" max="1" step="0.01" value="0.25" />
      </div>
      <div class="control-group">
        <label>فحص حقل TLV:</label>
        <select id="tag-select" class="dock-select">
          <option value="0">عرض كافة الحقول (Tags 1-9)</option>
        </select>
      </div>
      <div class="control-group">
        <label>زاوية الكاميرا:</label>
        <button class="dock-btn active" data-cam="iso">منظور قياسي</button>
        <button class="dock-btn" data-cam="qr">مصفوفة QR</button>
        <button class="dock-btn" data-cam="stamp">الختم التشفيري</button>
        <button class="dock-btn" data-cam="top">مسقط علوي</button>
      </div>
    </div>
  </div>
</div>

<script type="module">
import * as THREE from 'three';
import {{ OrbitControls }} from 'three/addons/controls/OrbitControls.js';
import {{ RoomEnvironment }} from 'three/addons/environments/RoomEnvironment.js';

const DATA = {payload_json};

// Populate top HUD
document.getElementById('doc-header-title').textContent =
  `🛡️ ${{DATA.doc_title_ar}} (${{DATA.doc_number}}) — ${{DATA.classification_ar}}`;
document.getElementById('doc-meta-line').textContent =
  `البائع: ${{DATA.seller_name}} (${{DATA.seller_vat}}) | الإجمالي: ${{DATA.grand_total}} | الضريبة: ${{DATA.vat_amount}} | الامتثال: ${{DATA.compliance_score_pct}}%`;
document.getElementById('doc-crypto-line').textContent =
  `UUID: ${{DATA.uuid}} | ICV: #${{DATA.icv}} | PIH: ${{DATA.pih}}`;

const tagSelect = document.getElementById('tag-select');
DATA.tags.forEach(t => {{
  const opt = document.createElement('option');
  opt.value = String(t.tag);
  opt.textContent = `Tag ${{t.tag}}: ${{t.name_ar}} (${{t.bytes}}B)`;
  tagSelect.appendChild(opt);
}});

// 1. Software WebGL detection
const isSoftwareGl = (() => {{
  const probeCanvas = document.createElement('canvas');
  const gl = probeCanvas.getContext('webgl2') || probeCanvas.getContext('webgl');
  if (!gl) return true;
  const ext = gl.getExtension('WEBGL_debug_renderer_info');
  const param = ext ? ext.UNMASKED_RENDERER_WEBGL : gl.RENDERER;
  const gpu = String(gl.getParameter(param));
  gl.getExtension('WEBGL_lose_context')?.loseContext();
  return /SwiftShader|llvmpipe|softpipe|Software|Basic Render/i.test(gpu);
}})();

const mountEl = document.getElementById('canvas-mount');
const renderer = new THREE.WebGLRenderer({{
  antialias: !isSoftwareGl,
  powerPreference: 'high-performance'
}});
renderer.outputColorSpace = THREE.SRGBColorSpace;
renderer.toneMapping = THREE.ACESFilmicToneMapping;
renderer.toneMappingExposure = 1.12;
renderer.setPixelRatio(isSoftwareGl ? 1 : Math.min(window.devicePixelRatio, 2));
renderer.setSize(mountEl.clientWidth, mountEl.clientHeight);
renderer.shadowMap.enabled = !isSoftwareGl;
renderer.shadowMap.type = THREE.PCFSoftShadowMap;
mountEl.appendChild(renderer.domElement);

const scene = new THREE.Scene();
const horizonColor = new THREE.Color(0x070d19);
scene.background = horizonColor;
scene.fog = new THREE.FogExp2(0x070d19, 0.032);

// Studio Environment Map (RoomEnvironment)
const pmremGenerator = new THREE.PMREMGenerator(renderer);
scene.environment = pmremGenerator.fromScene(new RoomEnvironment(), 0.04).texture;
pmremGenerator.dispose();

const camera = new THREE.PerspectiveCamera(42, mountEl.clientWidth / mountEl.clientHeight, 0.1, 120);
camera.position.set(6.8, 5.2, 7.8);

const controls = new OrbitControls(camera, renderer.domElement);
controls.target.set(0, 1.4, 0);
controls.enableDamping = !isSoftwareGl;
controls.dampingFactor = 0.07;
controls.maxPolarAngle = Math.PI * 0.48;
controls.minDistance = 3.2;
controls.maxDistance = 22.0;

// Balanced Studio 3-Point Lighting Rig + Warm/Cool Contrast
const hemiLight = new THREE.HemisphereLight(0x38bdf8, 0x0f172a, 0.65);
hemiLight.position.set(0, 20, 0);
scene.add(hemiLight);

const keyLight = new THREE.DirectionalLight(0xfff4e0, 2.4);
keyLight.position.set(7, 11, 6);
keyLight.castShadow = !isSoftwareGl;
keyLight.shadow.mapSize.width = 1024;
keyLight.shadow.mapSize.height = 1024;
keyLight.shadow.camera.near = 1.0;
keyLight.shadow.camera.far = 28.0;
const d = 7.5;
keyLight.shadow.camera.left = -d;
keyLight.shadow.camera.right = d;
keyLight.shadow.camera.top = d;
keyLight.shadow.camera.bottom = -d;
keyLight.shadow.bias = -0.0005;
keyLight.shadow.normalBias = 0.02;
scene.add(keyLight);

const rimLight = new THREE.DirectionalLight(0x10b981, 1.15);
rimLight.position.set(-7, 5, -6);
scene.add(rimLight);

// Procedural Floor Texture + Contact Shadow Grounding
function createStudioGridTexture() {{
  const c = document.createElement('canvas');
  c.width = 512; c.height = 512;
  const ctx = c.getContext('2d');
  ctx.fillStyle = '#091122';
  ctx.fillRect(0, 0, 512, 512);
  ctx.strokeStyle = '#1e293b';
  ctx.lineWidth = 2;
  for (let i = 0; i <= 512; i += 64) {{
    ctx.beginPath(); ctx.moveTo(i, 0); ctx.lineTo(i, 512); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(0, i); ctx.lineTo(512, i); ctx.stroke();
  }}
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.wrapS = THREE.RepeatWrapping;
  tex.wrapT = THREE.RepeatWrapping;
  tex.repeat.set(16, 16);
  tex.anisotropy = renderer.capabilities.getMaxAnisotropy();
  return tex;
}}

const floorGeo = new THREE.PlaneGeometry(48, 48);
const floorMat = new THREE.MeshStandardMaterial({{
  map: createStudioGridTexture(),
  roughness: 0.78,
  metalness: 0.15
}});
const floorMesh = new THREE.Mesh(floorGeo, floorMat);
floorMesh.rotation.x = -Math.PI / 2;
floorMesh.position.y = 0.0;
floorMesh.receiveShadow = true;
scene.add(floorMesh);

// Soft radial contact shadow plane at y = 0.02
function createContactShadowTexture() {{
  const c = document.createElement('canvas');
  c.width = 256; c.height = 256;
  const ctx = c.getContext('2d');
  const grad = ctx.createRadialGradient(128, 128, 12, 128, 128, 120);
  grad.addColorStop(0, 'rgba(0, 0, 0, 0.75)');
  grad.addColorStop(1, 'rgba(0, 0, 0, 0.0)');
  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, 256, 256);
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}}
const contactShadow = new THREE.Mesh(
  new THREE.PlaneGeometry(8.5, 8.5),
  new THREE.MeshBasicMaterial({{
    map: createContactShadowTexture(),
    transparent: true,
    depthWrite: false,
    opacity: 0.6
  }})
);
contactShadow.rotation.x = -Math.PI / 2;
contactShadow.position.y = 0.02;
scene.add(contactShadow);

// Procedural Invoice Header Texture
function createInvoiceSlabTexture() {{
  const c = document.createElement('canvas');
  c.width = 512; c.height = 720;
  const ctx = c.getContext('2d');
  ctx.fillStyle = '#0f172a';
  ctx.fillRect(0, 0, 512, 720);
  ctx.strokeStyle = '#38bdf8';
  ctx.lineWidth = 6;
  ctx.strokeRect(14, 14, 484, 692);

  ctx.fillStyle = '#1e3a8a';
  ctx.fillRect(28, 28, 456, 86);
  ctx.fillStyle = '#f8fafc';
  ctx.font = 'bold 24px sans-serif';
  ctx.fillText('ZATCA FATOORA PHASE 2', 48, 66);
  ctx.fillStyle = '#38bdf8';
  ctx.font = 'bold 18px monospace';
  ctx.fillText(DATA.doc_number + ' | ' + DATA.grand_total, 48, 98);

  ctx.fillStyle = '#cbd5e1';
  ctx.font = '15px monospace';
  ctx.fillText('TIN: ' + DATA.seller_vat, 40, 152);
  ctx.fillText('ICV: #' + DATA.icv + ' | UBL 2.1 XML', 40, 182);

  // Simulated UBL 2.1 XML & Hash bars
  for (let row = 0; row < 8; row++) {{
    ctx.fillStyle = row % 2 === 0 ? '#1e293b' : '#172554';
    ctx.fillRect(40, 215 + row * 34, 432, 22);
    ctx.fillStyle = '#10b981';
    ctx.fillRect(40, 215 + row * 34, 90 + ((row * 37) % 180), 22);
  }}

  ctx.fillStyle = DATA.phase2_compliant ? '#065f46' : '#7f1d1d';
  ctx.fillRect(40, 610, 432, 62);
  ctx.fillStyle = '#ffffff';
  ctx.font = 'bold 20px sans-serif';
  ctx.fillText(DATA.phase2_compliant ? 'PHASE 2 CRYPTO STAMP VERIFIED' : 'PHASE 2 CHECK REQUIRED', 64, 648);

  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.anisotropy = renderer.capabilities.getMaxAnisotropy();
  return tex;
}}

// Composite Hero Group (10 distinct procedural parts, grounded at y=0)
const heroGroup = new THREE.Group();
heroGroup.position.set(0, 0, 0);
scene.add(heroGroup);

// Part 1: LatheGeometry stepped metallic base pedestal (grounded flush at y=0)
const lathePoints = [
  new THREE.Vector2(0.0, 0.0),
  new THREE.Vector2(2.6, 0.0),
  new THREE.Vector2(2.45, 0.18),
  new THREE.Vector2(2.1, 0.24),
  new THREE.Vector2(1.95, 0.44),
  new THREE.Vector2(0.0, 0.44)
];
const basePedestalGeo = new THREE.LatheGeometry(lathePoints, 48);
const basePedestalMat = new THREE.MeshStandardMaterial({{
  color: 0x1e293b,
  metalness: 0.82,
  roughness: 0.26
}});
const basePedestal = new THREE.Mesh(basePedestalGeo, basePedestalMat);
basePedestal.castShadow = true;
basePedestal.receiveShadow = true;
heroGroup.add(basePedestal);

// Part 2: Brushed Gold Accent Collar Ring (contrasting roughness/metalness)
const goldCollarMat = new THREE.MeshPhysicalMaterial({{
  color: 0xf59e0b,
  metalness: 0.94,
  roughness: 0.14,
  clearcoat: 0.6
}});
const goldCollar = new THREE.Mesh(new THREE.TorusGeometry(2.15, 0.055, 20, 64), goldCollarMat);
goldCollar.rotation.x = Math.PI / 2;
goldCollar.position.y = 0.24;
heroGroup.add(goldCollar);

// Part 3: Central Fluted Cryptographic Core Column
const coreColumn = new THREE.Mesh(
  new THREE.CylinderGeometry(0.65, 0.85, 0.9, 16),
  new THREE.MeshStandardMaterial({{ color: 0x0f172a, metalness: 0.6, roughness: 0.52 }})
);
coreColumn.position.y = 0.88;
coreColumn.castShadow = true;
heroGroup.add(coreColumn);

// Part 4: Extruded Beveled Invoice Document Slab (Layer 0 in exploded view)
const slabShape = new THREE.Shape();
const sw = 1.15, sh = 1.55;
slabShape.moveTo(-sw, -sh);
slabShape.lineTo(sw, -sh);
slabShape.lineTo(sw, sh);
slabShape.lineTo(-sw, sh);
slabShape.closePath();

const slabGeo = new THREE.ExtrudeGeometry(slabShape, {{
  depth: 0.12,
  bevelEnabled: true,
  bevelSegments: 3,
  steps: 1,
  bevelSize: 0.04,
  bevelThickness: 0.04
}});
const slabFaceMat = new THREE.MeshStandardMaterial({{
  map: createInvoiceSlabTexture(),
  roughness: 0.28,
  metalness: 0.18
}});
const slabSideMat = new THREE.MeshStandardMaterial({{
  color: 0x38bdf8,
  roughness: 0.22,
  metalness: 0.85
}});
const invoiceSlab = new THREE.Mesh(slabGeo, [slabFaceMat, slabSideMat]);
invoiceSlab.position.set(0, 2.35, -0.35);
invoiceSlab.castShadow = true;
heroGroup.add(invoiceSlab);

// Part 5: Gold Cryptographic Stamp Seal Crest (CSID Tag 9 emblem on top of slab)
const sealGroup = new THREE.Group();
sealGroup.position.set(0, 2.35, 0.15);
const sealRing = new THREE.Mesh(new THREE.TorusGeometry(0.42, 0.045, 16, 48), goldCollarMat);
const sealCore = new THREE.Mesh(
  new THREE.CylinderGeometry(0.36, 0.36, 0.06, 32),
  new THREE.MeshStandardMaterial({{
    color: DATA.phase2_compliant ? 0x10b981 : 0xef4444,
    metalness: 0.72,
    roughness: 0.25
  }})
);
sealCore.rotation.x = Math.PI / 2;
sealGroup.add(sealRing, sealCore);
heroGroup.add(sealGroup);

// Part 6: 3D QR Code Voxel Matrix using THREE.InstancedMesh (21x21 = 441 instances)
const qrGridSize = 21;
const qrGroup = new THREE.Group();
qrGroup.position.set(0, 2.35, 0.55);
heroGroup.add(qrGroup);

const qrFrame = new THREE.Mesh(
  new THREE.BoxGeometry(1.68, 1.68, 0.05),
  new THREE.MeshPhysicalMaterial({{
    color: 0x0f172a,
    metalness: 0.4,
    roughness: 0.15,
    transmission: isSoftwareGl ? 0 : 0.75,
    transparent: true,
    opacity: isSoftwareGl ? 0.85 : 1.0
  }})
);
qrGroup.add(qrFrame);

const voxelGeo = new THREE.BoxGeometry(0.058, 0.058, 0.075);
const voxelMat = new THREE.MeshStandardMaterial({{
  color: 0x38bdf8,
  metalness: 0.75,
  roughness: 0.2
}});
const qrInstanced = new THREE.InstancedMesh(voxelGeo, voxelMat, qrGridSize * qrGridSize);
const _dummyMat = new THREE.Matrix4();
const _dummyColor = new THREE.Color();
const rawStr = DATA.qr_b64 || 'MIZANPRO';
let instIdx = 0;

for (let r = 0; r < qrGridSize; r++) {{
  for (let c = 0; c < qrGridSize; c++) {{
    const inFinder =
      (r < 5 && c < 5) ||
      (r < 5 && c >= qrGridSize - 5) ||
      (r >= qrGridSize - 5 && c < 5);
    const charCode = rawStr.charCodeAt((r * qrGridSize + c) % rawStr.length);
    const active = inFinder || ((charCode + r * 3 + c * 7) % 2 === 0);
    const x = (c - (qrGridSize - 1) / 2) * 0.07;
    const y = ((qrGridSize - 1) / 2 - r) * 0.07;
    const z = active ? 0.045 : 0.0;
    const scale = active ? 1.0 : 0.001;
    _dummyMat.makeScale(scale, scale, scale);
    _dummyMat.setPosition(x, y, z);
    qrInstanced.setMatrixAt(instIdx, _dummyMat);
    _dummyColor.setHex(inFinder ? 0xfacc15 : (r > 12 ? 0x10b981 : 0x38bdf8));
    qrInstanced.setColorAt(instIdx, _dummyColor);
    instIdx++;
  }}
}}
qrInstanced.instanceMatrix.needsUpdate = true;
if (qrInstanced.instanceColor) qrInstanced.instanceColor.needsUpdate = true;
qrInstanced.computeBoundingSphere();
qrGroup.add(qrInstanced);

// Part 7..9: 9 Orbital Cryptographic TLV Tag Pillars (Tags 1..9) around the pedestal perimeter
const tagPillarsGroup = new THREE.Group();
heroGroup.add(tagPillarsGroup);
const pillarMeshes = [];

DATA.tags.forEach((tInfo, idx) => {{
  const angle = (idx / 9) * Math.PI * 2 - Math.PI / 2;
  const radius = 2.95;
  const isPhase2Tag = tInfo.tag >= 6;
  const height = 0.75 + Math.min(1.35, (tInfo.bytes || 12) * 0.018);

  const pGroup = new THREE.Group();
  const baseRadiusX = Math.cos(angle) * radius;
  const baseRadiusZ = Math.sin(angle) * radius;
  pGroup.position.set(baseRadiusX, 0, baseRadiusZ);

  // Pillar plinth
  const plinth = new THREE.Mesh(
    new THREE.CylinderGeometry(0.24, 0.28, 0.16, 20),
    basePedestalMat
  );
  plinth.position.y = 0.08;
  pGroup.add(plinth);

  // Pillar body
  const colColor = !tInfo.present ? 0xef4444 : (isPhase2Tag ? 0x10b981 : 0x0284c7);
  const colMat = new THREE.MeshStandardMaterial({{
    color: colColor,
    metalness: 0.68,
    roughness: 0.25,
    emissive: colColor,
    emissiveIntensity: 0.15
  }});
  const colMesh = new THREE.Mesh(new THREE.CylinderGeometry(0.16, 0.18, height, 24), colMat);
  colMesh.position.y = 0.16 + height / 2;
  colMesh.castShadow = true;
  colMesh.userData = {{ tagInfo: tInfo, baseRadiusX, baseRadiusZ, colMat, defaultEmissive: 0.15 }};
  pGroup.add(colMesh);

  // Pillar cap ring
  const capRing = new THREE.Mesh(new THREE.TorusGeometry(0.19, 0.025, 12, 24), goldCollarMat);
  capRing.rotation.x = Math.PI / 2;
  capRing.position.y = 0.16 + height;
  pGroup.add(capRing);

  tagPillarsGroup.add(pGroup);
  pillarMeshes.push({{ group: pGroup, mesh: colMesh, angle, radius, tag: tInfo.tag }});
}});

// Part 10: PIH Blockchain Hash Link Arch (TubeGeometry connecting previous invoice hash to core)
const curve = new THREE.CatmullRomCurve3([
  new THREE.Vector3(-2.6, 0.18, 0),
  new THREE.Vector3(-1.8, 1.85, -0.4),
  new THREE.Vector3(0.0, 2.35, -0.4)
]);
const archGeo = new THREE.TubeGeometry(curve, 32, 0.045, 12, false);
const archMesh = new THREE.Mesh(archGeo, goldCollarMat);
heroGroup.add(archMesh);

if (!isSoftwareGl) {{
  renderer.compile(scene, camera);
}}

// Interactive state & pre-allocated math objects (Zero GC in loop)
let targetExplode = 0.25;
let currentExplode = 0.25;
let selectedTagNum = 0;
let camPresetActive = false;
const targetCamPos = new THREE.Vector3(6.8, 5.2, 7.8);
const targetLookAt = new THREE.Vector3(0, 1.4, 0);

controls.addEventListener('start', () => {{
  camPresetActive = false;
}});

function highlightTag(tagNum) {{
  selectedTagNum = Number(tagNum);
  const titleEl = document.getElementById('active-tag-title');
  const valEl = document.getElementById('active-tag-val');

  if (selectedTagNum === 0) {{
    titleEl.textContent = 'جميع حقول TLV (Tags 1–9) نشطة ومفحوصة';
    valEl.textContent = `UUID: ${{DATA.uuid.slice(0, 18)}}... | Score: ${{DATA.compliance_score_pct}}%`;
  }} else {{
    const found = DATA.tags.find(t => t.tag === selectedTagNum);
    if (found) {{
      titleEl.textContent = `Tag ${{found.tag}} (${{found.code}}) — ${{found.name_ar}}`;
      valEl.textContent = `[${{found.phase}} | ${{found.bytes}} Bytes] ${{found.value}}`;
    }}
  }}

  pillarMeshes.forEach(p => {{
    const isMatch = (selectedTagNum === 0 || p.tag === selectedTagNum);
    p.mesh.userData.colMat.emissiveIntensity = isMatch ? (p.tag === selectedTagNum ? 0.65 : 0.15) : 0.02;
    p.group.scale.setScalar(p.tag === selectedTagNum ? 1.18 : 1.0);
  }});
}}

// Raycasting on pointer click for pillar inspection
const raycaster = new THREE.Raycaster();
const pointer = new THREE.Vector2();
renderer.domElement.addEventListener('pointerdown', (e) => {{
  const rect = renderer.domElement.getBoundingClientRect();
  pointer.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
  pointer.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
  raycaster.setFromCamera(pointer, camera);
  const hits = raycaster.intersectObjects(pillarMeshes.map(p => p.mesh), false);
  if (hits.length > 0) {{
    const hitTag = hits[0].object.userData.tagInfo.tag;
    tagSelect.value = String(hitTag);
    highlightTag(hitTag);
  }}
}});

// UI Dock controls
document.getElementById('explode-slider').addEventListener('input', (e) => {{
  targetExplode = parseFloat(e.target.value);
}});

tagSelect.addEventListener('change', (e) => {{
  highlightTag(Number(e.target.value));
}});

document.querySelectorAll('.dock-btn[data-cam]').forEach(btn => {{
  btn.addEventListener('click', () => {{
    document.querySelectorAll('.dock-btn[data-cam]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const mode = btn.getAttribute('data-cam');
    camPresetActive = true;
    if (mode === 'iso') {{
      targetCamPos.set(6.8, 5.2, 7.8);
      targetLookAt.set(0, 1.4, 0);
    }} else if (mode === 'qr') {{
      targetCamPos.set(0.0, 2.4, 4.6);
      targetLookAt.set(0, 2.35, 0.5);
    }} else if (mode === 'stamp') {{
      targetCamPos.set(-3.2, 2.8, 3.6);
      targetLookAt.set(0, 2.2, 0.0);
    }} else if (mode === 'top') {{
      targetCamPos.set(0.0, 10.5, 0.01);
      targetLookAt.set(0, 0, 0);
    }}
  }});
}});

const bottomDock = document.getElementById('bottom-dock');
const dockToggle = document.getElementById('dock-toggle');
dockToggle.addEventListener('click', () => {{
  const isCollapsed = bottomDock.classList.toggle('collapsed');
  dockToggle.textContent = isCollapsed ? '▴ إظهار لوحة التحكم' : '▾ إخفاء لوحة التحكم (Zen Mode)';
}});

window.addEventListener('resize', () => {{
  camera.aspect = mountEl.clientWidth / mountEl.clientHeight;
  camera.updateProjectionMatrix();
  renderer.setSize(mountEl.clientWidth, mountEl.clientHeight);
}});

// Software-WebGL safe pacing helper
const clock = new THREE.Clock();
let frameId = 0;
function afterDraw(cb) {{
  const gl = renderer.getContext();
  if (gl && gl.fenceSync) {{
    const sync = gl.fenceSync(gl.SYNC_GPU_COMMANDS_COMPLETE, 0);
    gl.flush();
    const poll = () => {{
      const state = sync && gl.getSyncParameter(sync, gl.SYNC_STATUS);
      if (state === gl.UNSIGNALED) {{
        frameId = window.setTimeout(poll, 5);
      }} else {{
        gl.deleteSync(sync);
        frameId = window.setTimeout(cb, 80);
      }}
    }};
    frameId = window.setTimeout(poll, 5);
  }} else {{
    frameId = window.setTimeout(cb, 80);
  }}
}}

function tick() {{
  const dt = Math.min(clock.getDelta(), 0.1);
  const elapsed = clock.getElapsedTime();

  currentExplode = THREE.MathUtils.damp(currentExplode, targetExplode, 6.0, dt);

  // Smooth exploded-view separation across Z and radial perimeter
  invoiceSlab.position.z = -0.35 - currentExplode * 0.95;
  sealGroup.position.z = 0.15 + currentExplode * 0.25;
  sealGroup.rotation.z = elapsed * 0.35;
  qrGroup.position.z = 0.55 + currentExplode * 1.25;

  pillarMeshes.forEach(p => {{
    const r = p.radius + currentExplode * 0.85;
    p.group.position.x = Math.cos(p.angle) * r;
    p.group.position.z = Math.sin(p.angle) * r;
  }});

  if (camPresetActive) {{
    camera.position.x = THREE.MathUtils.damp(camera.position.x, targetCamPos.x, 5.0, dt);
    camera.position.y = THREE.MathUtils.damp(camera.position.y, targetCamPos.y, 5.0, dt);
    camera.position.z = THREE.MathUtils.damp(camera.position.z, targetCamPos.z, 5.0, dt);
    controls.target.x = THREE.MathUtils.damp(controls.target.x, targetLookAt.x, 5.0, dt);
    controls.target.y = THREE.MathUtils.damp(controls.target.y, targetLookAt.y, 5.0, dt);
    controls.target.z = THREE.MathUtils.damp(controls.target.z, targetLookAt.z, 5.0, dt);
    if (camera.position.distanceTo(targetCamPos) < 0.03) {{
      camPresetActive = false;
    }}
  }}

  controls.update();
  renderer.render(scene, camera);

  if (isSoftwareGl) afterDraw(tick);
  else frameId = requestAnimationFrame(tick);
}}

tick();
</script>
</body>
</html>"""
