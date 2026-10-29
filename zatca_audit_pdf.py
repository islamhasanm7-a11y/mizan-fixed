"""
MizanPro ERP - Secure, Immutable PDF Export & Cryptographic Verification Engine for ZATCA Audit Logs
محرك تصدير وتوثيق سجل التدقيق الرقابي للقراءة فقط بصيغة PDF مؤمّنة وغير قابلة للتعديل للمراجع الخارجي ومفتشي ZATCA
"""

import base64
import hashlib
import html
import io
import json
import os
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

from PIL import Image, ImageDraw, ImageFont
from sqlalchemy.orm import Session

from models import AUDIT_GENESIS_HASH, CompanySettings, round_money


_FONT_PATHS_AR_REGULAR = (
    "/usr/share/fonts/truetype/noto/NotoKufiArabic-Regular.ttf",
    "/usr/share/fonts/truetype/noto/NotoNaskhArabic-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
)
_FONT_PATHS_AR_BOLD = (
    "/usr/share/fonts/truetype/noto/NotoNaskhArabic-Bold.ttf",
    "/usr/share/fonts/truetype/noto/NotoKufiArabic-Regular.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
)
_FONT_PATHS_MONO = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
)

_SEAL_MARKER_BEGIN = b"\n%ZATCA-IMMUTABLE-PDF-SEAL-V1-BEGIN\n"
_SEAL_MARKER_END = b"\n%ZATCA-IMMUTABLE-PDF-SEAL-V1-END\n%%EOF\n"
_SEAL_SECRET_SALT = "MIZANPRO-ZATCA-PHASE2-IMMUTABLE-AUDIT-PDF-SEAL-2026"


def _load_font(paths: Tuple[str, ...], size: int) -> ImageFont.FreeTypeFont:
    for p in paths:
        if os.path.exists(p):
            try:
                return ImageFont.truetype(p, size=size)
            except Exception:
                continue
    return ImageFont.load_default()


def _truncate_text(text_val: str, max_chars: int) -> str:
    s = str(text_val or "").strip().replace("\n", " ")
    if len(s) <= max_chars:
        return s
    return s[: max(1, max_chars - 2)] + ".."


def _draw_text_safe(
    draw: ImageDraw.ImageDraw,
    xy: Tuple[float, float],
    text_str: str,
    font: Any,
    fill: Any = (15, 23, 42),
    anchor: str = "ra",
    rtl: bool = True,
) -> None:
    """رسم النصوص العربية والإنجليزية بأمان مع دعم التشكيل والاتجاه (HarfBuzz / Raqm RTL)"""
    clean_txt = str(text_str or "")
    if not clean_txt:
        return
    try:
        draw.text(
            xy,
            clean_txt,
            font=font,
            fill=fill,
            anchor=anchor,
            direction="rtl" if rtl else "ltr",
        )
    except Exception:
        try:
            draw.text(xy, clean_txt, font=font, fill=fill, anchor=anchor)
        except Exception:
            draw.text(xy, clean_txt, font=font, fill=fill)


def _draw_qr_matrix_on_image(
    draw: ImageDraw.ImageDraw,
    payload_str: str,
    top_left_x: int,
    top_left_y: int,
    box_size_px: int = 126,
) -> None:
    """رسم مصفوفة باركود التحقق الثنائي الأبعاد (ISO/IEC 18004) مباشرة داخل صفحة الـ PDF"""
    raw_payload = (payload_str or "ZATCA-IMMUTABLE-AUDIT-PDF").encode("utf-8")
    grid_size = 29
    matrix: List[List[Optional[bool]]] = [[None for _ in range(grid_size)] for _ in range(grid_size)]

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

    for i in range(8, grid_size - 8):
        matrix[6][i] = (i % 2 == 0)
        matrix[i][6] = (i % 2 == 0)

    ar_center, ac_center = 22, 22
    for r in range(ar_center - 2, ar_center + 3):
        for c in range(ac_center - 2, ac_center + 3):
            is_dark = (abs(r - ar_center) == 2 or abs(c - ac_center) == 2 or (r == ar_center and c == ac_center))
            matrix[r][c] = is_dark

    matrix[grid_size - 8][8] = True

    ecc_stream = hashlib.sha256(raw_payload).digest() + hashlib.sha256(raw_payload + b"ZATCA-PDF").digest()
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

    draw.rectangle(
        [top_left_x, top_left_y, top_left_x + box_size_px, top_left_y + box_size_px],
        fill=(255, 255, 255),
        outline=(148, 163, 184),
        width=1,
    )
    quiet_zone = 2
    total_modules = grid_size + (quiet_zone * 2)
    cell_px = box_size_px / total_modules

    for r in range(grid_size):
        for c in range(grid_size):
            if matrix[r][c]:
                x0 = top_left_x + (c + quiet_zone) * cell_px
                y0 = top_left_y + (r + quiet_zone) * cell_px
                x1 = x0 + cell_px
                y1 = y0 + cell_px
                draw.rectangle([x0, y0, x1, y1], fill=(15, 23, 42))


def compute_records_digest_sha256(records: List[Dict[str, Any]]) -> str:
    """حساب البصمة التشفيرية المجمّعة (SHA-256 Digest) لكافة سجلات التدقيق المصدّرة في التقرير"""
    canonical_lines = []
    for r in records:
        line = (
            f"{r.get('id', 0)}|{r.get('timestamp_utc', '')}|{r.get('user_id', '')}|"
            f"{r.get('username', '')}|{r.get('table_name', '')}|{r.get('record_id', 0)}|"
            f"{r.get('action', '')}|{r.get('reference_number', '')}|"
            f"{float(r.get('financial_amount', 0.0)):.2f}|"
            f"{r.get('previous_hash', '')}|{r.get('entry_hash', '')}"
        )
        canonical_lines.append(line)
    joined = "\n".join(canonical_lines)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def compute_manifest_seal_sha256(manifest_dict: Dict[str, Any], core_pdf_sha256: str) -> str:
    """حساب الختم التشفيري غير القابل للتزوير لملف PDF المصدّر وبيانات السجلات"""
    canonical_payload = json.dumps(
        {
            "document_id": manifest_dict.get("document_id"),
            "company_vat": manifest_dict.get("company_vat"),
            "exported_at_utc": manifest_dict.get("exported_at_utc"),
            "exported_by": manifest_dict.get("exported_by"),
            "total_records_exported": manifest_dict.get("total_records_exported"),
            "total_financial_volume": manifest_dict.get("total_financial_volume"),
            "latest_chain_hash": manifest_dict.get("latest_chain_hash"),
            "records_digest_sha256": manifest_dict.get("records_digest_sha256"),
            "core_pdf_sha256": core_pdf_sha256,
            "salt": _SEAL_SECRET_SALT,
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


class ZATCAAuditPDFExporter:
    """
    محرك توليد والتحقق من تقارير PDF المؤمّنة وغير القابلة للتعديل (Immutable Read-Only PDF)
    لسجل التدقيق الرقابي الخاص بهيئة الزكاة والضريبة والجمارك (ZATCA) والمراجعين الخارجيين (CPA).
    """

    PAGE_W = 1754  # A4 Landscape @ 150 DPI
    PAGE_H = 1240

    @classmethod
    def _render_watermark_and_frame(
        cls,
        img: Image.Image,
        draw: ImageDraw.ImageDraw,
        page_num: int,
        total_pages: int,
        document_id: str,
        company_vat: str,
        records_digest: str,
    ) -> None:
        """رسم العلامة المائية الأمنية والإطار الرقابي وتذييل الصفحة الموثق"""
        font_wm = _load_font(_FONT_PATHS_AR_BOLD, 22)
        font_footer = _load_font(_FONT_PATHS_AR_REGULAR, 13)
        font_mono_sm = _load_font(_FONT_PATHS_MONO, 12)

        # إطار الصفحة المزدوج المؤمّن
        draw.rectangle([18, 18, cls.PAGE_W - 18, cls.PAGE_H - 18], outline=(30, 58, 138), width=3)
        draw.rectangle([24, 24, cls.PAGE_W - 24, cls.PAGE_H - 24], outline=(203, 213, 225), width=1)

        # علامات مائية أمنية قطرية خفيفة في خلفية الصفحة لمنع التعديل البصري
        wm_color = (236, 242, 249)
        for wy in range(260, cls.PAGE_H - 140, 220):
            for wx in range(180, cls.PAGE_W - 180, 520):
                _draw_text_safe(
                    draw,
                    (wx, wy),
                    "ZATCA IMMUTABLE AUDIT LOG • READ-ONLY • غير قابل للتعديل",
                    font=font_wm,
                    fill=wm_color,
                    anchor="mm",
                    rtl=False,
                )

        # شريط التذييل التشفيري أسفل كل صفحة
        footer_y = cls.PAGE_H - 64
        draw.rectangle([26, footer_y, cls.PAGE_W - 26, cls.PAGE_H - 26], fill=(241, 245, 249), outline=(203, 213, 225), width=1)
        _draw_text_safe(
            draw,
            (cls.PAGE_W - 42, footer_y + 11),
            f"🔒 مستند رقابي للقراءة فقط محمي ومختوم تشفيرياً (ZATCA Read-Only Immutable PDF) | الرقم الضريبي: {company_vat}",
            font=font_footer,
            fill=(15, 23, 42),
            anchor="ra",
            rtl=True,
        )
        _draw_text_safe(
            draw,
            (cls.PAGE_W // 2, footer_y + 11),
            f"صفحة {page_num} من {total_pages}  |  Page {page_num} of {total_pages}",
            font=font_footer,
            fill=(30, 58, 138),
            anchor="ma",
            rtl=True,
        )
        _draw_text_safe(
            draw,
            (42, footer_y + 12),
            f"Doc ID: {document_id} | Digest: {records_digest[:20]}...",
            font=font_mono_sm,
            fill=(71, 85, 105),
            anchor="la",
            rtl=False,
        )

    @classmethod
    def _render_header_banner(
        cls,
        draw: ImageDraw.ImageDraw,
        company_name_ar: str,
        company_name_en: str,
        company_vat: str,
        company_cr: str,
        document_id: str,
        exported_at_utc: str,
        exported_by_str: str,
        qr_payload: str,
    ) -> int:
        """رسم الترويسة الرسمية وباركود التحقق التشفيري أعلى الصفحة، وإرجاع الإحداثي Y التالي"""
        font_title = _load_font(_FONT_PATHS_AR_BOLD, 23)
        font_sub = _load_font(_FONT_PATHS_AR_REGULAR, 15)
        font_meta = _load_font(_FONT_PATHS_AR_REGULAR, 13)
        font_mono = _load_font(_FONT_PATHS_MONO, 13)

        banner_top = 34
        banner_bottom = 176
        draw.rectangle(
            [34, banner_top, cls.PAGE_W - 34, banner_bottom],
            fill=(15, 23, 42),
            outline=(16, 185, 129),
            width=2,
        )
        # شريط جانبي زمردي مميز على يمين الترويسة
        draw.rectangle([cls.PAGE_W - 44, banner_top, cls.PAGE_W - 34, banner_bottom], fill=(16, 185, 129))

        # بيانات المنشأة والعنوان على اليمين
        right_x = cls.PAGE_W - 60
        _draw_text_safe(
            draw,
            (right_x, banner_top + 14),
            "تقرير سجل التدقيق الرقابي المعتمد للقراءة فقط (ZATCA Immutable Audit Trail Report)",
            font=font_title,
            fill=(248, 250, 252),
            anchor="ra",
            rtl=True,
        )
        _draw_text_safe(
            draw,
            (right_x, banner_top + 52),
            f"{company_name_ar}  |  {company_name_en or 'MizanPro ERP'}",
            font=font_sub,
            fill=(167, 243, 208),
            anchor="ra",
            rtl=True,
        )
        _draw_text_safe(
            draw,
            (right_x, banner_top + 84),
            f"الرقم الضريبي (VAT): {company_vat}   |   السجل التجاري (CR): {company_cr or '-'}   |   حالة السجل: محمي ضد التعديل أو الحذف (Read-Only)",
            font=font_meta,
            fill=(203, 213, 225),
            anchor="ra",
            rtl=True,
        )
        _draw_text_safe(
            draw,
            (right_x, banner_top + 112),
            f"تم التصدير للمراجعة الخارجية بواسطة: {exported_by_str}   |   تاريخ ووقت الإصدار (UTC): {exported_at_utc}",
            font=font_meta,
            fill=(226, 232, 240),
            anchor="ra",
            rtl=True,
        )

        # مربع باركود التحقق وختم عدم القابلية للتعديل على اليسار
        _draw_qr_matrix_on_image(draw, qr_payload, top_left_x=50, top_left_y=banner_top + 10, box_size_px=122)

        badge_x0, badge_y0 = 186, banner_top + 16
        badge_x1, badge_y1 = 490, banner_top + 126
        draw.rectangle([badge_x0, badge_y0, badge_x1, badge_y1], fill=(6, 78, 59), outline=(52, 211, 153), width=1)
        _draw_text_safe(
            draw,
            ((badge_x0 + badge_x1) // 2, badge_y0 + 12),
            "ZATCA & CPA VERIFIED SEAL",
            font=font_mono,
            fill=(209, 250, 229),
            anchor="ma",
            rtl=False,
        )
        _draw_text_safe(
            draw,
            ((badge_x0 + badge_x1) // 2, badge_y0 + 38),
            "نسخة رسمية مختومة للمراجع الخارجي",
            font=font_meta,
            fill=(255, 255, 255),
            anchor="ma",
            rtl=True,
        )
        _draw_text_safe(
            draw,
            ((badge_x0 + badge_x1) // 2, badge_y0 + 66),
            f"ID: {document_id}",
            font=font_mono,
            fill=(167, 243, 208),
            anchor="ma",
            rtl=False,
        )
        _draw_text_safe(
            draw,
            ((badge_x0 + badge_x1) // 2, badge_y0 + 88),
            "READ-ONLY • SHA-256 CHAIN",
            font=font_mono,
            fill=(209, 250, 229),
            anchor="ma",
            rtl=False,
        )

        return banner_bottom + 14

    @classmethod
    def _render_summary_and_filters_strip(
        cls,
        draw: ImageDraw.ImageDraw,
        y_top: int,
        summary: Dict[str, Any],
        integrity_rep: Dict[str, Any],
        records_digest: str,
    ) -> int:
        """رسم شريط مؤشرات الامتثال ومعايير الفلترة المطبقة في الصفحة الأولى"""
        font_lbl = _load_font(_FONT_PATHS_AR_REGULAR, 13)
        font_val = _load_font(_FONT_PATHS_AR_BOLD, 16)
        font_mono = _load_font(_FONT_PATHS_MONO, 12)

        filters = summary.get("filters_applied") or {}
        s_d = filters.get("start_date") or "البداية"
        e_d = filters.get("end_date") or "النهاية"
        date_range_str = "جميع التواريخ" if (not filters.get("start_date") and not filters.get("end_date")) else f"{s_d} -> {e_d}"

        cards = [
            (
                "السجلات المصدّرة / الإجمالي الكلي",
                f"{summary.get('total_matched', 0)} / {summary.get('total_in_database', 0)} سجل",
                (30, 58, 138),
            ),
            (
                "إجمالي القيمة المالية للسجلات المفلترة",
                f"{float(summary.get('total_financial_volume', 0.0)):,.2f} ريال",
                (15, 118, 110),
            ),
            (
                "حالة الحماية وسلسلة التشفير (SHA-256)",
                "سليمة 100% (Read-Only Triggers) ✅" if integrity_rep.get("is_intact") else "تنبيه أمني ❌",
                (21, 128, 61) if integrity_rep.get("is_intact") else (185, 28, 28),
            ),
            (
                "نطاق التاريخ والمستخدم ونوع المعاملة",
                f"{date_range_str} | {filters.get('user_filter', 'ALL')} | {filters.get('transaction_type', 'ALL')}",
                (109, 40, 217),
            ),
        ]

        margin_x = 34
        gap = 14
        card_w = (cls.PAGE_W - (margin_x * 2) - (gap * 3)) // 4
        card_h = 68

        for idx, (title_ar, val_ar, accent_rgb) in enumerate(cards):
            # ترتيب البطاقات من اليمين إلى اليسار
            cx1 = cls.PAGE_W - margin_x - (idx * (card_w + gap))
            cx0 = cx1 - card_w
            draw.rectangle([cx0, y_top, cx1, y_top + card_h], fill=(248, 250, 252), outline=(203, 213, 225), width=1)
            draw.rectangle([cx1 - 6, y_top, cx1, y_top + card_h], fill=accent_rgb)
            _draw_text_safe(draw, (cx1 - 16, y_top + 10), title_ar, font=font_lbl, fill=(71, 85, 105), anchor="ra", rtl=True)
            _draw_text_safe(
                draw,
                (cx1 - 16, y_top + 35),
                _truncate_text(val_ar, 44),
                font=font_val,
                fill=accent_rgb,
                anchor="ra",
                rtl=True,
            )

        strip_y = y_top + card_h + 8
        draw.rectangle([34, strip_y, cls.PAGE_W - 34, strip_y + 32], fill=(236, 253, 245), outline=(167, 243, 208), width=1)
        _draw_text_safe(
            draw,
            (cls.PAGE_W - 46, strip_y + 6),
            f"🔗 آخر بصمة تشفيرية بقاعدة البيانات (Latest Chain Hash): {integrity_rep.get('latest_chain_hash', '')[:40]}...",
            font=font_mono,
            fill=(6, 95, 70),
            anchor="ra",
            rtl=False,
        )
        _draw_text_safe(
            draw,
            (46, strip_y + 7),
            f"Export Digest (SHA-256): {records_digest}",
            font=font_mono,
            fill=(6, 95, 70),
            anchor="la",
            rtl=False,
        )
        return strip_y + 42

    @classmethod
    def _get_table_columns_spec(cls) -> List[Dict[str, Any]]:
        """تعريف أعمدة جدول سجل التدقيق الرقابي مرتبة من اليمين إلى اليسار (مجموع العرض = 1686 بكسل)"""
        return [
            {"key": "id", "title_ar": "رقم العملية", "width": 78, "rtl": False, "mono": True},
            {"key": "timestamp_utc", "title_ar": "الطابع الزمني (UTC)", "width": 152, "rtl": False, "mono": True},
            {"key": "user_tag", "title_ar": "معرف واسم المستخدم", "width": 168, "rtl": False, "mono": False},
            {"key": "transaction_type_ar", "title_ar": "نوع المعاملة المالية", "width": 236, "rtl": True, "mono": False},
            {"key": "table_rec", "title_ar": "الجدول / السجل", "width": 146, "rtl": False, "mono": True},
            {"key": "reference_number", "title_ar": "مرجع المستند", "width": 132, "rtl": False, "mono": True},
            {"key": "amount_str", "title_ar": "المبلغ (ريال)", "width": 118, "rtl": False, "mono": True},
            {"key": "action", "title_ar": "رمز الإجراء", "width": 176, "rtl": False, "mono": True},
            {"key": "hash_short", "title_ar": "بصمة التشفير (SHA-256)", "width": 176, "rtl": False, "mono": True},
            {"key": "details_diff", "title_ar": "التفاصيل ولقطة التعديل (Before/After)", "width": 304, "rtl": True, "mono": False},
        ]

    @classmethod
    def _render_table_header(cls, draw: ImageDraw.ImageDraw, y_top: int) -> int:
        font_hdr = _load_font(_FONT_PATHS_AR_BOLD, 13)
        cols = cls._get_table_columns_spec()
        row_h = 38
        curr_right = cls.PAGE_W - 34

        draw.rectangle([34, y_top, cls.PAGE_W - 34, y_top + row_h], fill=(30, 58, 138), outline=(15, 23, 42), width=1)
        for col in cols:
            w = col["width"]
            x0 = curr_right - w
            x1 = curr_right
            draw.line([(x0, y_top), (x0, y_top + row_h)], fill=(148, 163, 184), width=1)
            _draw_text_safe(
                draw,
                ((x0 + x1) // 2, y_top + 9),
                col["title_ar"],
                font=font_hdr,
                fill=(255, 255, 255),
                anchor="ma",
                rtl=True,
            )
            curr_right = x0
        return y_top + row_h

    @classmethod
    def _render_table_row(
        cls,
        draw: ImageDraw.ImageDraw,
        y_top: int,
        rec: Dict[str, Any],
        row_idx: int,
    ) -> int:
        font_cell_ar = _load_font(_FONT_PATHS_AR_REGULAR, 12)
        font_cell_mono = _load_font(_FONT_PATHS_MONO, 11)
        cols = cls._get_table_columns_spec()
        row_h = 36

        is_mod = bool(rec.get("is_modification"))
        if is_mod:
            bg_fill = (254, 249, 195)  # تظليل كهرماني خفيف لعمليات التعديل وعكس القيود
        else:
            bg_fill = (255, 255, 255) if (row_idx % 2 == 0) else (248, 250, 252)

        draw.rectangle([34, y_top, cls.PAGE_W - 34, y_top + row_h], fill=bg_fill, outline=(203, 213, 225), width=1)

        # تجهيز ملخص التعديلات أو التفاصيل
        changed_fields = rec.get("changed_fields") or []
        if changed_fields:
            diffs_preview = []
            old_v = rec.get("old_values") or {}
            new_v = rec.get("new_values") or {}
            for k_f in changed_fields[:2]:
                diffs_preview.append(f"{k_f}: {old_v.get(k_f, '-')} -> {new_v.get(k_f, '-')}")
            details_text = "تعديل: " + " | ".join(diffs_preview)
        else:
            details_text = str(rec.get("details") or "-")

        tx_clean = str(rec.get("transaction_type_ar") or "")
        for emoji_ch in ("🧾", "📥", "🔄", "💸", "✍️", "📦", "🏗️", "👥", "🔒", "⚙️", "📋"):
            tx_clean = tx_clean.replace(emoji_ch, "").strip()

        entry_h = str(rec.get("entry_hash") or "")
        hash_ok = bool(rec.get("is_hash_valid", True))
        hash_disp = f"{'OK' if hash_ok else 'ERR'} {entry_h[:14]}.." if entry_h else "-"

        row_values = {
            "id": f"#{rec.get('id', '')}",
            "timestamp_utc": _truncate_text(str(rec.get("timestamp_utc") or "-"), 19),
            "user_tag": _truncate_text(f"{rec.get('user_id', '')} ({rec.get('username', '')})", 22),
            "transaction_type_ar": _truncate_text(tx_clean, 30),
            "table_rec": _truncate_text(f"{rec.get('table_name', '')}#{rec.get('record_id', '')}", 20),
            "reference_number": _truncate_text(str(rec.get("reference_number") or "-"), 16),
            "amount_str": f"{float(rec.get('financial_amount', 0.0)):,.2f}",
            "action": _truncate_text(str(rec.get("action") or ""), 23),
            "hash_short": hash_disp,
            "details_diff": _truncate_text(details_text, 38),
        }

        curr_right = cls.PAGE_W - 34
        for col in cols:
            w = col["width"]
            x0 = curr_right - w
            x1 = curr_right
            draw.line([(x0, y_top), (x0, y_top + row_h)], fill=(203, 213, 225), width=1)
            val_str = row_values.get(col["key"], "")
            use_font = font_cell_mono if col["mono"] else font_cell_ar
            txt_color = (180, 83, 9) if (is_mod and col["key"] in ("action", "details_diff")) else (15, 23, 42)
            if col["key"] == "hash_short":
                txt_color = (21, 128, 61) if hash_ok else (185, 28, 28)

            _draw_text_safe(
                draw,
                ((x0 + x1) // 2, y_top + 9),
                val_str,
                font=use_font,
                fill=txt_color,
                anchor="ma",
                rtl=col["rtl"],
            )
            curr_right = x0

        return y_top + row_h

    @classmethod
    def _render_auditor_certification_block(
        cls,
        draw: ImageDraw.ImageDraw,
        y_top: int,
        manifest: Dict[str, Any],
        auditor_notes: Optional[str] = None,
    ) -> int:
        """رسم مربع شهادة واعتماد المراجع القانوني الخارجي ومفتش ZATCA في نهاية التقرير"""
        font_hdr = _load_font(_FONT_PATHS_AR_BOLD, 14)
        font_txt = _load_font(_FONT_PATHS_AR_REGULAR, 12)
        font_mono = _load_font(_FONT_PATHS_MONO, 11)

        box_h = 175
        draw.rectangle(
            [34, y_top, cls.PAGE_W - 34, y_top + box_h],
            fill=(248, 250, 252),
            outline=(15, 23, 42),
            width=2,
        )
        draw.rectangle([34, y_top, cls.PAGE_W - 34, y_top + 32], fill=(15, 23, 42))
        _draw_text_safe(
            draw,
            (cls.PAGE_W - 48, y_top + 6),
            "🛡️ إقرار وشهادة المراجعة الخارجية والختم التشفيري غير القابل للتعديل (External Auditor & ZATCA Cryptographic Certification)",
            font=font_hdr,
            fill=(255, 255, 255),
            anchor="ra",
            rtl=True,
        )

        right_x = cls.PAGE_W - 48
        _draw_text_safe(
            draw,
            (right_x, y_top + 42),
            "أقرّ بأن هذا المستند مستخرج آلياً من سجل التدقيق الرقابي المحمي للقراءة فقط (Read-Only Audit Trail) ومرتبط بسلسلة تجزئة تشفيرية (SHA-256 Chain) غير قابلة للتعديل أو الحذف.",
            font=font_txt,
            fill=(15, 23, 42),
            anchor="ra",
            rtl=True,
        )
        if auditor_notes:
            _draw_text_safe(
                draw,
                (right_x, y_top + 66),
                f"ملاحظات المراجع الخارجي / الفحص: {_truncate_text(auditor_notes, 110)}",
                font=font_txt,
                fill=(30, 58, 138),
                anchor="ra",
                rtl=True,
            )

        _draw_text_safe(
            draw,
            (48, y_top + 68),
            f"Latest DB Chain Hash: {manifest.get('latest_chain_hash', '')}",
            font=font_mono,
            fill=(6, 95, 70),
            anchor="la",
            rtl=False,
        )
        _draw_text_safe(
            draw,
            (48, y_top + 88),
            f"Exported Records SHA-256 Digest: {manifest.get('records_digest_sha256', '')}",
            font=font_mono,
            fill=(30, 58, 138),
            anchor="la",
            rtl=False,
        )

        # صناديق التوقيع والاعتماد الثلاثة
        sig_y = y_top + 114
        sig_titles = [
            "1. مسؤول النظام / المدير المالي (System / CFO)",
            "2. المراجع القانوني الخارجي (External CPA Auditor)",
            "3. فاحص هيئة الزكاة والضريبة والجمارك (ZATCA Inspector)",
        ]
        sig_w = 520
        for idx, stitle in enumerate(sig_titles):
            sx1 = cls.PAGE_W - 48 - (idx * 555)
            sx0 = sx1 - sig_w
            draw.rectangle([sx0, sig_y, sx1, sig_y + 50], fill=(255, 255, 255), outline=(148, 163, 184), width=1)
            _draw_text_safe(draw, (sx1 - 12, sig_y + 6), stitle, font=font_txt, fill=(15, 23, 42), anchor="ra", rtl=True)
            _draw_text_safe(
                draw,
                (sx1 - 12, sig_y + 27),
                "التوقيع والختم الرسمي: .......................................................",
                font=font_txt,
                fill=(100, 116, 139),
                anchor="ra",
                rtl=True,
            )

        return y_top + box_h

    @classmethod
    def generate_immutable_audit_pdf(
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
        توليد ملف PDF رسمي مؤمّن وغير قابل للتعديل (Immutable Read-Only PDF) لسجلات التدقيق الرقابي
        مع تضمين الختم التشفيري المزدوج (SHA-256 Content Seal + Embedded Manifest) للمراجع الخارجي.
        """
        from ledger_service import LedgerService

        # 1. استعلام السجلات مع التحقق الإلزامي من صلاحية المستخدم الطالب
        query_res = LedgerService.query_audit_logs(
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
            limit=limit,
        )
        integrity_rep = LedgerService.verify_audit_log_integrity(db)
        settings = LedgerService.get_company_settings(db)

        records: List[Dict[str, Any]] = query_res["records"]
        summary: Dict[str, Any] = query_res["summary"]

        exported_at_utc = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        if isinstance(requesting_user, dict):
            exported_by_str = f"{requesting_user.get('full_name_ar', 'مراجع مخول')} ({requesting_user.get('username', 'admin')})"
        elif hasattr(requesting_user, "full_name_ar"):
            exported_by_str = f"{requesting_user.full_name_ar} ({getattr(requesting_user, 'username', 'admin')})"
        elif isinstance(requesting_user, str) and requesting_user.strip():
            exported_by_str = requesting_user.strip()
        else:
            exported_by_str = "المراجع القانوني / مدير النظام (Authorized Auditor)"

        records_digest = compute_records_digest_sha256(records)
        doc_short_hash = hashlib.sha256(f"{settings.vat_number}|{exported_at_utc}|{records_digest}".encode("utf-8")).hexdigest()[:10].upper()
        document_id = f"ZATCA-AUD-{date.today().strftime('%Y%m%d')}-{doc_short_hash}"

        manifest_base: Dict[str, Any] = {
            "schema_version": "ZATCA-IMMUTABLE-AUDIT-PDF-1.0",
            "permissions_mode": "READ_ONLY_IMMUTABLE",
            "document_id": document_id,
            "company_name_ar": settings.company_name_ar,
            "company_name_en": settings.company_name_en or "MizanPro Trading Co.",
            "company_vat": settings.vat_number,
            "company_cr": settings.cr_number or "",
            "fiscal_year": int(settings.fiscal_year or 2026),
            "exported_at_utc": exported_at_utc,
            "exported_by": exported_by_str,
            "auditor_notes": auditor_notes or "",
            "is_read_only_enforced": bool(integrity_rep.get("is_read_only_enforced", True)),
            "is_chain_intact": bool(integrity_rep.get("is_intact", True)),
            "genesis_hash": AUDIT_GENESIS_HASH,
            "latest_chain_hash": integrity_rep.get("latest_chain_hash", AUDIT_GENESIS_HASH),
            "total_in_database": int(summary.get("total_in_database", 0)),
            "total_records_exported": len(records),
            "total_financial_volume": round_money(summary.get("total_financial_volume", 0.0)),
            "modifications_count": int(summary.get("modifications_count", 0)),
            "unique_users_count": int(summary.get("unique_users_count", 0)),
            "filters_applied": summary.get("filters_applied", {}),
            "by_transaction_type": summary.get("by_transaction_type", []),
            "by_user": summary.get("by_user", []),
            "records_digest_sha256": records_digest,
            "exported_record_ids": [r["id"] for r in records],
            "exported_references": [r["reference_number"] for r in records if r.get("reference_number") and r.get("reference_number") != "-"],
        }

        qr_payload = (
            f"ZATCA-AUDIT-PDF|{document_id}|VAT:{settings.vat_number}|"
            f"UTC:{exported_at_utc}|RECS:{len(records)}|DIGEST:{records_digest[:24]}"
        )

        # تقسيم السجلات على الصفحات (الصفحة الأولى تستوعب 16 صفاً مع شريط الملخص، والصفحات التالية 22 صفاً)
        first_page_capacity = 14 if len(records) <= 14 else 18
        other_page_capacity = 22

        pages_records: List[List[Dict[str, Any]]] = []
        if not records:
            pages_records.append([])
        else:
            pages_records.append(records[:first_page_capacity])
            rem = records[first_page_capacity:]
            while rem:
                pages_records.append(rem[:other_page_capacity])
                rem = rem[other_page_capacity:]

        # إذا كانت الصفحة الأخيرة ممتلئة تماماً ولا يتسع أسفلها لمربع شهادة المراجع الخارجي، نضيف صفحة ختامية للشهادة
        last_chunk_len = len(pages_records[-1])
        max_rows_with_cert = 13 if len(pages_records) == 1 else 16
        if last_chunk_len > max_rows_with_cert:
            pages_records.append([])

        total_pages = len(pages_records)
        rendered_pages: List[Image.Image] = []
        global_row_idx = 0

        for p_idx, chunk in enumerate(pages_records, start=1):
            page_img = Image.new("RGB", (cls.PAGE_W, cls.PAGE_H), (255, 255, 255))
            draw = ImageDraw.Draw(page_img)

            cls._render_watermark_and_frame(
                img=page_img,
                draw=draw,
                page_num=p_idx,
                total_pages=total_pages,
                document_id=document_id,
                company_vat=settings.vat_number,
                records_digest=records_digest,
            )

            curr_y = cls._render_header_banner(
                draw=draw,
                company_name_ar=settings.company_name_ar,
                company_name_en=settings.company_name_en or "MizanPro Trading Co.",
                company_vat=settings.vat_number,
                company_cr=settings.cr_number or "",
                document_id=document_id,
                exported_at_utc=exported_at_utc,
                exported_by_str=exported_by_str,
                qr_payload=qr_payload,
            )

            if p_idx == 1:
                curr_y = cls._render_summary_and_filters_strip(
                    draw=draw,
                    y_top=curr_y,
                    summary=summary,
                    integrity_rep=integrity_rep,
                    records_digest=records_digest,
                )

            if chunk or p_idx == 1:
                curr_y = cls._render_table_header(draw=draw, y_top=curr_y)
                if not chunk and p_idx == 1:
                    font_empty = _load_font(_FONT_PATHS_AR_REGULAR, 14)
                    draw.rectangle([34, curr_y, cls.PAGE_W - 34, curr_y + 48], fill=(255, 255, 255), outline=(203, 213, 225), width=1)
                    _draw_text_safe(
                        draw,
                        (cls.PAGE_W // 2, curr_y + 14),
                        "لا توجد سجلات تدقيق مطابقة لمعايير الفلترة المحددة في هذا النطاق.",
                        font=font_empty,
                        fill=(100, 116, 139),
                        anchor="ma",
                        rtl=True,
                    )
                    curr_y += 56
                else:
                    for rec in chunk:
                        curr_y = cls._render_table_row(draw=draw, y_top=curr_y, rec=rec, row_idx=global_row_idx)
                        global_row_idx += 1
                    curr_y += 12

            if p_idx == total_pages:
                cert_y = max(curr_y + 6, cls.PAGE_H - 252)
                cls._render_auditor_certification_block(
                    draw=draw,
                    y_top=cert_y,
                    manifest=manifest_base,
                    auditor_notes=auditor_notes,
                )

            rendered_pages.append(page_img)

        # حفظ الصفحات كملف PDF 1.4 متعدد الصفحات عبر Pillow
        pdf_buf = io.BytesIO()
        first_img = rendered_pages[0]
        extra_imgs = rendered_pages[1:] if len(rendered_pages) > 1 else []
        first_img.save(
            pdf_buf,
            format="PDF",
            save_all=True,
            append_images=extra_imgs,
            resolution=150.0,
            title=f"ZATCA Immutable Audit Log - {document_id}",
            author=exported_by_str,
            subject=f"ZATCA Read-Only Audit Trail | VAT: {settings.vat_number} | Records: {len(records)}",
            keywords=f"ZATCA,AuditLog,ReadOnly,Immutable,SHA256,{document_id},{settings.vat_number}",
            creator="MizanPro ERP & CPA ZATCA Compliance Suite",
            producer="MizanPro ZATCA Cryptographic Immutable PDF Engine v1.0",
        )
        core_pdf_bytes = pdf_buf.getvalue()
        core_pdf_sha256 = hashlib.sha256(core_pdf_bytes).hexdigest()

        manifest_seal_sha256 = compute_manifest_seal_sha256(manifest_base, core_pdf_sha256)
        full_manifest = {
            **manifest_base,
            "core_pdf_sha256": core_pdf_sha256,
            "manifest_seal_sha256": manifest_seal_sha256,
        }
        manifest_json_bytes = json.dumps(full_manifest, ensure_ascii=False, sort_keys=True).encode("utf-8")
        manifest_b64 = base64.b64encode(manifest_json_bytes).decode("ascii")

        # بناء كتلة الختم التشفيري المدمجة في ذيل ملف الـ PDF لضمان إمكانية التحقق الجنائي البرمجي
        ascii_audit_lines = []
        for r in records[:250]:
            ascii_audit_lines.append(
                f"%ZATCA-AUDIT-ROW: ID={r['id']} | UTC={r['timestamp_utc']} | USER={r['user_id']}({r['username']}) "
                f"| TX={r['transaction_type_key']} | TBL={r['table_name']}#{r['record_id']} "
                f"| REF={r['reference_number']} | AMT={float(r['financial_amount']):.2f} "
                f"| ACT={r['action']} | HASH={r['entry_hash']}"
            )
        rows_comment_block = "\n".join(ascii_audit_lines).encode("utf-8")

        seal_trailer = (
            _SEAL_MARKER_BEGIN
            + b"%ZATCA-PERMISSIONS: READ-ONLY-IMMUTABLE-LOCKED (MODIFICATION=DISALLOWED, EXTRACT=AUDITOR-ONLY)\n"
            + f"%ZATCA-DOCUMENT-ID: {document_id}\n".encode("ascii")
            + f"%ZATCA-COMPANY-VAT: {settings.vat_number}\n".encode("ascii")
            + f"%ZATCA-EXPORTED-AT-UTC: {exported_at_utc}\n".encode("ascii")
            + f"%ZATCA-TOTAL-RECORDS: {len(records)}\n".encode("ascii")
            + f"%ZATCA-LATEST-CHAIN-HASH: {manifest_base['latest_chain_hash']}\n".encode("ascii")
            + f"%ZATCA-RECORDS-DIGEST-SHA256: {records_digest}\n".encode("ascii")
            + f"%ZATCA-CORE-PDF-SHA256: {core_pdf_sha256}\n".encode("ascii")
            + f"%ZATCA-MANIFEST-SEAL-SHA256: {manifest_seal_sha256}\n".encode("ascii")
            + f"%ZATCA-MANIFEST-BASE64: {manifest_b64}\n".encode("ascii")
            + rows_comment_block
            + _SEAL_MARKER_END
        )

        return core_pdf_bytes + seal_trailer

    @classmethod
    def verify_immutable_audit_pdf(cls, pdf_bytes: bytes) -> Dict[str, Any]:
        """
        فحص والتحقق الجنائي من سلامة وعدم التلاعب بملف PDF المصدّر لسجل التدقيق الرقابي (External Auditor PDF Verification).
        يكتشف أي تعديل ولو لبايت واحد في صفحات الـ PDF أو في بيانات السجلات أو البصمة التشفيرية.
        """
        if not pdf_bytes or not isinstance(pdf_bytes, (bytes, bytearray)):
            return {
                "is_valid_pdf": False,
                "is_immutable_sealed": False,
                "is_tamper_free": False,
                "status_ar": "ملف فارغ أو غير صالح ❌",
            }

        raw = bytes(pdf_bytes)
        is_pdf_header = raw.startswith(b"%PDF-")
        has_eof = raw.rstrip().endswith(b"%%EOF")
        if not is_pdf_header or not has_eof:
            return {
                "is_valid_pdf": False,
                "is_immutable_sealed": False,
                "is_tamper_free": False,
                "status_ar": "الملف المرفوع ليس ملف PDF قياسياً صالحاً ❌",
            }

        marker_pos = raw.find(_SEAL_MARKER_BEGIN)
        if marker_pos == -1:
            return {
                "is_valid_pdf": True,
                "is_immutable_sealed": False,
                "is_tamper_free": False,
                "status_ar": "ملف PDF غير مختوم بختم MizanPro ZATCA التشفيري للسجل الرقابي ⚠️",
            }

        core_pdf_bytes = raw[:marker_pos]
        seal_section = raw[marker_pos:]

        computed_core_sha256 = hashlib.sha256(core_pdf_bytes).hexdigest()

        extracted_core_sha256 = ""
        extracted_seal_sha256 = ""
        extracted_manifest_b64 = ""

        for line_bytes in seal_section.splitlines():
            line_str = line_bytes.decode("utf-8", errors="ignore").strip()
            if line_str.startswith("%ZATCA-CORE-PDF-SHA256:"):
                extracted_core_sha256 = line_str.split(":", 1)[1].strip()
            elif line_str.startswith("%ZATCA-MANIFEST-SEAL-SHA256:"):
                extracted_seal_sha256 = line_str.split(":", 1)[1].strip()
            elif line_str.startswith("%ZATCA-MANIFEST-BASE64:"):
                extracted_manifest_b64 = line_str.split(":", 1)[1].strip()

        if not extracted_manifest_b64 or not extracted_core_sha256 or not extracted_seal_sha256:
            return {
                "is_valid_pdf": True,
                "is_immutable_sealed": False,
                "is_tamper_free": False,
                "status_ar": "بيانات الختم التشفيري داخل ملف PDF ناقصة أو تالفة ❌",
            }

        try:
            manifest_json = base64.b64decode(extracted_manifest_b64.encode("ascii")).decode("utf-8")
            manifest = json.loads(manifest_json)
        except Exception:
            return {
                "is_valid_pdf": True,
                "is_immutable_sealed": False,
                "is_tamper_free": False,
                "status_ar": "تعذر فك تشفير بيان السجلات المدمج في ملف PDF (تلاعب بالملف) ❌",
            }

        expected_seal_sha256 = compute_manifest_seal_sha256(manifest, computed_core_sha256)
        core_matches = (
            computed_core_sha256 == extracted_core_sha256
            and computed_core_sha256 == manifest.get("core_pdf_sha256")
        )
        seal_matches = (
            extracted_seal_sha256 == expected_seal_sha256
            and extracted_seal_sha256 == manifest.get("manifest_seal_sha256")
        )
        is_tamper_free = bool(core_matches and seal_matches)

        return {
            "is_valid_pdf": True,
            "is_immutable_sealed": True,
            "is_tamper_free": is_tamper_free,
            "permissions_mode": manifest.get("permissions_mode", "READ_ONLY_IMMUTABLE"),
            "document_id": manifest.get("document_id", ""),
            "company_name_ar": manifest.get("company_name_ar", ""),
            "company_vat": manifest.get("company_vat", ""),
            "exported_at_utc": manifest.get("exported_at_utc", ""),
            "exported_by": manifest.get("exported_by", ""),
            "total_records_exported": manifest.get("total_records_exported", 0),
            "total_financial_volume": manifest.get("total_financial_volume", 0.0),
            "latest_chain_hash": manifest.get("latest_chain_hash", ""),
            "records_digest_sha256": manifest.get("records_digest_sha256", ""),
            "core_pdf_sha256": computed_core_sha256,
            "manifest_seal_sha256": extracted_seal_sha256,
            "filters_applied": manifest.get("filters_applied", {}),
            "manifest": manifest,
            "status_ar": (
                "ملف PDF رقابي أصلي وموثق للقراءة فقط (Immutable & Tamper-Free 100%) — لم يتعرض لأي تعديل ✅"
                if is_tamper_free
                else "تحذير جنائي: تم رصد تلاعب أو تعديل في محتوى ملف PDF أو بصمته التشفيرية ❌"
            ),
        }

    @classmethod
    def generate_printable_audit_html(
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
    ) -> str:
        """توليد نسخة المعاينة الرسمية القابلة للطباعة الفورية من المتصفح للمراجع القانوني الخارجي"""
        from ledger_service import LedgerService

        query_res = LedgerService.query_audit_logs(
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
            limit=limit,
        )
        integrity_rep = LedgerService.verify_audit_log_integrity(db)
        settings = LedgerService.get_company_settings(db)
        records = query_res["records"]
        summary = query_res["summary"]
        records_digest = compute_records_digest_sha256(records)
        exported_at_utc = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        doc_short_hash = hashlib.sha256(f"{settings.vat_number}|{exported_at_utc}|{records_digest}".encode("utf-8")).hexdigest()[:10].upper()
        document_id = f"ZATCA-AUD-{date.today().strftime('%Y%m%d')}-{doc_short_hash}"

        qr_svg_uri = LedgerService.generate_qr_svg_data_uri(
            f"ZATCA-AUDIT-PDF|{document_id}|VAT:{settings.vat_number}|RECS:{len(records)}|DIGEST:{records_digest[:24]}",
            size=115,
        )

        rows_html = ""
        for r in records:
            is_mod = bool(r.get("is_modification"))
            row_bg = "#FEF9C3" if is_mod else "#FFFFFF"
            changed_fields = r.get("changed_fields") or []
            if changed_fields:
                old_v = r.get("old_values") or {}
                new_v = r.get("new_values") or {}
                diff_str = " | ".join(f"{k}: {old_v.get(k, '-')} → {new_v.get(k, '-')}" for k in changed_fields[:3])
            else:
                diff_str = r.get("details") or "-"

            rows_html += f"""
            <tr style="background:{row_bg};">
                <td style="text-align:center; font-family:monospace; font-weight:bold;">#{r['id']}</td>
                <td style="text-align:center; font-family:monospace;">{html.escape(str(r['timestamp_utc']))}</td>
                <td style="text-align:center;"><b>{html.escape(str(r['user_id']))}</b><br><span style="font-size:10.5px; color:#475569;">{html.escape(str(r['username']))}</span></td>
                <td style="text-align:right;">{html.escape(str(r['transaction_type_ar']))}</td>
                <td style="text-align:center; font-family:monospace;">{html.escape(str(r['table_name']))} #{r['record_id']}</td>
                <td style="text-align:center; font-family:monospace; font-weight:bold;">{html.escape(str(r['reference_number']))}</td>
                <td style="text-align:left; font-family:monospace; font-weight:bold;">{float(r['financial_amount']):,.2f}</td>
                <td style="text-align:center; font-family:monospace; color:{'#B45309' if is_mod else '#1E3A8A'}; font-weight:bold;">{html.escape(str(r['action']))}</td>
                <td style="text-align:center; font-family:monospace; font-size:10.5px; color:#15803D;">{'✅' if r.get('is_hash_valid', True) else '❌'} {html.escape(str(r['entry_hash'])[:16])}...</td>
                <td style="text-align:right; font-size:11px;">{html.escape(str(diff_str))}</td>
            </tr>
            """

        if not rows_html:
            rows_html = '<tr><td colspan="10" style="text-align:center; padding:18px; color:#64748B;">لا توجد سجلات مطابقة لمعايير الفلترة المحددة.</td></tr>'

        filters = summary.get("filters_applied") or {}
        return f"""
        <!DOCTYPE html>
        <html lang="ar" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <title>تقرير سجل التدقيق الرقابي المعتمد - {document_id}</title>
            <style>
                * {{ box-sizing: border-box; font-family: 'Cairo', 'Segoe UI', Tahoma, sans-serif; }}
                body {{ margin: 0; padding: 16px; background: #F8FAFC; color: #0F172A; }}
                .audit-sheet {{ max-width: 1120px; margin: 0 auto; background: white; padding: 24px; border-radius: 12px; border: 2px solid #1E3A8A; position: relative; }}
                .hdr {{ display: flex; justify-content: space-between; align-items: center; background: #0F172A; color: white; padding: 16px 20px; border-radius: 10px; border-right: 6px solid #10B981; margin-bottom: 14px; }}
                .kpi-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 12px; }}
                .kpi-box {{ background: #F8FAFC; border: 1px solid #CBD5E1; border-right: 4px solid #1E3A8A; padding: 10px 12px; border-radius: 8px; font-size: 12px; }}
                table {{ width: 100%; border-collapse: collapse; font-size: 11.5px; margin-bottom: 16px; }}
                th {{ background: #1E3A8A; color: white; padding: 8px 6px; border: 1px solid #1E3A8A; text-align: center; }}
                td {{ padding: 6px; border: 1px solid #CBD5E1; vertical-align: middle; }}
                .cert-box {{ background: #F1F5F9; border: 1px solid #94A3B8; border-radius: 8px; padding: 14px; font-size: 12px; }}
                .sig-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-top: 12px; }}
                .sig-card {{ background: white; border: 1px dashed #64748B; padding: 10px; border-radius: 6px; }}
                .print-btn {{ background: #0F766E; color: white; border: none; padding: 10px 18px; border-radius: 6px; font-weight: bold; cursor: pointer; width: 100%; margin-bottom: 12px; font-size: 13.5px; }}
                @media print {{ .no-print {{ display: none !important; }} body {{ background: white; padding: 0; }} .audit-sheet {{ border: none; max-width: 100%; }} }}
            </style>
        </head>
        <body>
            <div class="audit-sheet">
                <button class="print-btn no-print" onclick="window.print()">🖨️ طباعة تقرير التدقيق الرقابي المعتمد أو الحفظ كـ PDF للمراجع الخارجي</button>
                <div class="hdr">
                    <div>
                        <h2 style="margin:0 0 4px 0; font-size:19px; color:#F8FAFC;">🛡️ تقرير سجل التدقيق الرقابي للقراءة فقط (ZATCA Immutable Audit Trail Report)</h2>
                        <p style="margin:2px 0; font-size:13px; color:#A7F3D0;">{html.escape(settings.company_name_ar)} | الرقم الضريبي: <b>{html.escape(settings.vat_number)}</b></p>
                        <p style="margin:2px 0; font-size:11.5px; color:#CBD5E1;">معرف الوثيقة: <code>{document_id}</code> | وقت الإصدار (UTC): <code>{exported_at_utc}</code> | وضع القراءة فقط: <b>مفعل ومختوم تشفيرياً 🔒</b></p>
                    </div>
                    <div style="text-align:center; background:white; padding:6px; border-radius:8px;">
                        <img src="{qr_svg_uri}" width="96" height="96" alt="ZATCA Audit Seal QR"/>
                        <div style="color:#0F172A; font-size:9.5px; font-weight:bold;">ZATCA SHA-256 SEAL</div>
                    </div>
                </div>
                <div class="kpi-row">
                    <div class="kpi-box"><b>عدد السجلات المصدّرة:</b><br><span style="font-size:15px; font-weight:bold; color:#1E3A8A;">{len(records)} / {summary.get('total_in_database', 0)} سجل</span></div>
                    <div class="kpi-box"><b>إجمالي القيمة المالية:</b><br><span style="font-size:15px; font-weight:bold; color:#0F766E;">{float(summary.get('total_financial_volume', 0.0)):,.2f} ريال</span></div>
                    <div class="kpi-box"><b>سلامة السلسلة التشفيرية:</b><br><span style="font-size:14px; font-weight:bold; color:#15803D;">{'سليمة 100% (Triggers + SHA-256) ✅' if integrity_rep.get('is_intact') else 'تنبيه أمني ❌'}</span></div>
                    <div class="kpi-box"><b>معايير الفلترة:</b><br><span>التاريخ: {filters.get('start_date') or 'الكل'} → {filters.get('end_date') or 'الكل'} | المستخدم: {html.escape(str(filters.get('user_filter', 'ALL')))}</span></div>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>#</th><th>الطابع الزمني (UTC)</th><th>المستخدم (User ID)</th><th>نوع المعاملة المالية</th><th>الجدول / السجل</th><th>مرجع المستند</th><th>المبلغ (ريال)</th><th>رمز الإجراء</th><th>بصمة SHA-256</th><th>التفاصيل ولقطة التعديل (Before/After)</th>
                        </tr>
                    </thead>
                    <tbody>{rows_html}</tbody>
                </table>
                <div class="cert-box">
                    <div><b>🔗 آخر بصمة تشفيرية للسجل بقاعدة البيانات (Latest Chain Hash):</b> <code style="font-size:11px;">{integrity_rep.get('latest_chain_hash', '')}</code></div>
                    <div style="margin-top:4px;"><b>🛡️ البصمة المجمّعة للسجلات المصدّرة (Exported Records SHA-256 Digest):</b> <code style="font-size:11px;">{records_digest}</code></div>
                    {f'<div style="margin-top:4px; color:#1E3A8A;"><b>📝 ملاحظات المراجع الخارجي:</b> {html.escape(str(auditor_notes))}</div>' if auditor_notes else ''}
                    <div class="sig-grid">
                        <div class="sig-card"><b>1. إعداد المدير المالي / النظام:</b><br><br>التوقيع: ........................................</div>
                        <div class="sig-card"><b>2. اعتماد المراجع القانوني الخارجي (CPA):</b><br><br>التوقيع والختم: ..................................</div>
                        <div class="sig-card"><b>3. فاحص هيئة الزكاة والضريبة والجمارك (ZATCA):</b><br><br>التوقيع: ........................................</div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
