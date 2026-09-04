"""Thai-language PDF generation for case incident reports."""

import logging
from html import escape
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from fontTools.ttLib import TTFont as FontToolsTTFont
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Image,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from src.utils.thai_fonts import (
    THAI_FONT_BOLD,
    THAI_FONT_REGULAR,
    register_thai_fonts,
)


logger = logging.getLogger(__name__)

_FONT_PATH = (
    Path(__file__).resolve().parents[2]
    / "assets"
    / "fonts"
    / "Sarabun-Regular.ttf"
)
_LOGO_PATH = (
    Path(__file__).resolve().parents[2] / "assets" / "images" / "t-net.png"
)
_TIERS = ("Critical", "High", "Medium", "Low")


def _text(value: Any) -> str:
    """Return ReportLab-safe text for an arbitrary incident-report value."""
    if value is None:
        return ""
    return escape(str(value))


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    if value in (None, ""):
        return []
    return [value]


def _font_supports_glyphs(font_path: str, chars: str) -> bool:
    """Return whether a font's best Unicode cmap contains every character."""
    try:
        font = FontToolsTTFont(font_path, lazy=True)
        try:
            cmap = font.getBestCmap() or {}
            return all(ord(char) in cmap for char in chars)
        finally:
            font.close()
    except Exception:
        return False


def _render_severity_row(severity_4tier: str, glyphs_supported: bool) -> str:
    """Render the four severity choices with checkboxes or a bold marker."""
    selected = (severity_4tier or "").casefold()
    if glyphs_supported:
        return " | ".join(
            f"{'☑' if tier.casefold() == selected else '☐'} {tier}"
            for tier in _TIERS
        )
    return " | ".join(
        f"**{tier}**" if tier.casefold() == selected else tier for tier in _TIERS
    )


def _setup_styles(thai_fonts_registered: bool):
    regular = THAI_FONT_REGULAR if thai_fonts_registered else "Helvetica"
    bold = THAI_FONT_BOLD if thai_fonts_registered else "Helvetica-Bold"
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="IncidentReportTitle",
        parent=styles["Title"],
        fontName=bold,
        fontSize=20,
        leading=25,
        textColor=colors.HexColor("#0d6efd"),
        spaceAfter=16,
    ))
    styles.add(ParagraphStyle(
        name="IncidentSectionHeader",
        parent=styles["Heading2"],
        fontName=bold,
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#0d6efd"),
        spaceBefore=12,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="IncidentBody",
        parent=styles["BodyText"],
        fontName=regular,
        fontSize=10,
        leading=15,
        spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="IncidentTableHeader",
        parent=styles["BodyText"],
        fontName=bold,
        fontSize=10,
        leading=15,
        textColor=colors.white,
    ))
    styles.add(ParagraphStyle(
        name="LetterheadText",
        parent=styles["BodyText"],
        fontName=regular,
        fontSize=8.5,
        leading=12,
        alignment=2,
    ))
    return styles


def _build_letterhead(styles) -> Optional[Table]:
    """Build the company letterhead, or return ``None`` if its logo is absent."""
    if not _LOGO_PATH.exists():
        logger.warning("[INCIDENT-PDF] Letterhead logo not found: %s", _LOGO_PATH)
        return None

    logo = Image(str(_LOGO_PATH), width=0.9 * inch, height=0.9 * inch)
    company_text = Paragraph(
        "บริษัท ที-เน็ต ไอที โซลูชั่น จำกัด<br/>"
        "131 อาคารกลุ่มนวัตกรรม 1 ชั้น 2 ห้อง INC1-212 หมู่ 9<br/>"
        "ถนนพหลโยธิน ตำบลคลองหนึ่ง อำเภอคลองหลวง จังหวัดปทุมธานี 12120<br/>"
        "Tel. 02-564-7210 ต่อ 5512 Email. info@tnetitsolution.co.th",
        styles["LetterheadText"],
    )
    letterhead = Table(
        [[logo, company_text]], colWidths=[1.0 * inch, 5.5 * inch]
    )
    letterhead.setStyle(TableStyle([
        ("ALIGN", (0, 0), (0, 0), "LEFT"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return letterhead


def _data_table(rows: List[List[Any]], widths: List[float], styles) -> Table:
    rendered = []
    for row_index, row in enumerate(rows):
        style = (
            styles["IncidentTableHeader"]
            if row_index == 0
            else styles["IncidentBody"]
        )
        rendered.append([Paragraph(_text(cell), style) for cell in row])
    table = Table(rendered, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d6efd")),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#adb5bd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _paragraph_items(values: Iterable[Any], styles) -> List[Paragraph]:
    return [
        Paragraph(f"&#8226; {_text(value)}", styles["IncidentBody"])
        for value in values
    ]


def generate_incident_report_pdf(
    data: dict, output_path: str
) -> Optional[str]:
    """Generate a Thai incident-report PDF and return its path on success."""
    if not isinstance(data, dict):
        logger.error("[INCIDENT-PDF] Data must be a dictionary")
        return None

    thai_fonts_registered = register_thai_fonts()
    if not thai_fonts_registered:
        logger.warning(
            "[INCIDENT-PDF] Sarabun unavailable; falling back to Helvetica"
        )
    styles = _setup_styles(thai_fonts_registered)
    glyphs_supported = thai_fonts_registered and _font_supports_glyphs(
        str(_FONT_PATH), "☐☑"
    )

    try:
        document = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=42,
            leftMargin=42,
            topMargin=42,
            bottomMargin=42,
            title="รายงานเหตุการณ์ภัยคุกคาม",
        )
        metadata_rows = [
            ["หัวข้อ", "รายละเอียด"],
            ["ประเภทภัยคุกคาม", data.get("threat_type", "")],
            ["รายละเอียดภัยคุกคาม", data.get("threat_description", "")],
            ["IP ผู้โจมตี", data.get("attacker_ip", "")],
            ["IP เป้าหมาย", data.get("target_ip", "")],
            ["ชื่อผู้ใช้ที่ได้รับผลกระทบ", data.get("affected_username", "")],
            ["ผลลัพธ์การโจมตี", data.get("attack_outcome", "")],
            ["หมายเหตุการเกิดเหตุ", data.get("occurrence_note", "")],
            ["เวลาที่ตรวจพบ", data.get("detected_at", "")],
            ["อุปกรณ์ที่ตรวจพบ", data.get("detection_device", "")],
        ]
        severity = _render_severity_row(
            str(data.get("severity_4tier") or ""), glyphs_supported
        )
        if not glyphs_supported:
            severity = severity.replace("**", "<b>", 1).replace("**", "</b>", 1)

        story = []
        letterhead = _build_letterhead(styles)
        if letterhead is not None:
            story.extend([letterhead, Spacer(1, 10)])
        story.extend([
            Paragraph("รายงานเหตุการณ์ภัยคุกคาม", styles["IncidentReportTitle"]),
            _data_table(metadata_rows, [2.0 * inch, 4.5 * inch], styles),
            Spacer(1, 12),
            Paragraph("ระดับความรุนแรง", styles["IncidentSectionHeader"]),
            Paragraph(severity, styles["IncidentBody"]),
        ])

        sections = (
            ("ผลการตรวจสอบ", "findings"),
            ("การวิเคราะห์", "analysis"),
            ("ผลกระทบ", "impact"),
            ("การแก้ไขและป้องกัน", "remediation"),
            ("เอกสารอ้างอิง", "reference"),
        )
        for title, key in sections:
            story.append(Paragraph(title, styles["IncidentSectionHeader"]))
            items = _as_list(data.get(key))
            if items:
                story.extend(_paragraph_items(items, styles))

        story.extend([
            Spacer(1, 18),
            HRFlowable(
                width="100%", thickness=0.75, color=colors.HexColor("#adb5bd")
            ),
            Spacer(1, 6),
            Paragraph(
                "สร้างโดย CABTA - Cyan Agent Blue Team Assistant",
                styles["IncidentBody"],
            ),
        ])
        document.build(story)
        logger.info("[INCIDENT-PDF] Report saved: %s", output_path)
        return output_path
    except Exception as exc:
        logger.error("[INCIDENT-PDF] Generation failed: %s", exc, exc_info=True)
        return None
