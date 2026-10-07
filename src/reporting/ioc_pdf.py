"""PDF report generation for IOC analysis results."""

import logging
import re
from datetime import datetime, timezone
from html import escape
from numbers import Real
from typing import Any, Dict, Iterable, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from ..utils.thai_fonts import (
    THAI_FONT_BOLD,
    THAI_FONT_REGULAR,
    register_thai_fonts,
)
from ..web.report_source_display import build_source_display_rows
from ..web.source_classification import (
    classify_source,
    count_source_classes,
    source_status_label,
)
from ..scoring.intelligent_scoring import NON_API_SCORING_SOURCES

logger = logging.getLogger(__name__)

SOURCE_STATUS_COLORS = {
    "FLAGGED": ("#f7c1c1", "#501313"),
    "ERROR": ("#faeeda", "#633806"),
    "CLEAN": ("#e8f5e9", "#1b5e20"),
    "REPORTED": ("#e6eef7", "#0c447c"),
    "RESPONDED": ("#e6eef7", "#0c447c"),
}

NA_LABELS = {
    "domain": "N/A FOR DOMAINS",
    "ip": "N/A FOR IPS",
    "ipv4": "N/A FOR IPS",
    "ipv6": "N/A FOR IPS",
    "hash": "N/A FOR HASHES",
    "md5": "N/A FOR HASHES",
    "sha1": "N/A FOR HASHES",
    "sha256": "N/A FOR HASHES",
    "url": "N/A FOR URLS",
}


def _text(value: Any) -> str:
    """Return ReportLab-safe text for arbitrary analysis values."""
    if value is None:
        return ""
    return escape(_without_emoji(str(value)))


def _without_emoji(value: str) -> str:
    """Remove common emoji sequences that are absent from the bundled font."""
    return "".join(
        char for char in value
        if not (
            0x1F000 <= ord(char) <= 0x1FAFF
            or 0x2600 <= ord(char) <= 0x27BF
            or ord(char) == 0x25A0
            or ord(char) in {0xFE0E, 0xFE0F, 0x200D}
        )
    )


def _defang_ioc(value: Any, ioc_type: Any) -> str:
    """Return a display-only defanged IOC string."""
    text = str(value or "N/A")
    kind = str(ioc_type or "").lower()
    if kind not in {"domain", "url", "ipv4", "ipv6", "ip", "email"}:
        return text
    if kind == "url":
        text = re.sub(r"(?i)^https://", "hxxps://", text)
        text = re.sub(r"(?i)^http://", "hxxp://", text)
    if kind == "email" and "@" in text:
        local, domain = text.rsplit("@", 1)
        return f"{local}[@]{domain.replace('.', '[.]')}"
    return re.sub(r"(?<!\[)\.(?!\])", "[.]", text)


def _format_header_timestamp(value: Any) -> str:
    """Format ISO, epoch, or datetime values as a UTC header timestamp."""
    try:
        if value is None or value == "":
            return "N/A"
        if isinstance(value, datetime):
            timestamp = value
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            epoch = float(value)
            if abs(epoch) >= 100_000_000_000:
                epoch /= 1000
            timestamp = datetime.fromtimestamp(epoch, tz=timezone.utc)
        elif isinstance(value, str):
            normalized = value.strip()
            if not normalized:
                return "N/A"
            if normalized.upper().endswith(" UTC"):
                normalized = normalized[:-4].strip()
            if normalized.endswith(("Z", "z")):
                normalized = normalized[:-1] + "+00:00"
            timestamp = datetime.fromisoformat(normalized)
        else:
            return "N/A"

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (OverflowError, OSError, TypeError, ValueError):
        return "N/A"


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    if value in (None, ""):
        return []
    return [value]


def _setup_styles():
    thai_fonts_registered = register_thai_fonts()
    body_font = THAI_FONT_REGULAR if thai_fonts_registered else "Helvetica"
    bold_font = THAI_FONT_BOLD if thai_fonts_registered else "Helvetica-Bold"
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="IOCSectionHeader",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#12233f"),
        fontName=bold_font,
        spaceBefore=12,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="IOCVerdict",
        parent=styles["Normal"],
        fontSize=17,
        leading=21,
        alignment=1,
        textColor=colors.white,
        fontName=bold_font,
    ))
    styles.add(ParagraphStyle(
        name="IOCVerdictBody",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
        alignment=1,
        textColor=colors.white,
        fontName=body_font,
    ))
    styles.add(ParagraphStyle(
        name="IOCBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        spaceAfter=5,
        fontName=body_font,
    ))
    styles.add(ParagraphStyle(
        name="IOCHeaderCell",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        textColor=colors.white,
        fontName=bold_font,
    ))
    styles.add(ParagraphStyle(
        name="IOCReportMeta",
        parent=styles["BodyText"],
        fontSize=8,
        leading=12,
        alignment=2,
        textColor=colors.HexColor("#5b6a86"),
        fontName=body_font,
    ))
    styles.add(ParagraphStyle(
        name="IOCCode",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=7,
        leading=10,
        wordWrap="CJK",
    ))
    return styles


def _threat_box(result: Dict[str, Any], styles) -> Table:
    score = result.get("threat_score", 0)
    try:
        score = int(score)
    except (TypeError, ValueError):
        score = 0
    score = max(0, min(score, 100))

    verdict = str(result.get("verdict") or "UNKNOWN").upper()
    if score >= 70 or verdict == "MALICIOUS":
        background = colors.HexColor("#dc3545")
        risk = "HIGH"
    elif score >= 40 or verdict == "SUSPICIOUS":
        background = colors.HexColor("#d39e00")
        risk = "MEDIUM"
    else:
        background = colors.HexColor("#198754")
        risk = "LOW"

    data = [
        [Paragraph(f"<b>{_text(verdict)}</b>", styles["IOCVerdict"])],
        [Paragraph(f"Threat Score: <b>{score}/100</b>", styles["IOCVerdictBody"])],
        [Paragraph(f"Risk Level: <b>{risk}</b>", styles["IOCVerdictBody"])],
    ]
    table = Table(data, colWidths=[6.5 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), background),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#343a40")),
    ]))
    return table


def _data_table(rows: List[List[Any]], widths: List[float], styles) -> Table:
    rendered = []
    status_backgrounds = []
    is_source_table = bool(rows and len(rows[0]) >= 3 and rows[0][1] == "Result")
    for row_index, row in enumerate(rows):
        style = styles["IOCHeaderCell"] if row_index == 0 else styles["IOCBody"]
        rendered_row = []
        for col_index, cell in enumerate(row):
            cell_style = style
            if is_source_table and row_index > 0 and col_index == 1:
                background_hex, foreground_hex = SOURCE_STATUS_COLORS.get(
                    str(cell).upper(), ("#e6eef7", "#0c447c")
                )
                background = colors.HexColor(background_hex)
                foreground = colors.HexColor(foreground_hex)
                cell_style = ParagraphStyle(
                    name=f"IOCSourceStatus{row_index}",
                    parent=styles["IOCBody"],
                    alignment=1,
                    fontSize=8,
                    textColor=foreground,
                )
                status_backgrounds.append(
                    ("BACKGROUND", (col_index, row_index), (col_index, row_index), background)
                )
            rendered_row.append(Paragraph(
                f"<b>{_text(cell)}</b>" if row_index == 0 else _text(cell),
                cell_style,
            ))
        rendered.append(rendered_row)
    table = Table(rendered, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12233f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#adb5bd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ] + status_backgrounds))
    return table


def _source_detail_text(
    source_key: str,
    source_data: Any,
    cls: str,
    ioc_type: Any,
) -> str:
    """Build source detail text only from recorded source fields."""
    data = source_data if isinstance(source_data, dict) else {}
    key = str(source_key).lower()
    detail = "No additional detail"

    if cls == "error":
        error_text = str(data.get("error") or "")
        http_match = re.search(r"\bHTTP\s+(\d{3})\b", error_text, re.IGNORECASE)
        if http_match:
            code = http_match.group(1)
            if code in {"401", "403"}:
                return f"Authentication failed (HTTP {code}). Source not evaluated."
            return f"Request failed (HTTP {code}). Source not evaluated."
        if data.get("feed_status") == "unavailable":
            return "Feed unavailable. Source not evaluated."
        return "Source error. Source not evaluated."

    if cls == "clean":
        checked = data.get("sources_checked")
        if isinstance(checked, Real) and not isinstance(checked, bool):
            return f"Not found in {checked:g} trackers."
        return "Not found."

    if key == "virustotal" and data.get("detections") == "6/91":
        detail = "6 of 91 engines"
        last_analysis = data.get("last_analysis")
        if last_analysis not in (None, ""):
            detail += f", last analysis {last_analysis}"
        detail += "."
    elif key == "threatfox" and cls == "flagged":
        fields = []
        if data.get("confidence") not in (None, ""):
            fields.append(f"Confidence {data['confidence']}%")
        if data.get("score") not in (None, ""):
            fields.append(f"score {data['score']}")
        if data.get("first_seen") not in (None, ""):
            first_seen = re.match(r"^\d{4}-\d{2}-\d{2}", str(data["first_seen"]))
            if first_seen:
                fields.append(f"first seen {first_seen.group(0)}")
        detail = "Listed."
        if fields:
            detail += f" {', '.join(fields)}."

    if (
        source_status_label(data) in {"REPORTED", "FLAGGED"}
        and key not in NON_API_SCORING_SOURCES
    ):
        detail += " Context only, not part of the score."
    return detail


def _na_label(ioc_type: Any) -> str:
    return NA_LABELS.get(str(ioc_type or "").strip().lower(), "N/A")


def _source_rows(sources: Any, ioc_type: Any = None) -> List[List[Any]]:
    rows: List[List[Any]] = [["Source", "Result", "Detail"]]
    if not isinstance(sources, dict):
        return rows
    classes = {name: classify_source(value) for name, value in sources.items()}
    for display_row in build_source_display_rows(sources, classes):
        if display_row["source_class"] == "na":
            continue
        source_name = display_row["source_names"][0]
        detail = " / ".join(
            _source_detail_text(
                name,
                sources.get(name, {}),
                classify_source(sources.get(name, {})),
                ioc_type,
            )
            for name in display_row["source_names"]
        )
        rows.append([
            display_row["display_name"],
            source_status_label(sources.get(source_name, {})),
            detail,
        ])
    return rows


def _mitre_entries(value: Any) -> List[Tuple[str, str]]:
    entries: List[Tuple[str, str]] = []
    if isinstance(value, dict):
        for technique_id, detail in value.items():
            if isinstance(detail, dict):
                description = detail.get("name") or detail.get("technique_name") or detail.get("description") or detail
            else:
                description = detail
            entries.append((str(technique_id), str(description)))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                technique_id = item.get("technique_id") or item.get("techniqueID") or item.get("id") or "N/A"
                description = item.get("technique_name") or item.get("name") or item.get("description") or item
                entries.append((str(technique_id), str(description)))
            else:
                entries.append((str(item), ""))
    elif value not in (None, ""):
        entries.append((str(value), ""))
    return entries


def _paragraph_items(values: Iterable[Any], styles) -> List[Paragraph]:
    return [Paragraph(f"&#8226; {_text(value)}", styles["IOCBody"]) for value in values]


def _report_header(report_title: str, metadata: Dict[str, Any], styles) -> Table:
    display_title = "IOC analysis report" if report_title.startswith("IOC") else report_title.title()
    brand = Paragraph(
        f'<font size="16" color="#12233f"><b>{_text(display_title)}</b></font><br/>'
        '<font color="#5b6a86">CABTA - Cyan Agent Blue Team Assistant</font>',
        styles["IOCBody"],
    )
    lines = [
        f"Report {_text(metadata.get('analysis_id') or 'N/A')}",
        f"Analyzed {_text(_format_header_timestamp(metadata.get('created_at')))}",
        f"Generated {_text(_format_header_timestamp(metadata.get('generated_at')))}",
    ]
    if metadata.get("version"):
        lines.append(f"CABTA v{_text(metadata['version'])}")
    meta = Paragraph("<br/>".join(lines), styles["IOCReportMeta"])
    table = Table([[brand, meta]], colWidths=[4.3 * inch, 2.2 * inch])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 1, colors.HexColor("#12233f")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return table


def generate_ioc_pdf(
    result: dict,
    output_path: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Generate a role-scoped report PDF and return its path, or ``None``."""
    if not isinstance(result, dict):
        logger.error("[IOC-PDF] Result must be a dictionary")
        return None

    styles = _setup_styles()
    metadata = metadata if isinstance(metadata, dict) else {}
    try:
        analysis_type = str(metadata.get("analysis_type") or "ioc").lower()
        is_ioc = analysis_type == "ioc"
        type_label = {"file": "FILE", "email": "EMAIL"}.get(analysis_type, "ANALYSIS")
        report_title = "IOC ANALYSIS REPORT" if is_ioc else f"{type_label} ANALYSIS REPORT"
        document = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=42,
            leftMargin=42,
            topMargin=42,
            bottomMargin=42,
            title=report_title.title(),
        )
        story = [
            _report_header(report_title, metadata, styles),
            Spacer(1, 14),
        ]

        if not is_ioc:
            summary = result.get("summary") or result.get("executive_summary")
            story.append(Paragraph("Analysis summary", styles["IOCSectionHeader"]))
            story.append(Paragraph(
                _text(summary or "This export contains the available report summary only."),
                styles["IOCBody"],
            ))
            if result.get("threat_score") is not None:
                story.append(Paragraph(
                    f"Threat score: <b>{_text(result.get('threat_score'))}/100</b>",
                    styles["IOCBody"],
                ))
            story.append(Paragraph(
                "This is a summary export for a non-IOC analysis type.",
                styles["IOCBody"],
            ))
            story.extend([
                Spacer(1, 18),
                HRFlowable(width="100%", thickness=0.75, color=colors.HexColor("#adb5bd")),
                Spacer(1, 6),
                Paragraph("Generated by CABTA - Cyan Agent Blue Team Assistant", styles["IOCBody"]),
            ])
            document.build(story)
            logger.info("[IOC-PDF] Report saved: %s", output_path)
            return output_path

        story.extend([_threat_box(result, styles), Spacer(1, 14)])

        ioc = result.get("ioc") or "N/A"
        ioc_type = result.get("ioc_type") or "Unknown"
        sources = result.get("sources", {})
        counts = count_source_classes(sources)
        queried = counts["responded"] + counts["errors"]
        story.extend([
            Paragraph("Investigation Summary", styles["IOCSectionHeader"]),
            _data_table([
                ["Field", "Value"],
                ["IOC", _defang_ioc(ioc, ioc_type)],
                ["IOC Type", ioc_type],
                ["Sources Queried", queried],
            ], [1.8 * inch, 4.7 * inch], styles),
        ])

        count_table = Table([[
            Paragraph(f"<b>FLAGGED</b><br/>{counts['flagged']}", styles["IOCBody"]),
            Paragraph(f"<b>RESPONDED</b><br/>{counts['responded']}", styles["IOCBody"]),
            Paragraph(f"<b>ERRORS</b><br/>{counts['errors']}", styles["IOCBody"]),
            Paragraph(f"<b>{_text(_na_label(ioc_type))}</b><br/>{counts['na']}", styles["IOCBody"]),
        ]], colWidths=[1.625 * inch] * 4)
        count_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8f9fa")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cfd6e4")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        story.extend([
            Spacer(1, 8),
            count_table,
            Paragraph(
                "Responded includes flagged sources. Errors were queried but returned no usable result; N/A sources were not queried.",
                styles["IOCBody"],
            ),
        ])
        source_rows = _source_rows(sources, ioc_type)
        story.append(Paragraph("Source results", styles["IOCSectionHeader"]))
        if len(source_rows) > 1:
            story.append(_data_table(source_rows, [1.25 * inch, 1.1 * inch, 4.15 * inch], styles))
        else:
            story.append(Paragraph("No source results available.", styles["IOCBody"]))
        if counts["na"]:
            story.append(Paragraph(
                f"{counts['na']} sources are not applicable to this indicator type.",
                styles["IOCBody"],
            ))

        llm = result.get("llm_analysis", {})
        if isinstance(llm, dict) and llm:
            story.append(Paragraph("AI Analysis", styles["IOCSectionHeader"]))
            if llm.get("verdict"):
                story.append(Paragraph(f"<b>Verdict:</b> {_text(llm['verdict'])}", styles["IOCBody"]))
            if llm.get("analysis"):
                story.append(Paragraph(_text(llm["analysis"]).replace("\n", "<br/>") , styles["IOCBody"]))
            llm_recommendations = _as_list(llm.get("recommendations"))
            if llm_recommendations:
                story.append(Paragraph("AI Recommendations", styles["IOCSectionHeader"]))
                story.extend(_paragraph_items(llm_recommendations, styles))
        else:
            story.append(Paragraph("AI Analysis", styles["IOCSectionHeader"]))
            status_text = {
                "disabled": "disabled",
                "failed": "unavailable",
            }.get(result.get("ai_status"), "not available")
            story.append(Paragraph(
                f"AI analysis {status_text} for this report.",
                styles["IOCBody"],
            ))

        recommendations = _as_list(result.get("recommendations"))
        if recommendations:
            story.append(Paragraph("Recommendations", styles["IOCSectionHeader"]))
            story.extend(_paragraph_items(recommendations, styles))

        mitre_entries = _mitre_entries(result.get("mitre_mapping"))
        if mitre_entries:
            story.append(Paragraph("MITRE ATT&amp;CK Mapping", styles["IOCSectionHeader"]))
            story.append(_data_table(
                [["Technique", "Description"]] + [[technique, description] for technique, description in mitre_entries],
                [1.5 * inch, 5.0 * inch],
                styles,
            ))

        detection_rules = result.get("detection_rules", {})
        if isinstance(detection_rules, dict) and detection_rules:
            story.append(Paragraph("Detection Rules", styles["IOCSectionHeader"]))
            for rule_type, rule_content in detection_rules.items():
                story.append(Paragraph(f"<b>{_text(str(rule_type).upper())}</b>", styles["IOCBody"]))
                story.append(Paragraph(_text(rule_content).replace("\n", "<br/>") , styles["IOCCode"]))
                story.append(Spacer(1, 6))

        story.extend([
            Spacer(1, 18),
            HRFlowable(width="100%", thickness=0.75, color=colors.HexColor("#adb5bd")),
            Spacer(1, 6),
            Paragraph("Generated by CABTA - Cyan Agent Blue Team Assistant", styles["IOCBody"]),
        ])
        document.build(story)
        logger.info("[IOC-PDF] Report saved: %s", output_path)
        return output_path
    except Exception as exc:
        logger.error("[IOC-PDF] Generation failed: %s", exc, exc_info=True)
        return None
