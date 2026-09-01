"""PDF report generation for IOC analysis results."""

import logging
from html import escape
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

logger = logging.getLogger(__name__)


def _text(value: Any) -> str:
    """Return ReportLab-safe text for arbitrary analysis values."""
    if value is None:
        return ""
    return escape(str(value))


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    if value in (None, ""):
        return []
    return [value]


def _setup_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="IOCReportTitle",
        parent=styles["Title"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0d6efd"),
        spaceAfter=16,
    ))
    styles.add(ParagraphStyle(
        name="IOCSectionHeader",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0d6efd"),
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
    ))
    styles.add(ParagraphStyle(
        name="IOCBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        spaceAfter=5,
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
        [Paragraph(f"Threat Score: <b>{score}/100</b>", styles["IOCBody"])],
        [Paragraph(f"Risk Level: <b>{risk}</b>", styles["IOCBody"])],
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
    for row_index, row in enumerate(rows):
        style = styles["IOCBody"]
        rendered.append([
            Paragraph(f"<b>{_text(cell)}</b>" if row_index == 0 else _text(cell), style)
            for cell in row
        ])
    table = Table(rendered, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d6efd")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#adb5bd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _source_rows(sources: Any) -> List[List[Any]]:
    rows: List[List[Any]] = [["Source", "Status", "Details"]]
    if not isinstance(sources, dict):
        return rows
    for name, raw_value in sources.items():
        value = raw_value if isinstance(raw_value, dict) else {"value": raw_value}
        status = value.get("status") or value.get("verdict") or (
            "Flagged" if any(value.get(key) for key in ("detected", "listed", "is_tor")) else "Checked"
        )
        details = []
        for key, item in value.items():
            if key not in {"status", "verdict"} and item not in (None, "", [], {}):
                details.append(f"{key}: {item}")
        rows.append([name, status, "; ".join(details) or "No additional details"])
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


def generate_ioc_pdf(result: dict, output_path: str) -> Optional[str]:
    """Generate an IOC analysis PDF and return its path, or ``None`` on failure."""
    if not isinstance(result, dict):
        logger.error("[IOC-PDF] Result must be a dictionary")
        return None

    styles = _setup_styles()
    try:
        document = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=42,
            leftMargin=42,
            topMargin=42,
            bottomMargin=42,
            title="IOC Analysis Report",
        )
        story = [
            Paragraph("IOC ANALYSIS REPORT", styles["IOCReportTitle"]),
            _threat_box(result, styles),
            Spacer(1, 14),
        ]

        ioc = result.get("ioc") or "N/A"
        ioc_type = result.get("ioc_type") or "Unknown"
        checked = result.get("sources_checked", 0)
        flagged = result.get("sources_flagged", 0)
        story.extend([
            Paragraph("Investigation Summary", styles["IOCSectionHeader"]),
            _data_table([
                ["Field", "Value"],
                ["IOC", ioc],
                ["IOC Type", ioc_type],
                ["Sources Checked", checked],
                ["Sources Flagged", flagged],
            ], [1.8 * inch, 4.7 * inch], styles),
        ])

        sources = result.get("sources", {})
        source_rows = _source_rows(sources)
        story.append(Paragraph("Threat Intelligence Sources", styles["IOCSectionHeader"]))
        if len(source_rows) > 1:
            story.append(_data_table(source_rows, [1.25 * inch, 1.1 * inch, 4.15 * inch], styles))
        else:
            story.append(Paragraph("No source results available.", styles["IOCBody"]))

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
