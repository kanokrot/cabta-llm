from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "templates" / "case_detail.html"
CSS = ROOT / "static" / "css" / "case_detail.css"


def test_case_detail_c1b_header_summary_and_segmented_status() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")

    assert '<link rel="stylesheet" href="/static/css/case_detail.css?v=1">' in template
    assert "body:has(.case-detail-page) .sub-header" in css
    assert "height: 0;" in css
    assert "margin-top: 0 !important;" in css
    assert ".case-detail-page {" in css and "padding-top: 56px;" in css
    assert ".case-detail-page.case-detail-page { color: var(--text-primary); }" in css
    assert ".case-detail-page .case-summary-card .case-id-chip { color: var(--color-primary); }" in css
    assert ".case-detail-page .case-summary-card .case-status-label { color: var(--text-muted); }" in css
    assert ".case-detail-page .case-detail-header .case-detail-subtitle { color: var(--text-muted); }" in css
    assert ".case-detail-page .case-summary-status .case-status-message { color: var(--text-muted); }" in css

    header = template.split('<section class="card case-summary-card"', 1)[0]
    assert '&larr; Back to cases' in header
    assert '<h1>Case <b>Detail</b></h1>' in header
    assert "Summary · incident report · linked analyses · notes" in header
    assert '&#8681; Download PDF' in header
    assert 'id="downloadIncidentReportPdfBtn"' in header

    summary = template.split('<div class="case-detail-split">', 1)[0]
    assert '{{ case.id | e }}' in summary
    assert "case.id[:8]" not in summary
    summary_top = summary.split('<div class="case-summary-tiles">', 1)[0]
    assert "case-severity-badge" not in summary_top
    status_loop = re.search(r"\{% for status in \[(.*?)\] %\}", summary, re.DOTALL)
    assert status_loop is not None
    statuses = re.findall(r"'([^']+)'", status_loop.group(1))
    assert statuses == ["Open", "Investigating", "Resolved", "Closed"]
    assert summary.count('data-case-status="{{ status }}"') == 1
    assert 'id="statusSelect"' in summary
    assert 'id="statusBadge"' in summary
    assert 'id="caseSummaryTitle"' in summary
    assert 'class="case-status-segments"' in summary
    assert 'class="case-status-segment' in summary

    tile_labels = re.findall(r'<div class="case-summary-tile"><span>([^<]+)</span>', summary)
    assert tile_labels == ["Case ID", "Severity", "Status", "Analyses", "Notes", "Created"]
    assert 'class="case-severity-badge"' in summary
    assert 'class="case-status-value case-status-open"' in summary
    assert 'id="caseAnalysisCount"' in summary
    assert 'id="caseNoteCount"' in summary
    assert "case.analyses | length" in summary
    assert "case.notes | length" in summary
    assert "No description provided." in summary

    c1_visible_copy = re.sub(r"\{[\{%].*?[\}%]\}", "", summary, flags=re.DOTALL)
    assert not re.search(r"[\u0E00-\u0E7F]", c1_visible_copy)

    assert "function setIncidentReportExists(exists)" in template
    assert "function formatCaseDate(value)" in template
    assert "date.getUTCDate()" in template
    assert "date.getUTCHours()" in template
    assert "createdAt.textContent = formatCaseDate(createdValue) || createdValue || 'N/A'" in template
    assert "Failed to update status: ' + err.message" in template
    assert "statusBadge.className = 'case-status-value case-status-' + normalizedStatus" in template
    assert "statusText.textContent = normalizedStatus" in template


def test_case_detail_c1b_split_layout_and_theme_colors() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")

    assert 'class="case-detail-split"' in template
    assert ".case-detail-split {" in css
    assert "grid-template-columns: minmax(0, 2fr) minmax(0, 1fr);" in css
    assert "@media (max-width: 1000px)" in css
    assert ".case-detail-split { grid-template-columns: 1fr; }" in css

    side_stack_start = template.index('<div class="case-detail-side-stack">')
    linked_start = template.index("<!-- Linked Analyses -->", side_stack_start)
    notes_start = template.index("<!-- Notes Section -->", linked_start)
    side_stack_end = template.index("<!-- Link Analysis Modal -->", notes_start)
    assert side_stack_start < linked_start < notes_start < side_stack_end
    assert 'class="card case-detail-linked-card"' in template[side_stack_start:side_stack_end]
    assert 'class="card case-detail-notes-card"' in template[side_stack_start:side_stack_end]

    assert "@media (max-width: 560px)" in css
    assert "grid-template-columns: repeat(2, minmax(0, 1fr));" in css
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", css)


def test_case_detail_keeps_existing_report_and_note_hooks() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")

    for hook in (
        'id="incidentReportForm"',
        'id="incidentReportStatus"',
        'id="saveIncidentReportBtn"',
        'id="analysesTableBody"',
        'id="notesContainer"',
        'id="addNoteForm"',
        'id="linkAnalysisForm"',
    ):
        assert hook in template

    assert "fetch(incidentApiUrl)" in template
    assert "method: reportExists ? 'PATCH' : 'POST'" in template


def test_case_detail_incident_report_matches_english_mockup_form() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")
    report = template.split('<section class="card case-detail-report-card"', 1)[1].split(
        '<div class="case-detail-side-stack">', 1
    )[0]

    headings = re.findall(r'<section class="case-report-section">\s*<h3>(.*?)</h3>', report)
    assert headings == ["Overview", "Attack evidence", "Investigation"]
    for label in (
        "Threat type",
        "Severity",
        "Threat description",
        "Attacker IP",
        "Target IP",
        "Affected username",
        "Attack outcome",
        "Detected at",
        "Detection device",
        "Incident notes",
        "Findings",
        "Analysis",
        "Impact",
        "Remediation &amp; prevention",
        "References",
    ):
        assert f">{label}</label>" in report

    assert "List fields: one item per line" in report
    assert 'id="incidentReportStatus"' in report
    assert 'id="incidentReportSaveState"' in report
    assert "NOT SAVED YET" in report and "SAVED" in template
    assert 'form="incidentReportForm"' in report
    assert 'id="saveIncidentReportBtn"' in report
    assert "Save report" in report
    assert "saveState.textContent = exists ? 'SAVED' : 'NOT SAVED YET'" in template
    assert "incidentListFields" in template
    assert "join('\\n')" in template
    assert "split(/\\r?\\n/)" in template
    assert not re.search(r"[\u0E00-\u0E7F]", template)

    assert ".case-report-section h3::after" in css
    assert "grid-template-columns: repeat(2, minmax(0, 1fr));" in css
    assert "background-color: var(--bg-tertiary);" in css
    assert "outline: 1px solid var(--color-primary);" in css


def test_case_detail_linked_analyses_and_notes_match_mockup() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")
    linked = template.split('<section class="card case-detail-linked-card"', 1)[1].split(
        '<!-- Notes Section -->', 1
    )[0]
    notes = template.split('<section class="card case-detail-notes-card"', 1)[1].split(
        '</section>', 1
    )[0]

    assert "Linked Analyses</h5>" in linked
    assert 'id="linkedAnalysisCount"' in linked
    assert "+ Link</button>" in linked
    assert 'data-bs-toggle="modal"' in linked
    assert 'data-bs-target="#linkAnalysisModal"' in linked
    assert 'id="analysesTableBody"' in linked
    assert 'data-analysis-id="{{ analysis.analysis_id | e }}"' in linked
    assert 'id="noAnalysesRow"' in linked
    assert 'class="case-analysis-id-chip"' in linked
    assert 'class="case-linked-at" data-case-date=' in linked
    assert 'class="case-detail-card-button" title="View Report">View</a>' in linked
    assert "bi-eye" not in linked

    assert "Notes</h5>" in notes
    assert 'id="noteHeadingCount"' in notes
    assert 'id="caseNoteCount"' in template
    assert 'class="note-meta"' in notes
    assert 'class="case-note-author"' in notes
    assert 'class="case-note-separator"' in notes
    assert 'class="case-note-date" data-case-date=' in notes
    assert "bi-person" not in notes and "bi-clock" not in notes
    add_note_button = re.search(r'<button[^>]*id="addNoteBtn"[^>]*>(.*?)</button>', notes, re.DOTALL)
    assert add_note_button is not None
    assert "+ Add note" in add_note_button.group(1)
    assert "btn-primary" not in add_note_button.group(0)

    assert "function formatCaseDates()" in template
    assert "formatCaseDate(rawValue) || rawValue" in template
    assert "formatCaseDate(data.linked_at)" in template
    assert "formatCaseDate(data.created_at)" in template
    assert "linkedAnalysisCountElement.textContent = String(analysisCount)" in template
    assert "noteHeadingCountElement.textContent = String(noteCount)" in template

    def assert_scoped_color(selector: str, color: str) -> None:
        rule = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", css, re.DOTALL)
        assert rule is not None
        assert f"color: var({color});" in rule.group(1)

    assert_scoped_color(".case-detail-page .case-detail-linked-card .case-linked-count", "--text-muted")
    assert_scoped_color(".case-detail-page .case-detail-linked-card .case-analysis-id-chip", "--color-primary")
    assert_scoped_color(".case-detail-page .case-detail-linked-card .case-analyses-empty", "--text-muted")
    assert_scoped_color(".case-detail-page .case-detail-linked-card thead th", "--text-muted")
    assert_scoped_color(".case-detail-page .case-detail-notes-card .case-note-count", "--text-muted")
    assert_scoped_color(".case-detail-page .case-detail-notes-card .note-meta", "--text-muted")
    assert_scoped_color(".case-detail-page .case-detail-notes-card .note-meta .case-note-author", "--text-primary")
    assert_scoped_color(".case-detail-page .case-detail-notes-card .case-note-separator", "--text-muted")
    assert_scoped_color(".case-detail-page .case-detail-notes-card .case-note-field label", "--text-muted")
    assert_scoped_color(".case-detail-page .case-detail-card-button", "--color-primary")
    assert ".case-detail-page .case-detail-notes-card .case-note-field .form-control:focus" in css
    assert "border-left: 2px solid var(--color-primary);" in css
    assert "background: var(--bg-tertiary);" in css
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", css)
