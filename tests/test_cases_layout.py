from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "templates" / "cases.html"
CSS = ROOT / "static" / "css" / "cases.css"


def test_cases_template_and_css_match_list_layout() -> None:
    source = TEMPLATE.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")

    assert "{% block page_title %}{% endblock %}" in source
    assert "{% block page_subtitle %}{% endblock %}" in source
    assert 'class="cases-page"' in source
    assert "body:has(.cases-page) .sub-header" in css
    assert ".cases-page {\n    padding-top: 56px;\n}" in css
    assert '<link rel="stylesheet" href="/static/css/cases.css?v=1">' in source

    assert "CASE <em>MANAGEMENT</em>" in source
    assert "INVESTIGATION CASES" in source and "LINKED ANALYSES" in source
    labels = re.findall(r"<span>(TOTAL|OPEN|CRITICAL|RESOLVED|LINKED ANALYSES)</span>", source)
    assert labels == ["TOTAL", "OPEN", "CRITICAL", "RESOLVED", "LINKED ANALYSES"]
    assert 'class="cases-distribution"' in source
    assert 'class="cases-distribution-segment cases-distribution-open"' in source
    assert 'class="cases-distribution-segment cases-distribution-resolved"' in source
    assert 'class="btn btn-primary cases-new-case" data-bs-toggle="modal" data-bs-target="#newCaseModal"' in source
    assert ".cases-page .cases-new-case" in css
    assert "background-color: var(--cases-accent);" in css
    assert "color: #02141a;" in css
    assert ".cases-page .cases-stat-linked strong { --cases-stat-color: var(--cases-open); }" in css

    assert 'class="cases-toolbar"' in source
    assert "&gt;_" in source
    assert 'id="caseSearch"' in source
    assert 'placeholder="search case id, title, severity..."' in source
    assert "<kbd>/</kbd>" in source
    filter_buttons = re.findall(
        r'<button type="button" data-case-filter="([^"]+)"[^>]*>([^<]+)</button>',
        source,
    )
    assert filter_buttons == [("all", "ALL"), ("open", "OPEN"), ("resolved", "RESOLVED")]
    assert 'data-case-filter="all" aria-pressed="true" class="is-active"' in source
    assert 'id="casesVisibleCount"' in source
    headers = re.findall(r"<th scope=\"col\">([^<]+)</th>", source)
    assert headers == ["CASE ID", "TITLE", "SEVERITY", "STATUS", "ANALYSES", "NOTES", "CREATED"]
    assert "ACTIONS" not in headers

    for hook in (
        'id="caseSearch"', 'class="case-row"', 'id="casesTable"',
        'id="casesTableBody"', 'id="noCasesRow"', 'id="createCaseBtn"',
        'id="caseTitle"', 'id="caseSeverity"', 'id="caseDescription"',
        'id="newCaseModal"',
    ):
        assert hook in source

    assert "data-status=\"{{ case.status" in source
    assert "data-severity=\"{{ case.severity" in source
    assert "data-analyses=\"{{ case.analysis_count" in source
    assert 'data-created="{{ case.created_at | default(\'\') | e }}"' in source
    assert "function applyCaseFilters()" in source
    assert source.count("function applyCaseFilters()") == 1
    assert "applyCaseFilters();" in source
    assert "status === 'open' || status === 'investigating'" in source
    assert "status === 'resolved' || status === 'closed'" in source
    assert "searchInput.addEventListener('input', applyCaseFilters)" in source
    assert "event.key !== '/'" in source
    assert "searchInput.focus();" in source
    assert "function formatCaseDate(value)" in source
    assert "date.getUTCDate()" in source and "date.getUTCHours()" in source
    assert "cell.textContent = formatCaseDate(cell.dataset.created || '')" in source
    assert 'id="noCasesRow" {% if cases %}hidden{% endif %}' in source
    assert "if (emptyState) emptyState.hidden = visible !== 0;" in source
    assert "if (visibleCount) visibleCount.textContent = visible + ' / ' + rows.length;" in source
    assert "Number.isFinite(analyses)" in source
    assert "segmentedTotal ?" in source

    split_start = source.index('<div class="cases-split">')
    table_panel = source.index('<div class="card cases-table-panel">', split_start)
    detail_panel = source.index('<aside id="caseDetail" class="cases-detail"', table_panel)
    split_end = source.index('</div>', detail_panel)
    assert split_start < table_panel < detail_panel < split_end
    assert 'tabindex="0"' in source
    assert 'aria-selected="false"' in source
    assert 'classList.toggle(\'is-selected\', selected)' in source
    assert "setAttribute('aria-selected', selected ? 'true' : 'false')" in source
    assert "makeSection('LINKED ANALYSES'" in source
    assert "makeSection('NOTES'" in source
    assert "makeSection('ACTIVITY'" in source
    assert "'Open full case →'" in source
    assert "fetch('/api/cases/' + encodeURIComponent(requestedId)" in source
    assert "if (selectedCaseId !== requestedId || generation !== selectionGeneration) return;" in source
    assert "else if (!selectedCaseId" in source and "selectCase(visibleRows[0])" in source
    assert "if (!visibleRows.length) clearCaseSelection();" in source
    assert "element.textContent = String(value);" in source
    assert ".innerHTML" not in source
    assert "onclick=" not in source

    assert "{% set cases_can_write = cases_role in ['SOC Analyst Tier 1-2', 'Incident Responder', 'Threat Hunter', 'admin'] %}" in source
    assert "{% if cases_can_write %}<button type=\"button\" class=\"btn btn-primary cases-new-case\"" in source
    assert "data-can-write=\"{{ 'true' if cases_can_write else 'false' }}\"" in source
    assert "if (caseDetail.dataset.canWrite === 'true')" in source
    assert "['note', 'Add note'], ['analysis', 'Link analysis']" in source
    build_detail_start = source.index("function buildCaseDetail(row)")
    build_detail_end = source.index("function renderCaseDetails(parts, data, row)", build_detail_start)
    build_detail_script = source[build_detail_start:build_detail_end]
    assert "var parts = {" in build_detail_script
    assert "return parts;" in build_detail_script
    assert "openInlineCaseForm(action[0], formSlot, row, parts, selectionGeneration)" in build_detail_script
    assert "cases-detail-inline-form" in source
    assert "cases-detail-form-controls" in source
    assert "cases-detail-form-error" in source
    assert "contentInput.addEventListener('input', updateSaveState)" in source
    assert "saveButton.disabled = !contentInput.value.trim()" in source
    assert "'/notes'" in source and "JSON.stringify({ author: author, content: value })" in source
    assert "'/analyses?analysis_id=' + encodeURIComponent(value)" in source
    assert "var url = '/api/cases/' + encodeURIComponent(caseId);" in source
    assert "caseDetailsCache.delete(caseId);" in source
    assert "loadCaseDetails(row, parts, caseId, generation);" in source
    assert source.index("caseDetailsCache.delete(caseId);") < source.index("loadCaseDetails(row, parts, caseId, generation);")
    assert "row.dataset.analyses = String(analysisCount);" in source
    assert "row.dataset.notes = String(noteCount);" in source
    assert "row.cells[4].textContent = String(analysisCount)" in source
    assert "row.cells[5].textContent = String(noteCount)" in source
    assert "window.updateCaseStats = updateCaseStats;" in source
    assert "if (selectedCaseId !== requestedId || generation !== selectionGeneration) return;" in source
    assert ".cases-detail-header > .cases-id" in css
    assert "width: fit-content;" in css

    assert '[data-theme="light"] .cases-page' in css
    scoped_css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    for match in re.finditer(r"([^{}]+)\{", scoped_css):
        header = match.group(1).strip()
        if header.startswith("@") or header in {"from", "to"}:
            continue
        for selector in header.split(","):
            selector = selector.strip()
            assert (
                selector.startswith(".cases-page")
                or selector.startswith('[data-theme="light"] .cases-page')
                or selector == "body:has(.cases-page) .sub-header"
            )
