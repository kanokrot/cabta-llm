from __future__ import annotations

import re
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from fastapi.templating import Jinja2Templates


ROOT = Path(__file__).resolve().parents[1]


def _render_investigations() -> str:
    app = FastAPI()
    templates = Jinja2Templates(directory=str(ROOT / "templates"))

    @app.get("/agent/investigations")
    async def investigations_page(request: Request):
        request.state.user = {
            "id": 1,
            "username": "investigations-test",
            "email": "investigations-test@example.test",
            "role": "admin",
        }
        return templates.TemplateResponse(
            request,
            "agent_investigations.html",
            {
                "sessions": [],
                "stats": {"total": 12, "active": 2, "completed": 8, "failed": 2},
            },
        )

    with TestClient(app) as client:
        response = client.get("/agent/investigations")

    assert response.status_code == 200
    return response.text


def test_investigations_page_renders_header_stats_meter_toolbar_and_footer() -> None:
    rendered = _render_investigations()

    assert "/static/css/investigations.css?v=1" in rendered
    assert re.search(r"<h1>\s*Agent\s*<span>Investigations</span>\s*</h1>", rendered)
    assert "Investigation Sessions · Goals · Outcomes" in rendered
    assert "New Investigation" in rendered
    assert 'data-bs-toggle="modal"' in rendered
    assert 'data-bs-target="#newInvestigationModal"' in rendered
    assert '<label class="text-muted mb-0 small">Filter:</label>' not in rendered

    for status, count in (("Total", "12"), ("Active", "2"), ("Completed", "8"), ("Failed", "2")):
        assert re.search(
            rf'<div class="stat-label">{status}</div>\s*<div class="stat-value"[^>]*>{count}</div>',
            rendered,
        )

    assert 'id="investigationsMeterCompleted"' in rendered
    assert 'id="investigationsMeterFailed"' in rendered
    assert rendered.count('style="width:0%"') == 2
    assert 'id="goalSearchInput"' in rendered
    assert 'placeholder="search by goal or session id…"' in rendered
    assert '&gt;_' in rendered
    assert '<kbd class="investigations-search-hint" aria-hidden="true">/</kbd>' in rendered
    assert 'id="statusFilter"' in rendered
    assert 'id="viewTableBtn"' in rendered
    assert 'id="viewCardsBtn"' in rendered
    assert 'id="sessionsShownCount"' in rendered
    assert 'id="sessionsLoadedCount"' in rendered
    assert '<span id="sessionsLoadedCount"></span>' in rendered


def test_investigations_page_keeps_inline_script_ids_and_handlers() -> None:
    rendered = _render_investigations()
    required_ids = (
        "statTotal",
        "statActive",
        "statCompleted",
        "statFailed",
        "goalSearchInput",
        "statusFilter",
        "viewTableBtn",
        "viewCardsBtn",
        "tableViewContainer",
        "cardViewContainer",
        "sessionsBody",
        "sessionsCardGrid",
        "headerSelectAll",
        "selectAllCheck",
        "selectedCount",
        "newInvestigationModal",
        "startInvestigationBtn",
    )

    for element_id in required_ids:
        assert f'id="{element_id}"' in rendered

    assert "Investigations.filterByGoal()" in rendered
    assert "Investigations.loadSessions()" in rendered
    assert "Investigations.setView('table')" in rendered
    assert "Investigations.setView('cards')" in rendered


def test_investigations_css_is_page_scoped_and_uses_square_corners() -> None:
    css = (ROOT / "static" / "css" / "investigations.css").read_text(encoding="utf-8-sig")
    assert re.search(
        r"\.investigations-page \.investigations-heading h1\s*\{[^}]*text-shadow:\s*0 0 14px var\(--color-info\)\s*;",
        css,
        re.DOTALL,
    )
    assert ".investigations-page .investigations-stat-total" in css
    assert ".investigations-page .investigations-toolbar" in css
    assert ".investigations-page .investigations-table-card" in css
    assert re.search(
        r"\.investigations-page \.investigations-stat\s*\{[^}]*border-radius:\s*0\s*;",
        css,
        re.DOTALL,
    )
    assert re.search(
        r"\.investigations-page \.investigations-table-card\s*\{[^}]*border-radius:\s*0\s*;",
        css,
        re.DOTALL,
    )
    assert "var(--color-info)" in css
    assert "var(--color-success)" in css
    assert "var(--color-danger)" in css


def test_expanded_detail_renderer_uses_safe_dom_and_display_hooks() -> None:
    template = (ROOT / "templates" / "agent_investigations.html").read_text(encoding="utf-8")
    renderer = template.split("function toggleDetail", 1)[1].split(
        "// Side panel open/close", 1
    )[0]

    assert "innerHTML" not in renderer
    assert "investigations-detail-row" in renderer
    assert "investigations-detail-label" in renderer
    assert "investigations-result-block" in renderer
    assert "investigations-verdict-chip" in renderer
    assert "investigations-inline-code" in renderer
    assert "investigations-role-chip" in renderer
    assert "investigations-message-content" in renderer
    assert "Messages · ' + history.length" in renderer
    assert "target.appendChild(document.createTextNode" in renderer
    assert "code.textContent = match[1]" in renderer
    assert "chip.textContent = verdict" in renderer


def test_investigations_expanded_detail_css_has_wrapping_square_components() -> None:
    css = (ROOT / "static" / "css" / "investigations.css").read_text(encoding="utf-8-sig")
    required_selectors = (
        ".investigations-page .investigations-detail-row > td",
        ".investigations-page .investigations-result-block",
        ".investigations-page .investigations-verdict-chip",
        ".investigations-page .investigations-inline-code",
        ".investigations-page .investigations-message",
        ".investigations-page .investigations-role-chip",
    )

    for selector in required_selectors:
        assert selector in css

    for selector in (
        ".investigations-page .investigations-result-block",
        ".investigations-page .investigations-verdict-chip",
        ".investigations-page .investigations-inline-code",
        ".investigations-page .investigations-role-chip",
    ):
        assert re.search(
            re.escape(selector) + r"\s*\{[^}]*border-radius:\s*0\s*;",
            css,
            re.DOTALL,
        )

    assert "overflow-wrap: anywhere" in css
    assert "var(--bg-tertiary)" in css


def test_investigations_row_renderer_hooks_cover_status_date_search_and_counts() -> None:
    template = (ROOT / "templates" / "agent_investigations.html").read_text(encoding="utf-8")
    renderer = template.split("function makeStatusBadge", 1)[1].split(
        "function onRowCheckChange", 1
    )[0]
    stats_renderer = template.split("function updateStats", 1)[1].split(
        "function startNew", 1
    )[0]

    assert "innerHTML" not in renderer
    assert "investigations-status investigations-status-' + kind" in renderer
    assert "investigations-status-dot" in renderer
    assert "investigations-status-label" in renderer
    assert "formatCreatedAt(s.created_at || s.created || '-')" in renderer
    assert "date.getUTCDate()" in renderer
    assert "date.getUTCHours()" in renderer
    assert "match[7].slice(0, 3)" in renderer
    assert "sessionId.indexOf(query) !== -1 || goal.indexOf(query) !== -1" in renderer
    assert "sessions.length + ' shown'" in renderer
    assert "loadedCount + ' of ' + total + ' loaded · sorted by newest'" in renderer
    assert "completed / total * 100" in stats_renderer
    assert "failed / total * 100" in stats_renderer
    assert "No sessions match." in renderer


def test_investigations_row_status_css_is_dot_based_and_theme_aware() -> None:
    css = (ROOT / "static" / "css" / "investigations.css").read_text(encoding="utf-8-sig")

    assert ".investigations-page .investigations-status-dot" in css
    assert ".investigations-page .investigations-status-completed" in css
    assert ".investigations-page .investigations-status-failed" in css
    assert ".investigations-page .investigations-status-active" in css
    assert ".investigations-page .investigations-status-neutral" in css
    assert "box-shadow: 0 0 8px var(--investigations-status-color)" in css
    assert ":has(.investigations-status-completed)" in css
    assert ":has(.investigations-status-failed)" in css
    assert ":has(.investigations-status-active)" in css
    assert "var(--color-info)" in css
    assert "var(--color-success)" in css
    assert "var(--color-danger)" in css
