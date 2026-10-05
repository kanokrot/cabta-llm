from __future__ import annotations

import re
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from fastapi.templating import Jinja2Templates


ROOT = Path(__file__).resolve().parents[1]


def _ticket(
    ticket_id: str,
    verdict: str,
    *,
    ioc: str | None = None,
    summary: str = "Ticket summary",
    status: str = "open",
    recommendations: list[str] | None = None,
) -> dict:
    return {
        "id": ticket_id,
        "ticket_id": ticket_id,
        "analysis_id": f"analysis-{ticket_id}",
        "ioc": ioc or f"ioc-{ticket_id}",
        "verdict": verdict,
        "status": status,
        "created_at": "2026-10-05 12:00:00",
        "summary": summary,
        "recommendations": recommendations or [],
        "owner_id": 1,
    }


def _render_tickets(tickets: list[dict]) -> str:
    app = FastAPI()
    templates = Jinja2Templates(directory=str(ROOT / "templates"))

    @app.get("/tickets")
    async def tickets_page(request: Request):
        request.state.user = {
            "id": 1,
            "username": "ticket-test",
            "email": "ticket-test@example.test",
            "role": "admin",
        }
        return templates.TemplateResponse(
            request,
            "tickets.html",
            {"tickets": tickets},
        )

    with TestClient(app) as client:
        response = client.get("/tickets")
    assert response.status_code == 200
    return response.text


def test_tickets_page_renders_empty_state_without_rows() -> None:
    rendered = _render_tickets([])

    assert "No incident tickets yet." in rendered
    assert 'id="ticketCountTotal">0<' in rendered
    assert 'class="tickets-row"' not in rendered


def test_tickets_page_renders_verdict_rows_and_server_counts() -> None:
    rendered = _render_tickets(
        [
            _ticket("t-1", "MALICIOUS"),
            _ticket("t-2", "SUSPICIOUS"),
            _ticket("t-3", "CLEAN"),
            _ticket("t-4", "UNKNOWN"),
            _ticket("t-5", "MALICIOUS"),
        ]
    )

    assert 'data-verdict="MALICIOUS"' in rendered
    assert 'data-verdict="SUSPICIOUS"' in rendered
    assert 'data-verdict="CLEAN"' in rendered
    assert 'data-verdict="UNKNOWN"' in rendered
    assert 'id="ticketCountTotal">5<' in rendered
    assert 'id="ticketCountMalicious">2<' in rendered
    assert 'id="ticketCountSuspicious">1<' in rendered
    assert 'id="ticketCountClean">1<' in rendered
    assert 'id="ticketCountUnknown">1<' in rendered
    assert 'data-status="open"' in rendered
    assert 'data-search="t-1 ioc-t-1 Ticket summary analysis-t-1 MALICIOUS open"' in rendered


def test_tickets_page_escapes_ticket_text_fields() -> None:
    rendered = _render_tickets(
        [
            _ticket(
                "xss-1",
                "MALICIOUS",
                ioc="<script>alert('ioc')</script>",
                summary="<script>alert('summary')</script>",
                recommendations=["<script>alert('recommendation')</script>"],
            )
        ]
    )

    assert "&lt;script&gt;alert(&#39;ioc&#39;)&lt;/script&gt;" in rendered
    assert "&lt;script&gt;alert(&#39;summary&#39;)&lt;/script&gt;" in rendered
    assert "&lt;script&gt;alert(&#39;recommendation&#39;)&lt;/script&gt;" in rendered
    assert "<script>alert('ioc')</script>" not in rendered
    assert "<script>alert('summary')</script>" not in rendered
    assert "<script>alert('recommendation')</script>" not in rendered


def test_tickets_page_hides_base_subtitle_and_starts_with_all_filter_active() -> None:
    rendered = _render_tickets([])

    assert "Auto-generated tickets from investigation verdicts" not in rendered
    chips = re.findall(
        r'<button class="([^"]*tickets-filter[^"]*)" type="button" '
        r'data-filter="([A-Z]+)" aria-pressed="(true|false)">',
        rendered,
    )
    active_filters = [
        filter_name
        for classes, filter_name, pressed in chips
        if "tickets-filter-active" in classes.split() or pressed == "true"
    ]

    assert len(chips) == 5
    assert active_filters == ["ALL"]


def test_tickets_css_uses_square_corners_for_history_surface_elements() -> None:
    css = (ROOT / "static" / "css" / "tickets.css").read_text(encoding="utf-8")
    square_selectors = {
        ".tickets-page .tickets-count-badge",
        ".tickets-page .tickets-stat",
        ".tickets-page .tickets-distribution",
        ".tickets-page .tickets-toolbar",
        ".tickets-page .tickets-filter",
        ".tickets-page .tickets-table-card",
        ".tickets-page .tickets-empty-card",
        ".tickets-page .tickets-status",
        ".tickets-page .tickets-verdict",
    }
    radius_by_selector = {}

    for match in re.finditer(r"([^{}]+)\{([^{}]*)\}", css):
        declarations = match.group(2)
        radius = re.search(r"(?:^|;)\s*border-radius\s*:\s*([^;]+)", declarations)
        if radius:
            for selector in match.group(1).split(","):
                selector = selector.strip()
                if selector in square_selectors:
                    radius_by_selector[selector] = radius.group(1).strip()

    assert radius_by_selector == {selector: "0" for selector in square_selectors}


def test_tickets_css_verdict_and_status_chips_have_colored_square_borders() -> None:
    css = (ROOT / "static" / "css" / "tickets.css").read_text(encoding="utf-8")
    chip_rule = re.search(
        r"\.tickets-page \.tickets-status,\s*\.tickets-page \.tickets-verdict\s*\{([^}]*)\}",
        css,
    )
    assert chip_rule is not None
    assert re.search(r"border:\s*1px solid var\(--tickets-chip-color,\s*var\(--border-color\)\)", chip_rule.group(1))

    status_rule = re.search(r"\.tickets-page \.tickets-status\s*\{([^}]*)\}", css)
    verdict_rule = re.search(r"\.tickets-page \.tickets-verdict\s*\{([^}]*)\}", css)
    assert status_rule is not None and re.search(r"border-radius:\s*0\s*;", status_rule.group(1))
    assert verdict_rule is not None and re.search(r"border-radius:\s*0\s*;", verdict_rule.group(1))

    for verdict in ("malicious", "suspicious", "clean", "unknown"):
        assert re.search(
            rf"\.tickets-page \.tickets-verdict-{verdict}\s*\{{\s*--tickets-chip-color:\s*var\(--tickets-verdict-{verdict}\);",
            css,
        )

    assert "--tickets-status-chip-color: var(--border-color);" in css
    assert '.tickets-row[data-status="open"]' in css
    assert "--tickets-status-chip-color: var(--tickets-status-open);" in css
    assert 'data-status="closed"' in css
    assert "--tickets-status-chip-color: var(--tickets-status-closed);" in css
