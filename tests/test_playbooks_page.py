from __future__ import annotations

import re
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from fastapi.templating import Jinja2Templates


ROOT = Path(__file__).resolve().parents[1]


def _render_playbooks() -> str:
    app = FastAPI()
    templates = Jinja2Templates(directory=str(ROOT / "templates"))

    @app.get("/agent/playbooks")
    async def playbooks_page(request: Request):
        request.state.user = {
            "id": 1,
            "username": "playbooks-test",
            "email": "playbooks-test@example.test",
            "role": "admin",
        }
        return templates.TemplateResponse(
            request,
            "playbooks.html",
            {
                "playbooks": [
                    {
                        "id": "alert_triage",
                        "name": "Alert Triage",
                        "category": "Incident Response",
                        "description": "Classify and enrich security alerts.",
                        "trigger_type": "manual",
                        "step_count": 21,
                        "steps": [
                            {"name": "first", "tool": "tool_z"},
                            {"name": "second", "tool": "tool_a"},
                            {"name": "repeat", "tool": "tool_z"},
                            {"name": "finish", "action": "final_answer"},
                        ],
                    }
                ]
            },
        )

    with TestClient(app) as client:
        response = client.get("/agent/playbooks")

    assert response.status_code == 200
    return response.text


def test_playbooks_page_renders_list_header_tiles_meter_and_toolbar() -> None:
    rendered = _render_playbooks()

    assert "/static/css/playbooks.css?v=1" in rendered
    assert '<section class="playbooks-page"' in rendered
    assert re.search(r"<h1>\s*SECURITY\s*<span>PLAYBOOKS</span>\s*</h1>", rendered)
    assert "Pre-configured investigation workflows" in rendered
    assert 'id="refreshPlaybooksBtn"' in rendered
    assert 'onclick="Playbooks.loadPlaybooks()"' in rendered

    stat_labels = re.findall(
        r'<div class="stat-label">([^<]+)</div>',
        rendered.split('id="playbookStatsBar"', 1)[1].split('id="playbookCategoryMeter"', 1)[0],
    )
    assert stat_labels == ["Playbooks", "Total Steps", "Unique Tools", "Categories"]
    assert 'id="statTotalPlaybooks"' in rendered
    assert 'id="statTotalSteps"' in rendered
    assert 'id="statUniqueToolsTile"' in rendered
    assert 'id="statUniqueTools"' in rendered
    assert re.search(r'id="statUniqueTools">2</div>', rendered)
    assert 'id="statCategories"' in rendered
    assert 'id="playbookCategoryMeter" class="playbooks-meter"' in rendered
    assert re.search(r'class="[^"]*playbooks-toolbar[^"]*"', rendered)
    assert '&gt;_' in rendered
    assert 'id="playbookSearchInput"' in rendered
    assert 'placeholder="search playbooks by name or description…"' in rendered
    assert '<kbd class="playbooks-search-hint"' in rendered
    assert 'id="categoryFilters"' in rendered
    assert 'data-category="incident-response"' in rendered
    assert 'id="playbookGrid"' in rendered
    assert 'data-pb-category="incident-response"' in rendered


def test_playbooks_css_is_scoped_and_uses_square_corners_and_history_title_glow() -> None:
    css = (ROOT / "static" / "css" / "playbooks.css").read_text(encoding="utf-8-sig")

    assert "body:has(.playbooks-page) .sub-header" in css
    assert ".playbooks-page {" in css
    assert re.search(
        r"\.playbooks-page \.playbooks-heading h1\s*\{[^}]*text-shadow:\s*0 0 14px var\(--color-info\)\s*;",
        css,
        re.DOTALL,
    )
    assert "border-radius: 0;" in css
    for page_class in (
        ".playbooks-heading",
        ".playbooks-stats",
        ".playbooks-meter",
        ".playbooks-toolbar",
        ".playbooks-grid",
        ".playbooks-card",
    ):
        assert f".playbooks-page {page_class}" in css


def test_playbooks_cards_have_category_hover_glow_and_reduced_motion_support() -> None:
    css = (ROOT / "static" / "css" / "playbooks.css").read_text(encoding="utf-8-sig")

    hover_rule = re.search(
        r"\.playbooks-page \.playbooks-card:hover,\s*"
        r"\.playbooks-page \.playbooks-card:focus-within,.*?\{([^}]*)\}",
        css,
        re.DOTALL,
    )
    assert hover_rule is not None
    assert "box-shadow:" in hover_rule.group(1)
    assert "var(--playbooks-card-accent" in hover_rule.group(1)
    assert "transform: translateY(-2px);" in hover_rule.group(1)

    assert "@media (prefers-reduced-motion: reduce)" in css
    reduced_motion_css = css.split("@media (prefers-reduced-motion: reduce)", 1)[1].split(
        "@media (hover: none)", 1
    )[0]
    assert "transition: none;" in reduced_motion_css
    assert "transform: none;" in reduced_motion_css


def test_playbooks_stat_tiles_have_scoped_hover_glow() -> None:
    css = (ROOT / "static" / "css" / "playbooks.css").read_text(encoding="utf-8-sig")
    rendered = _render_playbooks()

    # The template keeps the compatibility class, but CSS leaves it visually inert.
    assert "playbooks-stat-highlight" in rendered
    assert ".playbooks-stat-highlight" not in css
    assert "--playbooks-highlight-glow-alpha" not in css

    hover_rule = re.search(
        r"\.playbooks-page \.playbooks-stat:hover,\s*"
        r"\.playbooks-page \.playbooks-stat:focus-within\s*\{([^}]*)\}",
        css,
        re.DOTALL,
    )
    assert hover_rule is not None
    assert "border-color: var(--playbooks-cat-threat-intel);" in hover_rule.group(1)
    assert "box-shadow:" in hover_rule.group(1)
    assert "var(--playbooks-hover-glow-alpha)" in hover_rule.group(1)
    assert "var(--playbooks-hover-glow-size)" in hover_rule.group(1)
    assert re.search(
        r"\.playbooks-page \.playbooks-stat:hover \.stat-value,\s*"
        r"\.playbooks-page \.playbooks-stat:focus-within \.stat-value\s*"
        r"\{[^}]*text-shadow:",
        css,
        re.DOTALL,
    )

    reduced_motion_css = css.split("@media (prefers-reduced-motion: reduce)", 1)[1].split(
        "@media (hover: none)", 1
    )[0]
    assert ".playbooks-page .playbooks-stat" in reduced_motion_css
    assert "transition: none;" in reduced_motion_css


def test_playbooks_page_keeps_existing_inline_javascript_hooks_and_modals() -> None:
    rendered = _render_playbooks()
    required_ids = (
        "playbookStatsBar",
        "statTotalPlaybooks",
        "statTotalSteps",
        "statUniqueTools",
        "statCategories",
        "playbookSearchInput",
        "categoryFilters",
        "playbookGrid",
        "runPlaybookModal",
        "executePlaybookBtn",
        "viewPlaybookModal",
        "viewModalRunBtn",
    )

    for element_id in required_ids:
        assert f'id="{element_id}"' in rendered

    assert "playbook-view-btn" in rendered
    assert "playbook-run-btn" in rendered
    assert 'data-playbook-id="alert_triage"' in rendered
    assert 'data-playbook-name="Alert Triage"' in rendered
    assert 'class="trigger-badge trigger-manual">manual</span>' in rendered
    assert "21 steps" in rendered
    assert "Array.isArray(pb.tools)" in rendered
