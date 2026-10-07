from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "templates" / "dashboard.html"
SCRIPT = ROOT / "static" / "js" / "dashboard.js"


def test_dashboard_script_ids_are_present_in_its_template() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    script = SCRIPT.read_text(encoding="utf-8")
    template_ids = set(re.findall(r'\bid="([^"]+)"', template))
    script_ids = {
        "quick-ioc-form",
        "stat-total-analyses",
        "stat-malicious",
        "stat-suspicious",
        "stat-clean",
        "verdict-dist-chart",
        "dash-verdict-legend",
        "dash-daily-chart",
        "dash-score-bars",
        "dash-data-status",
        "dash-malicious-feed",
        "recent-analyses-body",
    }

    assert script_ids <= template_ids
    assert "const dashboard = document.querySelector('.dash-page');\n    if (!dashboard) return;" in script
    assert "if (quickIocForm)" in script
    assert "const input = quickIocForm.querySelector('input[name=\"ioc\"]');" in script


def test_dashboard_has_no_sample_totals_or_forbidden_panels() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    visible_markup = re.sub(r"<style\b[^>]*>.*?</style>", "", template, flags=re.I | re.S)
    visible_markup = re.sub(r"<[^>]+>", " ", visible_markup)
    visible_markup = re.sub(r"\{\{.*?\}\}|\{%.*?%\}", " ", visible_markup, flags=re.S)

    for sample_total in ("160", "54", "5", "77", "24"):
        assert not re.search(rf"(?<!\d){sample_total}(?!\d)", visible_markup)
    for forbidden in ("world map", "Type-wise", "Premium APIs"):
        assert forbidden.casefold() not in template.casefold()
    assert "Threat origin" not in template


def test_dashboard_dynamic_data_uses_safe_dom_and_theme_styles() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    script = SCRIPT.read_text(encoding="utf-8")
    styles = re.search(r"<style>(.*?)</style>", template, flags=re.I | re.S)
    assert styles is not None
    dash_rules = re.findall(r"[^{}]*\.dash-[^{}]*\{([^{}]*)\}", styles.group(1), flags=re.S)

    assert dash_rules
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", "\n".join(dash_rules))
    assert "innerHTML" not in script
    assert "createElement(" in script
    assert "createElementNS(" in script
    assert "textContent" in script
    assert "setInterval(fetchDashboardStats" in script


def test_dashboard_keeps_lookup_and_report_navigation() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'id="quick-ioc-form"' in template
    assert 'name="ioc"' in template
    assert "`/analysis/ioc?q=${encodeURIComponent(iocValue)}`" in script
    assert "fetch('/api/dashboard/recent?limit=50')" in script
    assert "const score = item.threat_score ?? item.score;" in script
    assert 'href="/history"' in template
    assert 'href="/api/reports/{{ job.id }}/html"' in template
    assert "`/api/reports/${encodeURIComponent(String(item.id))}/html`" in script
