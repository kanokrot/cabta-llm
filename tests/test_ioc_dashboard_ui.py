"""Text-level regression tests for the IOC dashboard UI."""

from pathlib import Path


TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "analysis_ioc.html"


def template_text():
    return TEMPLATE.read_text(encoding="utf-8")


def dashboard_markup(text):
    start = text.index('<div class="ioc-dashboard"')
    end = text.index('<div class="row g-4 ioc-legacy-layout"', start)
    return text[start:end]


def dashboard_script(text):
    start = text.index("var dashboard = document.querySelector('.ioc-dashboard')")
    end = text.index("loadDashboard();", start)
    return text[start:end]


def test_dashboard_has_stats_distribution_chart_lookup_feed_and_origin_cards():
    markup = dashboard_markup(template_text())
    for element_id in (
        "iocDashTotal", "iocDashMalicious", "iocDashSuspicious", "iocDashClean",
        "iocDashSegments", "iocDashVerdictRows", "iocDashChart", "iocDashboardLookup",
        "iocDashboardValue", "iocDashFeed", "iocDashOriginTitle",
    ):
        assert f'id="{element_id}"' in markup
    assert "Threat origin visualization coming soon" in markup
    assert 'href="/history"' in markup


def test_dashboard_uses_existing_ioc_form_and_reports_empty_error_states():
    text = template_text()
    script = dashboard_script(text)
    assert "legacyForm.requestSubmit()" in script
    assert "window.setIOCMode('single')" in script
    assert "No analyses to summarize yet." in script
    assert "No timestamped analyses in this period." in script
    assert "No malicious analyses yet." in script
    assert "Unable to load verdict distribution." in script
    assert "Unable to load daily analysis counts." in script
    assert "Unable to load the malicious feed." in script


def test_feed_uses_report_links_text_nodes_and_breakable_indicator_code():
    text = template_text()
    script = dashboard_script(text)
    assert "'/report/' + encodeURIComponent(item.id)" in script
    assert "indicator.textContent = item.indicator || '—'" in script
    assert "View report" in script
    assert ".ioc-dashboard-feed-indicator" in text
    assert "word-break: break-all" in text


def test_feed_stacks_below_dashboard_on_narrow_screens():
    css = template_text()
    assert "@media (max-width: 900px)" in css
    assert ".ioc-dashboard-layout { grid-template-columns: minmax(0, 1fr); }" in css
    assert ".ioc-dashboard-feed-column { grid-row: 2; }" in css
