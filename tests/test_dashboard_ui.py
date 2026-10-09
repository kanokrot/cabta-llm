from __future__ import annotations

import re
import runpy
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
    for total_class, color_variable in (
        ("dash-total--malicious", "--color-danger"),
        ("dash-total--suspicious", "--color-warning"),
        ("dash-total--clean", "--color-success"),
    ):
        assert re.search(
            rf'\[data-theme="dark"\]\s+\.dash-page\s+\.{total_class}\s*'
            rf'\{{\s*color:\s*var\({color_variable}\);\s*\}}',
            styles.group(1),
        )
    assert ".dash-page #stat-total-analyses { color: var(--text-primary); }" in styles.group(1)


def test_dashboard_keeps_lookup_and_report_navigation() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'id="quick-ioc-form"' in template
    assert 'name="ioc"' in template
    assert "`/analysis/ioc?q=${encodeURIComponent(iocValue)}`" in script
    assert "fetch('/api/dashboard/recent?limit=50')" in script
    assert "const score = item.threat_score ?? item.score;" in script
    assert 'href="/history"' in template
    assert '<a class="dash-link dash-feed-all" href="/history">View all analyses</a>' in template
    assert 'href="/api/reports/{{ job.id }}/html"' in template
    assert "`/api/reports/${encodeURIComponent(String(item.id))}/html`" in script

    feed_link_style = re.search(r"\.dash-feed-all\s*\{([^}]*)\}", template)
    assert feed_link_style is not None
    assert "color: var(--color-accent)" in feed_link_style.group(1)
    assert "border: 0" in feed_link_style.group(1)
    assert "background: none" in feed_link_style.group(1)
    assert "box-shadow: none" in feed_link_style.group(1)
    assert ".dash-feed-all:focus-visible" in template


def test_indicator_locations_map_and_country_centroids() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    script = SCRIPT.read_text(encoding="utf-8")
    base = (ROOT / "templates" / "base.html").read_text(encoding="utf-8")
    partial = ROOT / "templates" / "partials" / "world_map_paths.html"
    partial_text = partial.read_text(encoding="utf-8") if partial.is_file() else ""

    assert 'id="dash-country-map" viewBox="0 0 720 500"' in template
    assert 'id="dash-country-map"' in template and 'tabindex="0"' in template
    assert 'aria-label="Interactive orthographic globe of indicator countries"' in template
    assert 'id="dash-country-map-title"' in template
    assert 'id="dash-map-sphere"' in template
    assert 'id="dash-map-graticule"' in template
    assert 'id="dash-map-countries"' in template
    assert 'id="dash-map-markers"' in template
    assert 'id="dash-country-focus"' in template
    assert 'id="dash-map-rotation"' not in template
    assert 'Rotate map' not in template
    assert 'type="range"' not in template[template.index('id="dash-country-title"'):template.index('id="dash-country-list"')]
    assert 'id="dash-map-zoom-in"' in template and 'aria-label="Zoom in"' in template
    assert 'id="dash-map-zoom-out"' in template and 'aria-label="Zoom out"' in template
    assert 'id="dash-map-zoom-reset"' in template and 'aria-label="Reset zoom"' in template
    assert 'id="dash-map-hover-card"' in template
    assert 'id="dash-map-hover-leader"' in template
    assert 'aria-hidden="true"' in template[template.index('id="dash-map-stars"'):template.index('id="dash-map-atmosphere"')]
    assert 'aria-hidden="true"' in template[template.index('class="dash-map-orbits"'):template.index('class="dash-map-hud-marks"')]
    assert 'prefers-reduced-motion: reduce' in template
    vendor_scripts = (
        '/static/vendor/d3-array.min.js?v=1',
        '/static/vendor/d3-geo.min.js?v=1',
        '/static/vendor/topojson-client.min.js?v=1',
    )
    vendor_positions = [template.index(script_tag) for script_tag in vendor_scripts]
    assert vendor_positions == sorted(vendor_positions)
    extra_head_position = base.index("{% block extra_head %}")
    dashboard_script_position = base.index('src="/static/js/dashboard.js?v=11"')
    scripts_block_position = base.index("{% block scripts %}")
    assert extra_head_position < dashboard_script_position < scripts_block_position
    assert 'COUNTRY_CENTROIDS' in script and 'COUNTRY_NUMERIC_IDS' in script
    assert 'geoOrthographic()' in script and '.clipAngle(90)' in script
    assert 'setPointerCapture(event.pointerId)' in script
    assert 'd3.geoDistance(point, center)' in script
    assert 'wheel' in script and 'pinchStart' in script and 'baseScale * globe.zoom' in script
    assert 'Math.random' not in script
    assert '{% include "partials/world_map_paths.html" %}' not in template
    assert partial.is_file()
    assert len(partial_text.encode("utf-8")) < 200_000
    assert 'class="dash-map-land dash-map-country"' in partial_text
    assert 'class="dash-map-borders"' in partial_text
    country_path_lines = re.findall(r'<path class="dash-map-land dash-map-country"[^>]+>', partial_text)
    assert len(country_path_lines) > 150
    assert all('data-n3="' in line or 'data-name="' in line for line in country_path_lines)
    france_path = next(
        line for line in country_path_lines if 'data-n3="250"' in line
    )
    france_geometry = re.search(r'\bd="([^"]+)"', france_path)
    assert france_geometry is not None
    assert len(re.findall(r'M', france_geometry.group(1))) == 2
    assert "dash-map-dots" not in template
    assert 'class="dash-map-graticule"' in template
    assert 'class="dash-map-legend"' in template
    assert "Hosting country of IP indicators, unique IPs. Only IP indicators have a country." in template
    assert 'id="dash-country-list"' in template
    assert 'id="dash-country-coverage"' in template
    assert "updateCountryLocations(data.country_stats, data.country_covered, data.total_analyses)" in script
    assert "Not on map:" in script
    assert "innerHTML" not in script

    centroids = script.split("const COUNTRY_CENTROIDS = {", 1)[1].split("\n    };", 1)[0]
    centroid_codes = set(re.findall(r"\b([A-Z]{2}):\s*\[", centroids))
    numeric_table = script.split("const COUNTRY_NUMERIC_IDS = {", 1)[1].split("\n    };", 1)[0]
    numeric_ids = dict(re.findall(r"\b([A-Z]{2}):\s*'([0-9]{3})'", numeric_table))
    assert centroid_codes <= set(numeric_ids)
    partial_ids = set(re.findall(r'data-n3="([0-9]{3})"', partial_text))
    current_codes = {"US": "840", "AU": "036", "FR": "250", "NL": "528", "PK": "586", "MU": "480", "HK": "344"}
    for code in current_codes:
        assert re.search(rf"\b{code}:\s*\[", centroids)
        assert numeric_ids[code] == current_codes[code]
    assert {code for code, numeric_id in current_codes.items() if numeric_id in partial_ids} == {
        "US", "AU", "FR", "NL", "PK",
    }


def test_dashboard_globe_uses_only_vendored_d3_functions_and_ascii_source() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    vendored_d3_functions = {
        "geoCentroid",
        "geoOrthographic",
        "geoPath",
        "geoGraticule10",
        "geoDistance",
        "geoContains",
    }
    d3_calls = set(re.findall(r"(?:window\.)?d3\.([A-Za-z_$][A-Za-z0-9_$]*)", script))

    assert "interpolateArray" not in script
    assert d3_calls == vendored_d3_functions
    assert script.isascii()


def test_globe_hover_card_typing_and_no_data_rows() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    script = SCRIPT.read_text(encoding="utf-8")
    assert "lastShownCountryCode" in script
    assert "state.lastShownCountryCode === countryCode" in script
    assert "window.setInterval" in script and "}, 35);" in script
    assert "kicker.textContent = 'SCANNING';" in script
    assert "startScanTyping(kicker, countryKey, globe, reducedMotion());" in script
    assert "stopScanTyping(byId('dash-map-hover-kicker'), globe);" in script
    assert 'id="dash-map-hover-stats" class="dash-map-hover-stats"' in template
    assert "byId('dash-map-hover-stats').hidden = !stats;" in script
    assert "byId('dash-map-hover-empty').hidden = Boolean(stats);" in script
    assert 'id="dash-map-hover-empty" class="dash-map-hover-empty" hidden>No indicators</p>' in template
    assert ".dash-map-hover-stats[hidden]" in template
    assert "innerHTML" not in script
    assert script.isascii()


def test_globe_threat_feed_layer_is_separate_toggleable_and_safe() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    script = SCRIPT.read_text(encoding="utf-8")
    assert 'id="dash-map-threat-feed"' in template
    assert 'id="dash-map-markers"' in template
    assert 'id="dash-map-threat-feed-toggle" aria-pressed="true"' in template
    assert 'dash-map-threat-feed-toggle[aria-pressed="false"]' in template
    assert 'dash-map-threat-feed-toggle[aria-pressed="true"]' in template
    assert "border: 1px solid rgb(63 230 255 / 42%)" in template
    assert ".dash-map-threat-feed-toggle:hover" in template
    assert "dash-map-threat-feed-online" in template
    assert "dash-map-threat-feed-offline" in template
    assert "dash-map-threat-feed-threatfox" in template
    assert "countryCenter(code)" in script
    assert "C2 \\u00d7${stats.count}" in script
    assert "fetch('/api/dashboard/threat-feed/countries')" in script
    assert 'id="dash-map-hover-threat-feed"' in template
    assert 'id="dash-map-hover-threat-feed-value"' in template
    assert "feedValue.textContent = feedParts.join(' \\u00b7 ')" in script
    assert "`Feodo ${feedStats.feodo_count}`" in script
    assert "`ThreatFox ${feedStats.threatfox_count}`" in script
    assert "if (feedStats.online_count !== null)" in script
    assert "const markerX = projected[0] + 18;" in script
    assert "const markerY = projected[1] - 18;" in script
    assert "stats?.feodo_count || 0" in script
    assert "stats?.threatfox_count" in script
    assert "const THREAT_FEED_LABEL_MIN_COUNT = 3;" in script
    assert "stats.count >= THREAT_FEED_LABEL_MIN_COUNT" in script
    assert "const THREAT_FEED_RADIUS_SCALE = 1.6;" in script
    assert "Math.sqrt(count) * THREAT_FEED_RADIUS_SCALE" in script
    assert "threatFeedRadius(offlineCount, 4, 9)" in script
    assert "threatFeedRadius(stats?.online_count || 0, 3, 8)" in script
    assert 'src="/static/js/dashboard.js?v=11"' in (ROOT / "templates" / "base.html").read_text(encoding="utf-8")
    assert "geoDistance(point, center) <= Math.PI / 2 + 1e-6" in script


def test_weekly_threat_feed_panel_is_safe_and_accessible() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    script = SCRIPT.read_text(encoding="utf-8")
    panel_start = template.index('<aside class="dash-card" aria-labelledby="dash-threat-feed-title">')
    panel_end = template.index("</aside>", panel_start) + len("</aside>")
    panel = template[panel_start:panel_end]
    item_renderer = script.split("function createThreatFeedItem(item)", 1)[1].split(
        "async function fetchThreatFeed()", 1
    )[0]

    for element_id in (
        "dash-threat-feed-title",
        "dash-threat-feed-items",
        "dash-threat-feed-sources",
        "dash-threat-feed-action-status",
    ):
        assert f'id="{element_id}"' in panel
    assert 'aria-labelledby="dash-threat-feed-title"' in panel
    assert 'id="dash-threat-feed-items" aria-live="polite"' in panel
    assert "Threat feed (weekly)" in panel
    assert "External IOCs from ThreatFox and Feodo Tracker, synced weekly" in panel
    assert 'id="dash-threat-feed-sync"' in panel
    assert "request.state.user.role == 'admin'" in panel
    panel_header = panel.split("<header", 1)[1].split("</header>", 1)[0]
    assert 'id="dash-threat-feed-sync"' in panel_header

    assert "fetch('/api/dashboard/threat-feed?limit=10')" in script
    assert "fetch('/api/dashboard/threat-feed/sync', {method: 'POST'})" in script
    assert "function defangIoc(value, iocType)" in script
    assert "const THREAT_FEED_ERROR_MESSAGES = {" in script
    assert "response_too_large: 'Provider returned an unexpected response'" in script
    assert "function threatFeedErrorMessage(code)" in script
    assert "dash-threat-chip--warning" in script and "stateText === 'Stale'" in script
    assert "No threat feed data yet" in script
    assert "Could not load threat feed" in script
    assert "A sync is already running" in script
    assert "innerHTML" not in script
    assert script.isascii()
    assert panel.isascii()
    assert "<a " not in panel.lower()
    assert "appendText(card, 'a'" not in item_renderer
    assert "createElement('a')" not in item_renderer
    assert ".href" not in item_renderer
    assert "void fetchThreatFeed()" in script
    assert "setInterval(fetchThreatFeed" not in script


def test_verdict_distribution_has_six_distinct_color_segments() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    script = SCRIPT.read_text(encoding="utf-8")
    styles = re.search(r"<style>(.*?)</style>", template, flags=re.I | re.S)
    assert styles is not None
    for verdict in ("malicious", "phishing", "suspicious", "spam", "clean", "unknown"):
        assert f".dash-segment--{verdict}" in styles.group(1)
        assert f"group: '{verdict}'" in script
    for key in (
        "malicious_count", "phishing_count", "suspicious_count",
        "spam_count", "clean_count", "unknown_count",
    ):
        assert f"key: '{key}'" in script
    assert "dash-verdict-bar" in styles.group(1)
    assert "gap: 2px" in styles.group(1)
    assert "groups.map((item) => `${item.label} ${item.count}`).join(', ')" in script
    for pill in ("dash-pill--phishing", "dash-pill--spam"):
        assert pill in template


def test_world_map_decoder_applies_transform_and_reversed_arc_indices() -> None:
    decoder = runpy.run_path(str(ROOT / "scripts" / "adhoc" / "build_world_map_svg.py"))["decode_topology"]
    topology = {
        "type": "Topology",
        "transform": {"scale": [0.1, 0.1], "translate": [10, 20]},
        "arcs": [
            [[0, 0], [10, 0]],
            [[10, 0], [0, 10], [-10, -10]],
        ],
        "objects": {
            "countries": {
                "type": "GeometryCollection",
                "geometries": [
                    {"type": "Polygon", "arcs": [[0, 1]], "id": 840, "properties": {"name": "Forward"}},
                    {"type": "Polygon", "arcs": [[-2, -1]], "properties": {"name": "Reversed"}},
                ],
            }
        },
    }

    geometries = decoder(topology)
    assert geometries[0]["coordinates"][0] == [(10, 20), (11.0, 20.0), (11.0, 21.0), (10.0, 20.0)]
    assert geometries[1]["coordinates"][0] == [(10.0, 20.0), (11.0, 21.0), (11.0, 20.0), (10.0, 20.0)]
    builder = runpy.run_path(str(ROOT / "scripts" / "adhoc" / "build_world_map_svg.py"))
    country_paths, _borders, _max_width, missing_ids = builder["build_paths"](topology)
    assert ("data-n3", "840") in [(attribute, value) for attribute, value, _path in country_paths]
    assert ("data-name", "Reversed") in [(attribute, value) for attribute, value, _path in country_paths]
    assert missing_ids == ["Reversed"]


def test_world_map_builder_splits_antimeridian_rings_without_wide_edges() -> None:
    builder = runpy.run_path(str(ROOT / "scripts" / "adhoc" / "build_world_map_svg.py"))
    ring = [(170, 8), (-170, 8), (-170, 12), (170, 12), (170, 8)]

    parts = builder["split_antimeridian"](ring)
    assert len(parts) == 2
    for part in parts:
        projected = builder["densify_wide_segments"](
            builder["simplify_ring"](builder["project_ring"](part))
        )
        assert projected[0] == projected[-1]
        max_width = max(abs(end[0] - start[0]) for start, end in zip(projected, projected[1:]))
        assert max_width <= builder["VIEWBOX_WIDTH"] * 0.5
