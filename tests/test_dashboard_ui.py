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
    assert 'href="/api/reports/{{ job.id }}/html"' in template
    assert "`/api/reports/${encodeURIComponent(String(item.id))}/html`" in script


def test_indicator_locations_map_and_country_centroids() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    script = SCRIPT.read_text(encoding="utf-8")
    partial = ROOT / "templates" / "partials" / "world_map_paths.html"
    partial_text = partial.read_text(encoding="utf-8") if partial.is_file() else ""

    assert 'id="dash-country-map" viewBox="0 0 1050 414"' in template
    assert '{% include "partials/world_map_paths.html" %}' in template
    assert partial.is_file()
    assert len(partial_text.encode("utf-8")) < 200_000
    assert 'class="dash-map-land dash-map-country"' in partial_text
    assert 'class="dash-map-borders"' in partial_text
    country_path_lines = re.findall(r'<path class="dash-map-land dash-map-country"[^>]+>', partial_text)
    assert len(country_path_lines) > 150
    assert all('data-n3="' in line or 'data-name="' in line for line in country_path_lines)
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
