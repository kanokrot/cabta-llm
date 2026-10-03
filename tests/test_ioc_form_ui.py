"""Text-level regression tests for the IOC form, sources, and history UI."""

import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = PROJECT_ROOT / "templates" / "analysis_ioc.html"


def _template_text():
    return TEMPLATE.read_text(encoding="utf-8")


def _source_panel(text):
    start = text.index("<!-- Intelligence Sources -->")
    end = text.index("<!-- Progress Area", start)
    return text[start:end]


def _history_builder(text):
    start = text.index("function renderIOCHistory(")
    end = text.index("function timeAgo(", start)
    return text[start:end]


def test_required_ioc_ids_remain_present():
    text = _template_text()
    for element_id in (
        "iocForm",
        "iocType",
        "iocHistoryList",
        "btnClearHistory",
        "iocProgressArea",
        "iocProgressBar",
        "progressStatus",
        "progressLog",
        "progressSpinner",
        "progressTitle",
        "progressPercent",
    ):
        assert f'id="{element_id}"' in text
    assert re.search(r'<select[^>]+id="iocType"', text)


def test_seven_type_chips_are_buttons():
    text = _template_text()
    expected = {
        "auto": "Auto-detect",
        "ip": "IP",
        "domain": "Domain",
        "url": "URL",
        "hash": "Hash",
        "email": "Email",
        "cve": "CVE",
    }
    for value, label in expected.items():
        assert re.search(
            rf'<button\s+type="button"[^>]+data-ioc-type="{value}"[^>]*>{label}</button>',
            text,
        )


def test_progress_ui_has_no_fixed_source_count_or_detected_wording():
    text = _template_text()
    assert "of 25" not in text
    assert "25 sources" not in text
    assert "Detected:" not in text


def test_history_builder_uses_dom_text_without_inner_html():
    builder = _history_builder(_template_text())
    assert "createElement" in builder
    assert "textContent" in builder
    assert "innerHTML" not in builder


def test_new_ioc_css_has_no_hex_colors():
    text = _template_text()
    start = text.index("/* ── IOC Form Controls ── */")
    end = text.index("/* ── Responsive ── */", start)
    new_ioc_css = text[start:end]
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", new_ioc_css)


def test_new_sources_panel_avoids_legacy_source_classes():
    panel = _source_panel(_template_text())
    class_tokens = {
        token
        for class_attr in re.findall(r'class="([^"]+)"', panel)
        for token in class_attr.split()
    }
    for legacy_class in ("source-item", "source-name", "source-category"):
        assert legacy_class not in class_tokens
    assert "Sources queried depend on the indicator type." in panel
