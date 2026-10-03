from pathlib import Path
import re


TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "analysis_ioc.html"


def template_text():
    return TEMPLATE.read_text(encoding="utf-8")


def progress_dialog(text):
    start = text.index('<dialog id="iocProgressArea"')
    end = text.index("</dialog>", start) + len("</dialog>")
    return text[start:end]


def hero_css(text):
    start = text.index("IOC Results Hero")
    end = text.index("/* ── Threat Score Gauge", start)
    return text[start:end]


def scripts_body(text):
    start = text.index("{% block scripts %}")
    end = text.index("{% endblock %}", start)
    return text[start:end]


def progress_css(text):
    start = text.index("IOC Progress Card")
    end = text.index("IOC Card Polish", start)
    return text[start:end]


def test_progress_area_is_native_dialog_and_ids_are_preserved():
    text = template_text()
    dialog = progress_dialog(text)
    assert re.search(r'<dialog[^>]+id="iocProgressArea"', dialog)
    for element_id in (
        "iocProgressArea",
        "iocProgressBar",
        "progressStatus",
        "progressLog",
        "progressSpinner",
        "progressTitle",
        "progressPercent",
    ):
        assert f'id="{element_id}"' in dialog


def test_dialog_open_close_and_hide_behaviour_are_present():
    text = template_text()
    dialog = progress_dialog(text)
    assert "showModal()" in text
    assert "progressArea.close()" in text
    assert 'id="progressHideButton"' in dialog
    assert "Cancel" not in dialog
    assert "if (capturedRunId !== runId) return;" in text
    assert "closeProgressDialog(true);" in text
    assert "progressLogDetails.open = true;" in text


def test_threat_score_text_uses_readable_theme_colour():
    text = template_text()
    gauge_rule = text[text.index(".threat-gauge-text"):text.index("}", text.index(".threat-gauge-text"))]
    assert "var(--text-primary)" in gauge_rule
    assert "var(--bs-body-color)" not in gauge_rule


def test_hero_css_has_no_gradient_or_hex_colour():
    css = hero_css(template_text())
    assert "linear-gradient" not in css
    assert re.search(r"#[0-9a-fA-F]{3,8}", css) is None


def test_forbidden_copy_and_renderer_fields_are_preserved():
    text = template_text()
    for forbidden in ("of 25", "25 sources", "Detected:", "[Source name]"):
        assert forbidden not in text
    assert "data.verdict" in text
    assert "data.threat_score" in text


def test_dialog_display_fallback_is_the_only_inline_display_write():
    text = template_text()
    script = scripts_body(text)
    fallback_start = script.index("function openProgressDialog()")
    fallback_end = script.index("function scrollToResultsArea()", fallback_start)
    fallback = script[fallback_start:fallback_end]
    outside_fallback = script[:fallback_start] + script[fallback_end:]
    assert "progressArea.style.display = 'block';" in fallback
    assert "progressArea.style.display = '';" in fallback
    assert "progressArea.style.display" not in outside_fallback


def test_closed_dialog_has_explicit_hidden_guard():
    css = progress_css(template_text())
    assert ".ioc-progress-area:not([open])" in css
    assert re.search(r"\.ioc-progress-area:not\(\[open\]\)\s*\{[^}]*display:\s*none", css, re.S)


def test_show_modal_is_guarded_by_open_check():
    script = scripts_body(template_text())
    assert script.count("showModal(") == 1
    assert re.search(r"if\s*\(!progressArea\.open\)\s*progressArea\.showModal\(\)", script)


def test_progress_css_has_no_hex_colours():
    assert re.search(r"#[0-9a-fA-F]{3,8}", progress_css(template_text())) is None
