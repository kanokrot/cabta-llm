"""Text-level regression tests for the IOC analysis progress card."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = PROJECT_ROOT / "templates" / "analysis_ioc.html"


def _template_text():
    return TEMPLATE.read_text(encoding="utf-8")


def _progress_card(text):
    start = text.index('<div id="iocProgressArea"')
    end = text.index("<!-- Results Container", start)
    return text[start:end]


def test_progress_card_ids_are_preserved():
    text = _template_text()
    for element_id in (
        "iocProgressArea",
        "iocProgressBar",
        "progressStatus",
        "progressLog",
        "progressSpinner",
    ):
        assert f'id="{element_id}"' in text


def test_progress_log_is_collapsed_inside_details():
    card = _progress_card(_template_text())
    assert "<details" in card
    assert card.index("<details") < card.index('id="progressLog"')
    assert card.index('id="progressLog"') < card.index("</details>")


def test_progress_code_has_run_guard_and_deduplicates_messages():
    text = _template_text()
    assert "var runId = 0;" in text
    assert "var capturedRunId = ++runId;" in text
    assert text.count("if (capturedRunId !== runId) return;") >= 3
    assert "lastProgressMessage" in text
    assert "progressMessageCount" in text
    assert "message === lastProgressMessage" in text
    assert "lastProgressCountBadge.textContent = 'x' + progressMessageCount;" in text


def test_progress_log_lines_use_safe_dom_text_only():
    text = _template_text()
    start = text.index("function setProgress(")
    end = text.index("/**", start)
    set_progress = text[start:end]
    assert "createElement('li')" in set_progress
    assert "textContent = message" in set_progress
    assert "innerHTML" not in set_progress


def test_progress_card_has_no_hardcoded_source_counts_or_groups():
    card = _progress_card(_template_text())
    assert "of 25" not in card
    assert "Premium APIs" not in card
