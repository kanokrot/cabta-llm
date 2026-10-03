from pathlib import Path
import re


TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "analysis_ioc.html"


def template_text():
    return TEMPLATE.read_text(encoding="utf-8")


def progress_card(text):
    start = text.index('<div id="iocProgressArea"')
    end = text.index('<!-- Results Container', start)
    return text[start:end]


def sources_panel(text):
    start = text.index("<!-- Intelligence Sources -->")
    end = text.index("<!-- Progress Area", start)
    return text[start:end]


def new_ioc_css(text):
    start = text.index("IOC Card Polish")
    end = text.index("</style>", start)
    css = text[start:end]
    return "\n".join(
        declarations
        for selector, declarations in re.findall(r"([^{}]+)\{([^{}]*)\}", css)
        if ".ioc-" in selector
    )


def test_existing_ioc_ids_and_progress_percent_remain():
    text = template_text()
    for element_id in (
        "iocForm",
        "iocType",
        "iocValue",
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


def test_progress_card_has_no_hourglass_icon():
    assert "bi-hourglass-split" not in progress_card(template_text())


def test_no_fixed_source_count_or_detected_wording():
    text = template_text()
    assert "of 25" not in text
    assert "25 sources" not in text
    assert "Detected:" not in text


def test_new_ioc_css_has_no_hex_colours():
    assert re.search(r"#[0-9a-fA-F]{3,8}", new_ioc_css(template_text())) is None


def test_sources_panel_uses_only_new_source_classes():
    panel = sources_panel(template_text())
    assert not re.search(r'class="[^"]*\bsource-(?:item|name|category)\b', panel)
    assert not re.search(
        r"\.ioc-source-dot-extended\s*\{\s*background:\s*var\(--color-danger\)",
        template_text(),
    )
