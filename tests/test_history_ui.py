from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "templates" / "history.html"
CSS = ROOT / "static" / "css" / "history.css"
JS = ROOT / "static" / "js" / "history.js"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_history_template_has_static_shell_and_seven_cards() -> None:
    source = read(TEMPLATE)

    for element_id in (
        "historyPage", "stats", "dist", "q", "ty", "dt", "chips",
        "historySummaryError", "historyLoading", "historyError", "tb",
        "em", "cnt", "historyPrev", "historyNext", "historyDrawer",
        "historyDrawerBackdrop", "historyDrawerBody", "historyDrawerClose",
    ):
        assert f'id="{element_id}"' in source

    for group in (
        "", "malicious", "suspicious", "clean", "failed",
        "unknown", "in_progress",
    ):
        assert f'data-group="{group}"' in source

    assert len(re.findall(r'class="history-stat(?:\s|[\"])', source)) == 7
    assert "{% block page_title %}" in source
    assert "{% block page_subtitle %}" in source
    assert source.count("<h1") == 1
    history_section = source.split('<section id="historyPage"', 1)[1].split("</section>", 1)[0]
    assert history_section.count("<h1") == 1
    assert "{% block page_title %}{% endblock %}" in source
    assert "{% block page_subtitle %}{% endblock %}" in source
    assert "{{ jobs" not in source
    assert "{% if jobs" not in source
    assert "{% for job" not in source
    history_section = source.split('<section id="historyPage"', 1)[1].split("</section>", 1)[0]
    assert 'id="historyDrawer"' in history_section
    assert 'id="historyDrawerBackdrop"' in history_section
    assert 'id="historyDrawerBody"' in history_section
    assert 'id="historyDrawerClose"' in history_section
    assert 'role="dialog"' in history_section
    assert 'aria-modal="true"' in history_section


def test_history_js_uses_dom_text_rendering_and_scoped_events() -> None:
    source = read(JS)

    assert "innerHTML" not in source
    assert "textContent" in source
    assert "event.key === \"Escape\"" in source
    assert "encodeURIComponent" in source
    assert "historyDrawer" in source
    assert 'getElementById("historyPage")' in source
    assert 'document.addEventListener("click"' not in source
    assert "AbortController" in source
    assert "replaceState" in source
    assert "pushState" in source
    assert "popstate" in source
    assert 'document.getElementById("dt").addEventListener("change"' in source


def test_history_api_urls_are_present() -> None:
    source = read(JS)

    assert "/api/analysis/history/summary" in source
    assert "/api/analysis/history/?" in source


def test_history_sources_contain_no_thai_text() -> None:
    thai = re.compile(r"[\u0e00-\u0e7f]")

    for path in (TEMPLATE, CSS, JS):
        assert thai.search(read(path)) is None


def test_history_css_is_scoped() -> None:
    source = read(CSS)
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    source = re.sub(
        r"@keyframes\s+[^{}]+\{(?:[^{}]+\{[^{}]*\})+\}",
        "",
        source,
        flags=re.DOTALL,
    )

    chrome_selector = "body:has(.history-page) .sub-header"
    assert chrome_selector in source

    assert re.search(
        r"(?m)^\s*(?:body|header|h1|table|button)(?:\s|[,{:#.])",
        source.replace(chrome_selector, ""),
    ) is None

    for match in re.finditer(r"([^{}]+)\{", source):
        header = match.group(1).strip()
        if header.startswith("@") or header in {"from", "to"}:
            continue
        for selector in header.split(","):
            selector = selector.strip()
            assert (
                selector.startswith(".history-page")
                or selector.startswith('[data-theme="light"] .history-page')
                or selector == chrome_selector
            )
