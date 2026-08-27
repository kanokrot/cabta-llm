"""
Static regression tests for static/js/analysis.js.

Purpose
-------
On 2026-08-28 a dead-code cleanup removed several functions from
analysis.js that were confirmed unreachable (id mismatch against all
three consuming templates: analysis_ioc.html, analysis_file.html,
analysis_email.html). These tests are a guardrail:

1. The removed dead code / dead ids must not silently reappear
   (e.g. from a bad merge, a revert, or someone pasting an old
   version of the file back in).
2. The functions that ARE still required by the templates must
   remain present and exported on `window`.

These are plain text/regex checks (no Node/Jest dependency), consistent
with this project's existing pytest-only tooling.

NOTE: Paths are relative to the project root. Adjust ANALYSIS_JS /
TEMPLATES_DIR below if the repo layout differs from what was verified
in chat (D:\\ai_cti_automate\\static\\js\\analysis.js and
D:\\ai_cti_automate\\templates\\analysis_*.html).
"""

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ANALYSIS_JS = PROJECT_ROOT / "static" / "js" / "analysis.js"
TEMPLATES_DIR = PROJECT_ROOT / "templates"

TEMPLATE_FILES = {
    "ioc": TEMPLATES_DIR / "analysis_ioc.html",
    "file": TEMPLATES_DIR / "analysis_file.html",
    "email": TEMPLATES_DIR / "analysis_email.html",
}


@pytest.fixture(scope="module")
def analysis_js_text():
    assert ANALYSIS_JS.exists(), f"Expected file not found: {ANALYSIS_JS}"
    return ANALYSIS_JS.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def template_texts():
    texts = {}
    for name, path in TEMPLATE_FILES.items():
        assert path.exists(), f"Expected template not found: {path}"
        texts[name] = path.read_text(encoding="utf-8")
    return texts


# ---------------------------------------------------------------------------
# 1. Dead code / dead ids must NOT reappear
# ---------------------------------------------------------------------------

DEAD_FUNCTION_NAMES = [
    "initIOCForm",
    "initFileUpload",
    "uploadFile",
    "connectProgressSocket",
    "showProgress",
    "updateProgress",
    "hideProgress",
    "renderResults",
    "createSection",
    "addDLRow",
    "verdictClass",
    "renderIOCResult",
]

DEAD_IDS = [
    "ioc-analysis-form",
    "file-upload-area",
    "file-upload-input",
    "analysis-progress",
    "analysis-results",
]

DEAD_WINDOW_EXPORTS = [
    "window.BTAAnalysis",
    "window.renderIOCResult",
]


@pytest.mark.parametrize("func_name", DEAD_FUNCTION_NAMES)
def test_dead_function_not_reintroduced(analysis_js_text, func_name):
    """Dead functions confirmed unreachable must not reappear as
    function declarations in analysis.js."""
    pattern = rf"function\s+{re.escape(func_name)}\s*\("
    assert not re.search(pattern, analysis_js_text), (
        f"'{func_name}' reappeared in analysis.js as a function declaration. "
        "This was confirmed dead code (id mismatch against all 3 templates) "
        "and removed intentionally. If it's genuinely needed again, verify "
        "the calling template actually uses the matching id first."
    )


@pytest.mark.parametrize("dead_id", DEAD_IDS)
def test_dead_id_not_reintroduced_in_js(analysis_js_text, dead_id):
    """Legacy ids that never matched any template must not reappear
    in analysis.js (would indicate dead code creeping back in)."""
    assert dead_id not in analysis_js_text, (
        f"id '{dead_id}' reappeared in analysis.js. This id never matched "
        "any element in analysis_ioc.html / analysis_file.html / "
        "analysis_email.html and was tied to code removed as dead."
    )


@pytest.mark.parametrize("dead_id", DEAD_IDS)
def test_dead_id_not_present_in_templates(template_texts, dead_id):
    """None of the three analysis templates should use these legacy ids
    either -- confirms the current id naming convention stays in place."""
    for name, text in template_texts.items():
        assert dead_id not in text, (
            f"id '{dead_id}' found in analysis_{name}.html. This id was "
            "verified absent from all templates during the dead-code audit."
        )


@pytest.mark.parametrize("export_name", DEAD_WINDOW_EXPORTS)
def test_dead_window_export_not_reintroduced(analysis_js_text, export_name):
    assert export_name not in analysis_js_text, (
        f"'{export_name}' reappeared in analysis.js. This export had no "
        "callers in any template and was removed."
    )


def test_dead_branch_removed_from_poll_analysis(analysis_js_text):
    """The unreachable `renderIOCResult(fullResult)` branch inside
    pollAnalysis() must not come back. analysisType is only ever
    'ioc' | 'file' | 'email', produced solely by this module's own
    start*Analysis() functions."""
    assert "renderIOCResult(fullResult)" not in analysis_js_text


def test_auto_load_id_param_removed_from_analysis_js(analysis_js_text):
    """The init()/DOMContentLoaded auto-load of ?id= was removed from
    analysis.js because each template (ioc/file/email) already
    implements its own ?id= auto-load. If this assertion starts
    failing because someone re-added it to analysis.js, first confirm
    whether the per-template auto-load logic was removed too --
    otherwise the id param would now be double-handled."""
    assert "function init(" not in analysis_js_text


# ---------------------------------------------------------------------------
# 2. Required functions must remain present and exported
# ---------------------------------------------------------------------------

REQUIRED_FUNCTION_NAMES = [
    "startIOCAnalysis",
    "startFileAnalysis",
    "startEmailAnalysis",
    "pollAnalysis",
    "renderFileResult",
    "renderEmailResult",
    "apiFetch",
    "showToast",
    "escHtml",
    "formatBytes",
]

REQUIRED_WINDOW_EXPORTS = [
    "window.startIOCAnalysis",
    "window.startFileAnalysis",
    "window.startEmailAnalysis",
    "window.renderFileResult",
    "window.renderEmailResult",
]


@pytest.mark.parametrize("func_name", REQUIRED_FUNCTION_NAMES)
def test_required_function_present(analysis_js_text, func_name):
    pattern = rf"function\s+{re.escape(func_name)}\s*\("
    assert re.search(pattern, analysis_js_text), (
        f"'{func_name}' is missing from analysis.js. This function is "
        "actively called by one or more templates and must be preserved."
    )


@pytest.mark.parametrize("export_name", REQUIRED_WINDOW_EXPORTS)
def test_required_window_export_present(analysis_js_text, export_name):
    assert export_name in analysis_js_text, (
        f"'{export_name}' is missing from analysis.js. Templates call "
        "this via inline scripts (window.<fn>(...)), so it must stay "
        "exported even if the internal implementation changes."
    )


# ---------------------------------------------------------------------------
# 3. Cross-check: each template's own ?id= auto-load still exists
#    (this is what makes removing analysis.js's init() safe)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["ioc", "file", "email"])
def test_template_has_own_id_param_autoload(template_texts, name):
    text = template_texts[name]
    assert "URLSearchParams" in text, (
        f"analysis_{name}.html no longer parses URLSearchParams. "
        "analysis.js's init() (which did this centrally) was removed "
        "on the assumption every template handles its own ?id= "
        "auto-load -- if that's no longer true, the feature is now "
        "silently broken for this page."
    )
    assert re.search(r"\.get\(\s*['\"]id['\"]\s*\)", text), (
        f"analysis_{name}.html no longer reads the 'id' query param. "
        "Same concern as above: this must exist independently now that "
        "analysis.js no longer provides it centrally."
    )