import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_rule_editor_card_resolves_rule_wrapper():
    analysis_js = (ROOT / 'static/js/analysis.js').read_text(encoding='utf-8')

    assert "return button.closest('.rule-wrapper')" in analysis_js


def test_report_view_keeps_rule_editor_elements_inside_rule_wrapper():
    report_view = (ROOT / 'templates/report_view.html').read_text(encoding='utf-8')

    assert re.search(
        r'<div class="rule-wrapper".*?data-rule-display.*?data-rule-editor',
        report_view,
        re.DOTALL,
    )
