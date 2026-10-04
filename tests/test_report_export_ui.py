import re
from pathlib import Path
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader


def test_report_export_controls_render_for_present_rule_types():
    templates_dir = Path(__file__).resolve().parents[1] / 'templates'
    template = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=True,
    ).get_template('report_view.html')
    rule_types = ('kql', 'spl', 'sigma', 'xql', 'dql', 'suricata')
    rendered = template.render(
        job={
            'id': 'export-ui-test',
            'ioc': 'kurs.if.ua',
            'score': 0,
            'result': {
                'ioc': 'kurs.if.ua',
                'detection_rules': {rule_type: f'{rule_type} rule' for rule_type in rule_types},
            },
        },
        request=SimpleNamespace(
            query_params={},
            url=SimpleNamespace(path='/report/export-ui-test'),
            state=SimpleNamespace(user={'role': 'admin'}),
        ),
    )

    assert 'data-rule-export-status' in rendered
    assert 'aria-live="polite"' in rendered
    export_button = re.search(
        r'<button[^>]+data-rule-action="zip"[^>]*>.*?Export selected as ZIP.*?</button>',
        rendered,
        re.DOTALL,
    )
    assert export_button is not None
    assert 'disabled' in export_button.group(0)
    assert 'aria-disabled="true"' in export_button.group(0)
