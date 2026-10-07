import re
from pathlib import Path
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader


def test_report_source_badges_follow_source_status_mapping():
    templates_dir = Path(__file__).resolve().parents[1] / 'templates'
    template = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=True,
    ).get_template('report_view.html')
    sources = {
        'circl': {'status': '⚠'},
        'misp': {'status': '⚠', 'score': 0},
        'abuseipdb': {'status': '➖'},
        'virustotal': {'status': '✗', 'score': 0},
        'pulsedive': {'status': 'Not found'},
        'flagged': {'status': 'flagged', 'score': 50},
    }

    rendered = template.render(
        job={
            'id': 'badge-test',
            'ioc': 'example.com',
            'score': 0,
            'result': {
                'ioc': 'example.com',
                'sources': sources,
                'sources_checked': len(sources),
                'sources_flagged': 1,
            },
        },
        request=SimpleNamespace(
            query_params={},
            url=SimpleNamespace(path='/reports'),
            state=SimpleNamespace(user={'role': ''}),
        ),
    )
    source_section = rendered.split('Threat Intelligence Sources', 1)[1].split(
        '</table>', 1
    )[0]
    source_section = source_section.split('<tbody>', 1)[1].split('</tbody>', 1)[0]
    badges = re.findall(
        r'<span class="badge ([^"]+)"(?: title="[^"]*")?>([^<]+)</span>',
        source_section,
    )

    assert badges == [
        ('badge-warning', 'Error'),
        ('badge-warning', 'Error'),
        ('badge-success', 'Clean'),
        ('badge-success', 'Clean'),
        ('badge-danger', 'Flagged'),
    ]
    assert source_section.count('title="Source unavailable"') == 2
    assert 'N/A' not in source_section          # N/A lives only in the collapsed list
    na_details = rendered.split('<details class="rv-na"', 1)[1].split('</details>', 1)[0]
    assert 'abuseipdb' in na_details.lower()
    assert len(re.findall(
        r'<span class="badge badge-secondary"[^>]*>N/A</span>', na_details
    )) == 1
