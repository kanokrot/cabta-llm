import asyncio
from email.message import EmailMessage
from types import SimpleNamespace

from src.tools.email_analyzer import EMAIL_ANALYSIS_STEPS, EmailAnalyzer
from src.web.analysis_manager import AnalysisManager
from src.web.routes import analysis as analysis_routes
from src.web.visibility import serialize_status


def _email_analyzer(monkeypatch, *, headers=None):
    analyzer = EmailAnalyzer.__new__(EmailAnalyzer)
    analyzer.config = {'analysis': {'enable_llm': False}}
    analyzer.ioc_investigator = None
    analyzer.file_analyzer = None
    analyzer.bec_detector = SimpleNamespace(analyze=lambda data: {
        'bec_score': 0,
        'verdict': 'LOW',
        'indicator_count': 0,
        'has_financial_indicators': False,
        'has_impersonation_indicators': False,
    })
    analyzer.advanced_analyzer = SimpleNamespace(
        analyze_headers=lambda msg: headers if headers is not None else {'anomalies': []},
        detect_link_text_mismatch=lambda value: [],
        detect_lookalike_domains=lambda value: [],
        analyze_html_obfuscation=lambda value: {},
        detect_qr_codes=lambda html, attachments: {'qr_codes_found': 0},
        detect_brand_impersonation=lambda *args: [],
        detect_mixed_script=lambda subject, sender: {
            'found': False, 'fields': {'subject': [], 'display_name': []}, 'count': 0,
        },
        fingerprint_email_template=lambda html, subject: {},
    )

    async def extract(msg):
        return {
            'from': 'analyst@example.com',
            'to': 'soc@example.org',
            'subject': 'Safe test',
            'date': '',
            'message_id': '',
            'reply_to': '',
            'return_path': '',
            'from_domain': 'example.com',
            'body_html': '',
            'body_text': 'safe',
            'urls': [],
            'ips': [],
            'domains': [],
            'attachments': [],
        }

    analyzer._extract_email_data = extract
    analyzer._check_spf = lambda msg: 'none'
    analyzer._check_dkim = lambda msg: 'none'
    analyzer._check_dmarc = lambda msg: 'none'
    analyzer._authentication_header_presence = lambda msg: {
        'spf': True, 'dkim': True, 'dmarc': True,
    }
    analyzer._build_indicator_summary = lambda *args, **kwargs: {
        'found': 0, 'checkable': 1, 'factors': [],
    }
    analyzer._calculate_base_phishing_score = lambda *args, **kwargs: 0
    analyzer._determine_indicator_verdict = lambda summary: 'CLEAN'
    return analyzer


def _write_email(tmp_path):
    message = EmailMessage()
    message['From'] = 'analyst@example.com'
    message['To'] = 'soc@example.org'
    message['Subject'] = 'Safe test'
    message.set_content('safe')
    path = tmp_path / 'sample.eml'
    path.write_bytes(message.as_bytes())
    return path


def test_email_callback_reports_real_order_and_optional_skips(monkeypatch, tmp_path):
    analyzer = _email_analyzer(monkeypatch)
    monkeypatch.setattr(
        'src.tools.email_analyzer.EmailForensics.perform_full_forensics',
        lambda *args: {'forensics_score': 0},
    )
    monkeypatch.setattr(
        'src.tools.email_analyzer.EmailThreatIndicators.run_all_checks',
        lambda **kwargs: {
            'checks_run': 0, 'overall_severity': 'NONE',
            'total_score_impact': 0, 'active_checks': [],
        },
    )
    events = []
    result = asyncio.run(analyzer.analyze(
        str(_write_email(tmp_path)), on_step=lambda key, state: events.append((key, state)),
    ))

    assert result['verdict'] == 'CLEAN'
    observed = []
    for key, _ in events:
        if key not in observed:
            observed.append(key)
    assert observed == [key for key, _ in EMAIL_ANALYSIS_STEPS]
    assert events[-4:] == [
        ('attachment_analysis', 'skipped'),
        ('llm_analysis', 'skipped'),
        ('detection_rules', 'started'),
        ('detection_rules', 'completed'),
    ]
    assert ('ioc_investigation', 'skipped') in events


def test_email_callback_reports_failed_step_and_preserves_error_handling(monkeypatch, tmp_path):
    analyzer = _email_analyzer(monkeypatch)
    analyzer.advanced_analyzer.analyze_headers = lambda msg: (_ for _ in ()).throw(
        RuntimeError('header failure')
    )
    events = []
    result = asyncio.run(analyzer.analyze(
        str(_write_email(tmp_path)), on_step=lambda key, state: events.append((key, state)),
    ))

    assert 'error' in result
    assert events[-1] == ('headers', 'failed')


def test_step_progress_is_based_on_completed_and_skipped(tmp_path):
    manager = AnalysisManager(str(tmp_path / 'jobs.db'))
    job_id = manager.create_job('email', {})
    definitions = (('parse', 'Parse'), ('ioc', 'IOC'), ('llm', 'AI'))
    steps, callback = analysis_routes._step_callback(manager, job_id, definitions)

    callback('parse', 'started')
    assert manager.get_job(job_id)['progress'] == 0
    callback('parse', 'completed')
    assert manager.get_job(job_id)['progress'] == 33
    callback('ioc', 'skipped')
    assert manager.get_job(job_id)['progress'] == 67
    callback('llm', 'failed')
    job = manager.get_job(job_id)
    assert job['progress'] == 67
    assert job['params']['_analysis_steps'][2]['state'] == 'failed'


def test_status_serializes_steps_without_extra_result_data():
    job = {
        'id': 'job-1',
        'status': 'running',
        'progress': 50,
        'current_step': 'Parse',
        'verdict': None,
        'score': None,
        'params': {
            '_analysis_steps': [
                {'key': 'parse', 'label': 'Parse', 'state': 'completed'},
                {'key': 'ioc', 'label': 'IOC', 'state': 'skipped'},
                {'key': 'llm', 'label': 'AI', 'state': 'pending'},
            ],
            'secret': 'not exposed',
        },
        'result': {'secret_result': 'not exposed'},
    }

    status = serialize_status(job)
    assert status['steps_total'] == 3
    assert status['steps_done'] == 2
    assert status['steps'][1]['state'] == 'skipped'
    assert 'secret' not in status
    assert 'secret_result' not in status
