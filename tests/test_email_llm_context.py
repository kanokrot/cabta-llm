from email.message import EmailMessage
from unittest.mock import AsyncMock, MagicMock, mock_open

import pytest

from src.integrations.llm_analyzer import LLMAnalyzer
from src.tools.email_analyzer import EmailAnalyzer
import src.tools.email_analyzer as email_analyzer_module


def _build_email_analyzer(monkeypatch):
    analyzer = EmailAnalyzer.__new__(EmailAnalyzer)
    analyzer.config = {'analysis': {'enable_llm': True}}
    analyzer.llm_analyzer = MagicMock()
    analyzer.llm_analyzer.analyze_email = AsyncMock(
        return_value={'verdict': 'SPAM', 'analysis': 'Scoring context captured.'}
    )

    analyzer.advanced_analyzer = MagicMock()
    analyzer.advanced_analyzer.analyze_headers.return_value = {
        'anomalies': [],
        'received_chain': [],
        'x_headers': {},
    }
    analyzer.advanced_analyzer.detect_link_text_mismatch.return_value = []
    analyzer.advanced_analyzer.detect_lookalike_domains.return_value = [
        {
            'domain': 'example.com',
            'brand': 'Example',
            'similarity': 0.91,
            'risk': 'medium',
        },
        {
            'domain': 'apple.com',
            'brand': 'Apple',
            'similarity': 0.88,
            'risk': 'high',
        },
    ]
    analyzer.advanced_analyzer.analyze_html_obfuscation.return_value = {
        'risk_score': 0,
    }
    analyzer.advanced_analyzer.detect_qr_codes.return_value = {
        'qr_codes_found': 0,
    }
    analyzer.advanced_analyzer.detect_brand_impersonation.return_value = []
    analyzer.advanced_analyzer.fingerprint_email_template.return_value = {}

    analyzer.bec_detector = MagicMock()
    analyzer.bec_detector.analyze.return_value = {
        'bec_score': 0,
        'verdict': 'LOW',
        'indicator_count': 0,
        'has_financial_indicators': False,
        'has_impersonation_indicators': False,
    }

    analyzer.ioc_investigator = object()

    async def investigate_iocs(_email_data, capability_errors):
        capability_errors.append({
            'capability': 'ioc_investigator',
            'status': 'timeout',
            'message': 'IOC investigation timed out.',
        })
        return []

    analyzer._investigate_iocs = investigate_iocs
    analyzer.file_analyzer = None
    analyzer.rag_kb = None
    analyzer._calculate_base_phishing_score = MagicMock(return_value=70)
    analyzer._check_spf = MagicMock(return_value='pass')
    analyzer._check_dkim = MagicMock(return_value='pass')
    analyzer._check_dmarc = MagicMock(return_value='pass')
    analyzer._extract_email_data = AsyncMock(
        return_value={
            'from': 'sender@example.com',
            'from_domain': 'example.com',
            'to': 'recipient@example.com',
            'subject': 'Quarterly update',
            'date': '',
            'reply_to': '',
            'body_text': 'Routine message.',
            'body_html': '',
            'attachments': [],
            'urls': [],
            'ips': [],
            'domains': [],
        }
    )

    monkeypatch.setattr(
        email_analyzer_module.EmailForensics,
        'perform_full_forensics',
        MagicMock(return_value={'forensics_score': 12}),
    )
    monkeypatch.setattr(
        email_analyzer_module.EmailThreatIndicators,
        'run_all_checks',
        MagicMock(
            return_value={
                'checks_run': 10,
                'overall_severity': 'NONE',
                'total_score_impact': 0,
                'active_checks': [],
            }
        ),
    )
    monkeypatch.setattr(
        email_analyzer_module.RuleGenerator,
        'generate_email_rules',
        MagicMock(return_value={}),
    )

    message = EmailMessage()
    message['From'] = 'sender@example.com'
    message['To'] = 'recipient@example.com'
    message['Subject'] = 'Quarterly update'
    message.set_content('Routine message.')
    monkeypatch.setattr('builtins.open', mock_open(read_data=b''))
    monkeypatch.setattr(
        email_analyzer_module.email,
        'message_from_binary_file',
        MagicMock(return_value=message),
    )
    return analyzer


@pytest.mark.asyncio
async def test_email_analyzer_passes_calculated_scores_and_lookalikes(monkeypatch):
    analyzer = _build_email_analyzer(monkeypatch)

    result = await analyzer.analyze('message.eml')

    assert result['composite_score'] == 70
    context = analyzer.llm_analyzer.analyze_email.await_args.args[0]
    assert context['base_score'] == 70
    assert context['composite_score'] == 70
    assert context['forensics_score'] == 12
    assert [item['domain'] for item in context['lookalike_domains']] == [
        'example.com',
        'apple.com',
    ]
    assert context['capability_errors'][0]['status'] == 'timeout'


@pytest.mark.asyncio
async def test_llm_prompt_includes_scores_lookalikes_and_capability_limits():
    analyzer = LLMAnalyzer({'llm': {'provider': 'ollama'}})
    analyzer._call_ollama_api = AsyncMock(
        return_value={'verdict': 'SPAM', 'analysis': 'Assessment completed.'}
    )

    await analyzer.analyze_email({
        'subject': 'Quarterly update',
        'from': 'sender@example.com',
        'to': 'recipient@example.com',
        'base_score': 70,
        'composite_score': 70,
        'forensics_score': 12,
        'lookalike_domains': [
            {'domain': 'example.com', 'brand': 'Example', 'similarity': 0.91, 'risk': 'medium'},
            {'domain': 'apple.com', 'brand': 'Apple', 'similarity': 0.88, 'risk': 'high'},
        ],
        'capability_errors': [
            {
                'capability': 'ioc_investigator',
                'status': 'timeout',
                'message': 'IOC investigation timed out.',
            }
        ],
    })

    prompt = analyzer._call_ollama_api.await_args.args[0]
    assert 'Base Phishing Score: 70/100' in prompt
    assert 'Forensics Score: 12/100' in prompt
    assert 'Composite Score: 70/100' in prompt
    assert 'example.com' in prompt
    assert 'apple.com' in prompt
    assert 'ioc_investigator' in prompt
    assert 'timeout' in prompt
    assert 'if the base score is high, explain before concluding CLEAN' in prompt
    assert analyzer._ensure_list(2) == [2]
