import asyncio
from email.message import EmailMessage

from src.tools.email_analyzer import EmailAnalyzer


def _html_message() -> EmailMessage:
    message = EmailMessage()
    message['From'] = 'sender@external.test'
    message['To'] = 'recipient@example.test'
    message['Subject'] = 'Rule input test'
    message.set_content('Please review the links.')
    message.add_alternative(
        '<a href="https://fonts.gstatic.com/s/example/style.css">font</a>'
        '<a href="https://fonts.googleapis.com/css?family=Example">css</a>'
        '<a href="https://malicious.example.net/path?a=1&amp;b=2">external</a>',
        subtype='html',
    )
    return message


def _extract(message: EmailMessage) -> dict:
    analyzer = EmailAnalyzer({'analysis': {'enable_rag': False, 'enable_llm': False}})
    return asyncio.run(analyzer._extract_email_data(message))


def test_html_urls_are_unescaped_without_mutating_stored_html():
    data = _extract(_html_message())

    assert 'https://malicious.example.net/path?a=1&b=2' in data['urls']
    assert '&amp;' in data['body_html']
    assert '&amp;' not in ' '.join(data['urls'])


def test_detection_rules_filter_shared_allowlist_but_keep_external_urls(tmp_path):
    path = tmp_path / 'rule-inputs.eml'
    path.write_bytes(_html_message().as_bytes())

    analyzer = EmailAnalyzer({'analysis': {'enable_rag': False, 'enable_llm': False}})
    result = asyncio.run(analyzer.analyze(str(path)))
    rules = str(result['detection_rules'])

    assert 'https://fonts.gstatic.com' not in rules
    assert 'https://fonts.googleapis.com' not in rules
    assert 'https://malicious.example.net/path?a=1&b=2' in rules
    assert result['iocs_found']['urls'] == 3
