"""Security regression tests for trusted-domain URL matching."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.tools.ioc_investigator import IOCInvestigator, TRUSTED_DOMAINS
from src.analyzers.text_analyzer import TextFileAnalyzer
from src.utils.helpers import extract_domain_from_url, is_domain_or_subdomain


@pytest.fixture
def investigator():
    # The trust predicate is pure; bypass the integration-heavy constructor.
    return IOCInvestigator.__new__(IOCInvestigator)


@pytest.mark.parametrize(
    'url',
    [
        'https://microsoft.com.evil-phishing-site.ru/login',
        'https://evil.example/steal?ref=microsoft.com',
        'https://malware-drop.com/download/microsoft.com/update.exe',
        'https://microsoft.com@evil.example/login',
        'https://evilmicrosoft.com/login',
    ],
)
def test_trusted_name_outside_actual_hostname_is_not_trusted(investigator, url):
    assert investigator._is_trusted_infrastructure(url, 'url') is False


@pytest.mark.parametrize(
    'url',
    [
        'https://microsoft.com/',
        'https://login.microsoft.com/path?redirect=evil.example',
        'https://MICROSOFT.COM:443/',
        'https://microsoft.com./',
    ],
)
def test_exact_trusted_hostname_and_real_subdomains_remain_trusted(investigator, url):
    assert investigator._is_trusted_infrastructure(url, 'url') is True


def test_trust_decision_records_hostname_and_matching_domain(investigator):
    assert investigator._trusted_infrastructure_match(
        'https://login.microsoft.com/path', 'url'
    ) == {
        'hostname': 'login.microsoft.com',
        'matched_domain': 'microsoft.com',
    }


@pytest.mark.parametrize('trusted', sorted(TRUSTED_DOMAINS))
def test_every_trusted_domain_requires_the_hostname_boundary(investigator, trusted):
    assert investigator._is_trusted_infrastructure(
        f'https://login.{trusted}/', 'url'
    ) is True
    assert investigator._is_trusted_infrastructure(
        f'https://{trusted}.evil.example/', 'url'
    ) is False
    assert investigator._is_trusted_infrastructure(
        f'https://evil.example/path/{trusted}', 'url'
    ) is False


@pytest.mark.parametrize(
    'url',
    [
        # Browsers treat backslash as a slash for special schemes, while
        # urllib can treat microsoft.com as the authority in this string.
        r'https://evil.example\@microsoft.com/login',
        'https://microsoft.com:not-a-port/login',
        'https:///microsoft.com/login',
        'https://microsoft.com/has a space',
    ],
)
def test_ambiguous_or_malformed_url_fails_closed(investigator, url):
    assert investigator._is_trusted_infrastructure(url, 'url') is False


def test_domain_matching_requires_dns_label_boundary():
    assert is_domain_or_subdomain('login.microsoft.com', 'microsoft.com') is True
    assert is_domain_or_subdomain('microsoft.com.evil', 'microsoft.com') is False
    assert is_domain_or_subdomain('evilmicrosoft.com', 'microsoft.com') is False


def test_extract_domain_returns_hostname_not_netloc():
    assert extract_domain_from_url('https://user:pass@Example.COM:8443/path') == 'example.com'


def test_text_analyzer_does_not_whitelist_suffix_lookalike():
    result = TextFileAnalyzer()._extract_urls('https://evilmicrosoft.com/payload')[0]

    assert result['host'] == 'evilmicrosoft.com'
    assert result['is_whitelisted'] is False


@pytest.mark.asyncio
async def test_bypass_url_reaches_threat_intelligence():
    investigator = IOCInvestigator.__new__(IOCInvestigator)
    investigator.config = {'analysis': {'enable_llm': False}}
    investigator.rag_kb = None
    investigator.llm_analyzer = MagicMock()
    investigator.threat_intel = MagicMock()
    investigator.threat_intel.investigate_ioc_comprehensive = AsyncMock(
        return_value={
            'sources': {},
            'sources_checked': 0,
            'sources_flagged': 0,
        }
    )
    investigator._enrich_domain = AsyncMock(return_value={})

    url = 'https://evil.example/steal?ref=microsoft.com'
    with (
        patch(
            'src.tools.ioc_investigator.IntelligentScoring.calculate_ioc_score',
            return_value=0,
        ),
        patch(
            'src.tools.ioc_investigator.IntelligentScoring.calculate_source_coverage',
            return_value={
                'total_sources_attempted': 1,
                'sources_flagged': 0,
                'sources_clean': 1,
            },
        ),
        patch(
            'src.tools.ioc_investigator.RuleGenerator.generate_ioc_rules',
            return_value={},
        ),
    ):
        result = await investigator.investigate(url)

    investigator.threat_intel.investigate_ioc_comprehensive.assert_awaited_once_with(
        url, 'url'
    )
    assert result.get('note') != (
        'Trusted infrastructure (Certificate Authority / CDN / Major vendor)'
    )
