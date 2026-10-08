"""Unsupported IOC types must stop before threat-intel lookup and scoring."""

import pytest
from unittest.mock import AsyncMock, Mock

from src.tools.ioc_investigator import IOCInvestigator


@pytest.mark.parametrize(
    ("ioc", "expected_error"),
    [
        ("analyst@example.com", "Unsupported IOC type: email"),
        ("CVE-2024-1234", "Unsupported IOC type: cve"),
    ],
)
@pytest.mark.asyncio
async def test_unsupported_ioc_types_skip_threat_intel_and_scoring(
    monkeypatch, ioc, expected_error
):
    investigator = IOCInvestigator.__new__(IOCInvestigator)
    investigator.threat_intel = Mock()
    investigator.threat_intel.investigate_ioc_comprehensive = AsyncMock()
    score = Mock()
    monkeypatch.setattr(
        "src.tools.ioc_investigator.IntelligentScoring.calculate_ioc_score",
        score,
    )

    result = await investigator.investigate(ioc)

    assert result == {"error": expected_error}
    investigator.threat_intel.investigate_ioc_comprehensive.assert_not_awaited()
    score.assert_not_called()
