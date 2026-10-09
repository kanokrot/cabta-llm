import pytest
import json
import re

from src.integrations.llm_analyzer import LLMAnalyzer


class _ProviderStub:
    def __init__(self):
        self.prompt = None

    async def __call__(self, prompt):
        self.prompt = prompt
        return {
            "verdict": "CLEAN",
            "analysis": "No findings.",
            "recommendations": [],
        }


async def _build_prompt(monkeypatch, sources):
    analyzer = LLMAnalyzer({"llm": {"provider": "ollama"}})
    provider = _ProviderStub()
    monkeypatch.setattr(analyzer, "_call_ollama_api", provider)

    await analyzer.analyze_ioc_results(
        "example.test",
        "domain",
        {
            "sources": sources,
            "sources_checked": len(sources),
            "sources_flagged": 0,
            "threat_score": 0,
        },
    )

    assert provider.prompt is not None
    return provider.prompt


RULE_9 = (
    "9. Recommend restoring a feed and re-running now only for degraded scored\n"
    "    sources listed in scored_degraded. For degraded context sources, mention\n"
    "    briefly that they are supporting evidence and do not affect the score.\n"
    "    Never recommend restoring a permanently excluded source; permanently\n"
    "    excluded sources are: circl, greynoise, pulsedive, talos.\n"
    "    Do not suggest waiting days for a degraded scored source to recover."
)
RULE_10 = (
    "10. If any source is degraded, do not recommend \"maintaining\" or \"recording\"\n"
    "    a Clean status; describe the verdict as provisional."
)


@pytest.mark.asyncio
async def test_degraded_source_prompt_contains_rules_and_source_status(monkeypatch):
    prompt = await _build_prompt(
        monkeypatch,
        {"credentialed_feed": {"error": "credentials rejected"}},
    )

    assert RULE_9 in prompt
    assert RULE_10 in prompt
    assert "Source Status" in prompt
    assert "credentialed_feed" in prompt
    assert "scored_degraded" in prompt
    assert "context_degraded" in prompt


@pytest.mark.asyncio
async def test_prompt_separates_scored_and_context_degraded_sources(monkeypatch):
    prompt = await _build_prompt(
        monkeypatch,
        {
            "spamhaus": {"error": "feed timeout"},
            "alienvault": {"error": "credentials rejected"},
        },
    )

    # Recommendation scope follows the score input set, while context feed
    # failures remain available as limited supporting evidence.
    source_status_json = re.search(
        r"\*\*Source Status:\*\*\n(.*?)\n\*\*IMPORTANT RULES:\*\*",
        prompt,
        re.DOTALL,
    ).group(1)
    source_status = json.loads(source_status_json)
    assert source_status["scored_degraded"] == [
        {"source": "spamhaus", "reason": "feed timeout"}
    ]
    assert source_status["context_degraded"] == [
        {"source": "alienvault", "reason": "credentials rejected"}
    ]
    # The old combined list was removed so all degraded names are no longer
    # presented as one undifferentiated restore queue.
    assert '"degraded": [' not in prompt
    assert "do not affect the score" in prompt
    assert "only for degraded scored" in prompt


@pytest.mark.asyncio
async def test_prompt_names_permanently_excluded_sources(monkeypatch):
    prompt = await _build_prompt(
        monkeypatch,
        {
            "greynoise": {"error": "legacy feed unavailable"},
            "talos": {"error": "legacy feed unavailable"},
            "pulsedive": {"error": "legacy feed unavailable"},
            "circl": {"error": "legacy feed unavailable"},
        },
    )

    # These legacy feeds can appear in old payloads but are not recoverable;
    # expose the single permanent-exclusion list to prevent restore advice.
    assert "excluded sources are: circl, greynoise, pulsedive, talos." in prompt


@pytest.mark.asyncio
async def test_prompt_keeps_conditional_rules_without_degraded_sources(monkeypatch):
    prompt = await _build_prompt(
        monkeypatch,
        {"healthy_feed": {"status": "ok"}},
    )

    assert RULE_9 in prompt
    assert RULE_10 in prompt


@pytest.mark.asyncio
async def test_prompt_preserves_distinctive_rules_one_through_eleven(monkeypatch):
    prompt = await _build_prompt(monkeypatch, {})

    assert "1. The scoring engine verdict above is authoritative." in prompt
    assert "4. If any source is degraded, state that the engine verdict reflects limited coverage and name the degraded sources." in prompt
    assert "8. ONLY reference source names that appear in the \"Key Findings\" or \"Source Status\" sections above. Do NOT mention any other source by name." in prompt
    assert "Scorer Source Breakdown (authoritative for source flags and score contributions)" in prompt
    assert "sole authority" in prompt
    # These rules preserve existing coverage, allowlisting, source-name, and
    # provisional-verdict guardrails while only rule 9 changes its scope.
    assert "7. Do not recommend allowlisting when any source is degraded." in prompt
    assert "10. If any source is degraded, do not recommend \"maintaining\" or \"recording\"" in prompt
