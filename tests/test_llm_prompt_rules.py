import pytest

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
    "9. If any source is degraded, one recommendation MUST be to restore that\n"
    "    source (fix its credentials or feed) and re-run the analysis now.\n"
    "    Do not suggest waiting days for a degraded source to recover."
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
