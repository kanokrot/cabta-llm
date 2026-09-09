from unittest.mock import AsyncMock

import pytest

from src.integrations.sandbox_submitter import (
    SandboxSubmitter,
    SubmissionResult,
    SubmissionStatus,
    auto_submit_suspicious,
)


def test_reads_nested_api_keys_for_all_providers(monkeypatch):
    environment_variables = (
        "ANYRUN_API_KEY",
        "HYBRID_API_KEY",
        "JOESANDBOX_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "TRIAGE_API_KEY",
    )
    for variable in environment_variables:
        monkeypatch.delenv(variable, raising=False)

    submitter = SandboxSubmitter({
        "api_keys": {
            "anyrun": "anyrun-key",
            "hybrid_analysis": "hybrid-key",
            "joe_sandbox": "joe-key",
            "virustotal": "virustotal-key",
            "triage": "triage-key",
        }
    })

    assert submitter.api_keys == {
        "anyrun": "anyrun-key",
        "hybrid": "hybrid-key",
        "joe": "joe-key",
        "virustotal": "virustotal-key",
        "triage": "triage-key",
    }
    assert submitter.available_providers == [
        "anyrun",
        "hybrid",
        "joe",
        "virustotal",
        "triage",
    ]


def test_api_key_environment_fallbacks_match_default_config(monkeypatch):
    environment_keys = {
        "ANYRUN_API_KEY": "anyrun-env-key",
        "HYBRID_API_KEY": "hybrid-env-key",
        "JOESANDBOX_API_KEY": "joe-env-key",
        "VIRUSTOTAL_API_KEY": "virustotal-env-key",
        "TRIAGE_API_KEY": "triage-env-key",
    }
    for variable, value in environment_keys.items():
        monkeypatch.setenv(variable, value)

    submitter = SandboxSubmitter({"api_keys": {}})

    assert submitter.api_keys == {
        "anyrun": "anyrun-env-key",
        "hybrid": "hybrid-env-key",
        "joe": "joe-env-key",
        "virustotal": "virustotal-env-key",
        "triage": "triage-env-key",
    }


@pytest.mark.parametrize(
    ("score", "expected_submitted"),
    [(0, False), (29, False), (30, True), (40, True), (70, True),
     (71, False), (100, False)],
)
@pytest.mark.asyncio
async def test_auto_submit_score_gate(
    tmp_path, monkeypatch, score, expected_submitted
):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    submit_file = AsyncMock(return_value={
        "anyrun": SubmissionResult(
            provider="anyrun",
            success=True,
            task_id="task-id",
            status=SubmissionStatus.PENDING,
        )
    })
    monkeypatch.setattr(SandboxSubmitter, "submit_file", submit_file)

    result = await auto_submit_suspicious(
        str(sample), score, {"api_keys": {"anyrun": "test-key"}}
    )

    if expected_submitted:
        assert result["submitted"] is True
        submit_file.assert_awaited_once_with(str(sample), private=True)
    else:
        assert result is None
        submit_file.assert_not_awaited()


@pytest.mark.asyncio
async def test_private_submission_skips_unsupported_provider(
    tmp_path, monkeypatch, caplog
):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    submit_virustotal = AsyncMock()
    monkeypatch.setattr(
        SandboxSubmitter, "_submit_virustotal", submit_virustotal
    )
    submitter = SandboxSubmitter({
        "api_keys": {"virustotal": "virustotal-key"}
    })

    results = await submitter.submit_file(str(sample), private=True)

    assert results["virustotal"].success is False
    assert "does not support" in results["virustotal"].error_message
    assert "private submission was requested" in caplog.text
    submit_virustotal.assert_not_awaited()


@pytest.mark.asyncio
async def test_results_map_to_invoked_providers_when_large_file_is_skipped(
    tmp_path, monkeypatch
):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"too large for first provider")
    submitter = SandboxSubmitter({
        "api_keys": {
            "anyrun": "anyrun-key",
            "hybrid_analysis": "hybrid-key",
            "triage": "triage-key",
        }
    })
    monkeypatch.setattr(
        submitter,
        "SIZE_LIMITS",
        {"anyrun": 1, "hybrid": 1_000, "triage": 1_000},
    )

    async def fake_submit(provider, *_args):
        return SubmissionResult(
            provider=provider,
            success=True,
            task_id=f"{provider}-task",
        )

    monkeypatch.setattr(submitter, "_submit_to_provider", fake_submit)

    results = await submitter.submit_file(str(sample), private=False)

    assert results["anyrun"].success is False
    assert results["anyrun"].error_message == "File too large for anyrun"
    assert results["hybrid"].provider == "hybrid"
    assert results["hybrid"].task_id == "hybrid-task"
    assert results["triage"].provider == "triage"
    assert results["triage"].task_id == "triage-task"


@pytest.mark.asyncio
async def test_auto_submit_reports_false_when_no_provider_is_configured(
    tmp_path, monkeypatch
):
    for variable in (
        "ANYRUN_API_KEY",
        "HYBRID_API_KEY",
        "JOESANDBOX_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "TRIAGE_API_KEY",
    ):
        monkeypatch.delenv(variable, raising=False)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")

    result = await auto_submit_suspicious(
        str(sample), 40, {"api_keys": {}}
    )

    assert result["submitted"] is False
    assert result["results"]["error"]["error"] == (
        "No sandbox providers configured"
    )
