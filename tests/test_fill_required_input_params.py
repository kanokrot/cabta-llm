"""Regression tests for required playbook input fallback behavior."""

from src.agent.playbook_engine import PlaybookEngine


def _playbook(*input_params):
    return {"input_params": list(input_params)}


def test_single_required_param_backfills_from_generic_query():
    playbook = _playbook({"name": "alert_text", "required": True})
    input_data = {"query": "suspicious process alert"}

    result = PlaybookEngine._fill_required_input_params(playbook, input_data)

    assert result is input_data
    assert result["alert_text"] == "suspicious process alert"


def test_multiple_required_params_do_not_broadcast_generic_query():
    playbook = _playbook(
        {"name": "host_identifier", "required": True},
        {"name": "remote_username", "required": True},
        {"name": "remote_key_path", "required": True},
    )
    input_data = {"query": "server.example.test"}

    result = PlaybookEngine._fill_required_input_params(playbook, input_data)

    assert result is input_data
    assert result == {"query": "server.example.test"}
    assert "host_identifier" not in result
    assert "remote_username" not in result
    assert "remote_key_path" not in result


def test_multiple_required_params_already_present_are_unchanged():
    playbook = _playbook(
        {"name": "file_path", "required": True},
        {"name": "analysis_context", "required": True},
    )
    analysis_context = {"file_type": "PE", "verdict": "MALICIOUS"}
    input_data = {
        "query": "generic fallback must not be used",
        "file_path": "C:/samples/malware.exe",
        "analysis_context": analysis_context,
    }
    expected = dict(input_data)

    result = PlaybookEngine._fill_required_input_params(playbook, input_data)

    assert result is input_data
    assert result == expected
    assert result["analysis_context"] is analysis_context


def test_no_required_params_returns_input_unchanged():
    playbook = _playbook(
        {"name": "reported_by", "required": False},
        {"name": "notes"},
    )
    input_data = {"query": "unchanged", "reported_by": "analyst"}
    expected = dict(input_data)

    result = PlaybookEngine._fill_required_input_params(playbook, input_data)

    assert result is input_data
    assert result == expected
