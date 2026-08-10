"""Standalone tests for _aggregate_malicious_flag (containment-trigger bug fix)."""

from src.agent.playbook_engine import _aggregate_malicious_flag


def test_mcp_wrapped_malicious_result_returns_true():
    results = [
        {"result": {"malicious": True, "source": "malwarebazaar"}, "server": "threat-intel-free", "tool": "malwarebazaar_hash_lookup"},
    ]
    assert _aggregate_malicious_flag(results) is True


def test_non_malicious_and_error_results_return_false():
    results = [
        {"result": {"malicious": False}, "server": "threat-intel-free", "tool": "blocklist_check"},
        {"error": "timeout"},
    ]
    assert _aggregate_malicious_flag(results) is False


def test_empty_list_returns_false():
    assert _aggregate_malicious_flag([]) is False


def test_non_list_input_returns_false():
    assert _aggregate_malicious_flag(None) is False


def test_malwarebazaar_query_status_ok_with_data_returns_true():
    results = [
        {"result": {"query_status": "ok", "data": [{"sha256_hash": "abc"}]}, "server": "threat-intel-free", "tool": "malwarebazaar_hash_lookup"},
    ]
    assert _aggregate_malicious_flag(results) is True


def test_malwarebazaar_hash_not_found_returns_false():
    results = [
        {"result": {"query_status": "hash_not_found"}, "server": "threat-intel-free", "tool": "malwarebazaar_hash_lookup"},
    ]
    assert _aggregate_malicious_flag(results) is False
