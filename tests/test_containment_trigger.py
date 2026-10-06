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


def test_kev_in_catalog_returns_true():
    results = [
        {"result": {"in_kev": True}, "server": "vulnerability-tools", "tool": "kev_check"},
    ]
    assert _aggregate_malicious_flag(results) is True


def test_kev_not_in_catalog_returns_false():
    results = [
        {"result": {"in_kev": False}, "server": "vulnerability-tools", "tool": "kev_check"},
    ]
    assert _aggregate_malicious_flag(results) is False


def test_kev_error_results_return_false():
    results = [
        {"error": "MCP request failed", "server": "vulnerability-tools", "tool": "kev_check"},
        {"result": {"error": "KEV check failed", "in_kev": True}, "server": "vulnerability-tools", "tool": "kev_check"},
    ]
    assert _aggregate_malicious_flag(results) is False


def test_existing_malicious_result_shapes_remain_supported():
    results = [
        {"result": {"malicious": True}, "server": "threat_intel_tools", "tool": "blocklist_check"},
        {"result": {"query_status": "ok", "data": [{"sha256_hash": "abc"}]}, "server": "threat_intel_tools", "tool": "malwarebazaar_hash_lookup"},
    ]
    assert _aggregate_malicious_flag(results) is True
