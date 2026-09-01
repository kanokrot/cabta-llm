"""Characterize the current attachment-macro aggregation and lookup semantics."""

from src.agent.playbook_engine import _aggregate_malicious_flag, _resolve_var


def _olevba_mcp_result(*, suspicious_keywords):
    """Match remnux_tools.olevba_analyze through MCPClient.call_tool."""
    return {
        "result": {
            "file": "C:/attachments/sample.docm",
            "has_macros": bool(suspicious_keywords),
            "macro_count": 1 if suspicious_keywords else 0,
            "macros": [],
            "suspicious_keywords": suspicious_keywords,
            "iocs": {
                "urls": [],
                "ips": [],
                "executables": [],
                "registry_keys": [],
            },
            "auto_exec_triggers": [],
        },
        "server": "remnux_tools",
        "tool": "olevba_analyze",
    }


def test_olevba_suspicious_keywords_do_not_aggregate_as_malicious():
    attachment_macro_check_results = [
        _olevba_mcp_result(suspicious_keywords=[]),
        _olevba_mcp_result(
            suspicious_keywords=[
                {
                    "type": "Suspicious",
                    "keyword": "Shell",
                    "description": "May run an executable file or a system command",
                }
            ]
        ),
    ]

    assert _aggregate_malicious_flag(attachment_macro_check_results) is False


def test_unsuffixed_attachment_macro_suspicious_resolves_to_none_when_missing():
    attachment_macro_check_results = [
        _olevba_mcp_result(suspicious_keywords=[]),
        _olevba_mcp_result(
            suspicious_keywords=[
                {
                    "type": "Suspicious",
                    "keyword": "Shell",
                    "description": "May run an executable file or a system command",
                }
            ]
        ),
    ]
    context = {
        "attachment_macro_check_results": attachment_macro_check_results,
        "attachment_macro_check_any_malicious": False,
    }

    assert _resolve_var("attachment_macro_check.suspicious", context) is None


def test_attachment_macro_suspicious_resolves_to_none_for_list_shaped_step_value():
    attachment_macro_check_results = [
        _olevba_mcp_result(suspicious_keywords=[]),
        _olevba_mcp_result(
            suspicious_keywords=[
                {
                    "type": "Suspicious",
                    "keyword": "Shell",
                    "description": "May run an executable file or a system command",
                }
            ]
        ),
    ]
    context = {"attachment_macro_check": attachment_macro_check_results}

    assert _resolve_var("attachment_macro_check.suspicious", context) is None
