import socket
from types import SimpleNamespace

from src.mcp_servers import free_osint_tools


def _query_result(status, answers=None):
    return SimpleNamespace(
        answers=answers or [],
        resolver="mock",
        status=status,
    )


def test_typosquat_all_dns_errors_are_unknown(monkeypatch):
    monkeypatch.setattr(free_osint_tools._dns_helper, "dns_available", lambda: True)
    monkeypatch.setattr(
        free_osint_tools._dns_helper,
        "resolve_record",
        lambda name, record_type: _query_result("error"),
    )

    result = free_osint_tools.typosquat_detect("example.com")

    assert result["failed_query_count"] == result["checked"]
    assert result["dns_unavailable"] is True
    assert result["risk_level"] == "UNKNOWN"
    assert "DNS resolution failed" in result["message"]


def test_typosquat_partial_dns_resolution_keeps_risk_calculation(monkeypatch):
    calls = {"count": 0}

    def resolve_record(name, record_type):
        calls["count"] += 1
        return _query_result("ok", ["192.0.2.1"]) if calls["count"] == 1 else _query_result("error")

    monkeypatch.setattr(free_osint_tools._dns_helper, "dns_available", lambda: True)
    monkeypatch.setattr(free_osint_tools._dns_helper, "resolve_record", resolve_record)

    result = free_osint_tools.typosquat_detect("example.com")

    assert result["resolving_count"] == 1
    assert result["failed_query_count"] < result["checked"]
    assert result["dns_unavailable"] is False
    assert result["risk_level"] == "LOW"


def test_typosquat_all_nxdomain_is_normal_low_risk(monkeypatch):
    monkeypatch.setattr(free_osint_tools._dns_helper, "dns_available", lambda: True)
    monkeypatch.setattr(
        free_osint_tools._dns_helper,
        "resolve_record",
        lambda name, record_type: _query_result("nxdomain"),
    )

    result = free_osint_tools.typosquat_detect("example.com")

    assert result["failed_query_count"] == 0
    assert result["dns_unavailable"] is False
    assert result["risk_level"] == "LOW"


def test_typosquat_socket_fallback_reports_dns_limitation(monkeypatch):
    monkeypatch.setattr(free_osint_tools._dns_helper, "dns_available", lambda: False)
    monkeypatch.setattr(
        socket,
        "gethostbyname",
        lambda name: (_ for _ in ()).throw(socket.gaierror("mock failure")),
    )

    result = free_osint_tools.typosquat_detect("example.com")

    assert result["dns_unavailable"] is True
    assert "cannot distinguish DNS timeouts from NXDOMAIN" in result["dns_limitations"][0]
