import json

from src.mcp_servers import malwoverview_tools


def _stub_common(monkeypatch):
    monkeypatch.setattr(malwoverview_tools, "_run_malwoverview", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        malwoverview_tools,
        "_query_urlhaus_host",
        lambda value: {"query_status": "no_results"},
    )
    monkeypatch.setattr(
        malwoverview_tools,
        "_query_urlhaus_url",
        lambda value: {"query_status": "no_results"},
    )
    monkeypatch.setattr(
        malwoverview_tools,
        "_query_feodo_tracker_ip",
        lambda value: {"found": False},
    )
    monkeypatch.setattr(
        malwoverview_tools,
        "_query_malwarebazaar_hash",
        lambda value: {"query_status": "hash_not_found"},
    )


def test_threatfox_exact_ioc_match_sets_found_true(monkeypatch):
    _stub_common(monkeypatch)
    monkeypatch.setattr(
        malwoverview_tools,
        "_query_threatfox_ioc",
        lambda value: {
            "query_status": "ok",
            "data": [{"ioc": "1.2.3.4", "ioc_type": "ipv4"}],
        },
    )

    result = json.loads(malwoverview_tools.malwoverview_ip_check("1.2.3.4"))

    assert result["sources"]["threatfox"]["found"] is True


def test_threatfox_other_domain_sets_found_false(monkeypatch):
    _stub_common(monkeypatch)
    monkeypatch.setattr(
        malwoverview_tools,
        "_query_threatfox_ioc",
        lambda value: {
            "query_status": "ok",
            "data": [{"ioc": "other.example", "ioc_type": "domain"}],
        },
    )

    result = json.loads(malwoverview_tools.malwoverview_domain_check("example.com"))

    assert result["sources"]["threatfox"] == {
        "found": False,
        "message": "No exact match in ThreatFox",
    }


def test_threatfox_empty_data_sets_found_false(monkeypatch):
    _stub_common(monkeypatch)
    monkeypatch.setattr(
        malwoverview_tools,
        "_query_threatfox_ioc",
        lambda value: {"query_status": "ok", "data": []},
    )

    result = json.loads(malwoverview_tools.malwoverview_hash_lookup("a" * 64))

    assert result["sources"]["threatfox"] == {
        "found": False,
        "message": "No exact match in ThreatFox",
    }


def test_threatfox_url_lookup_separates_host(monkeypatch):
    _stub_common(monkeypatch)
    queried = []

    def fake_threatfox(value):
        queried.append(value)
        return {
            "query_status": "ok",
            "data": [{"ioc": "example.com", "ioc_type": "domain"}],
        }

    monkeypatch.setattr(malwoverview_tools, "_query_threatfox_ioc", fake_threatfox)

    result = json.loads(
        malwoverview_tools.malwoverview_url_check("https://example.com/path/file.exe")
    )

    assert queried == ["example.com"]
    assert result["sources"]["threatfox"]["found"] is True
