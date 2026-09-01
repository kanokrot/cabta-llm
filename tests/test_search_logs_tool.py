"""Tests for the local forensic search_logs MCP tool."""

import json

from src.mcp_servers.forensics_tools import _flatten_indicators, search_logs


def _decode(result: str) -> dict:
    return json.loads(result)


def test_flatten_indicators_matches_extract_iocs_shape():
    nested = {
        "ipv4": ["203.0.113.10", "203.0.113.10"],
        "domains": ["evil.example", "EVIL.EXAMPLE"],
        "urls": ["https://evil.example/payload"],
        "emails": ["operator@evil.example"],
        "hashes": {
            "md5": ["d41d8cd98f00b204e9800998ecf8427e"],
            "sha1": [],
            "sha256": ["e3b0c44298fc1c149afbf4c8996fb924"],
        },
        "ignored": [None, "", "   ", 42],
    }

    assert _flatten_indicators(nested) == [
        "203.0.113.10",
        "evil.example",
        "https://evil.example/payload",
        "operator@evil.example",
        "d41d8cd98f00b204e9800998ecf8427e",
        "e3b0c44298fc1c149afbf4c8996fb924",
    ]


def test_search_logs_accepts_flat_and_nested_indicators(tmp_path):
    first = tmp_path / "security.log"
    first.write_text(
        "clean line\n"
        "2026-09-01T10:00:00Z connection to 203.0.113.10\n"
        "DNS request for Evil.Example\n",
        encoding="utf-8",
    )
    second = tmp_path / "endpoint.log"
    second.write_text(
        "operator downloaded https://evil.example/payload\n"
        "another clean line\n",
        encoding="utf-8",
    )
    (tmp_path / "nested").mkdir()

    flat_result = _decode(search_logs(str(tmp_path), ["203.0.113.10"]))
    assert flat_result["total_matches_found"] == 1
    assert flat_result["matches"][0]["file"] == str(first.resolve())
    assert flat_result["matches"][0]["line_number"] == 2
    assert flat_result["matches"][0]["indicator"] == "203.0.113.10"

    nested_result = _decode(search_logs(str(tmp_path), {
        "domains": ["evil.example"],
        "urls": ["https://evil.example/payload"],
        "hashes": {"sha256": []},
    }))
    found = {
        (match["file"], match["line_number"], match["indicator"])
        for match in nested_result["matches"]
    }
    assert (str(first.resolve()), 3, "evil.example") in found
    assert (str(second.resolve()), 1, "evil.example") in found
    assert (str(second.resolve()), 1, "https://evil.example/payload") in found
    assert all("clean line" not in match["line"] for match in nested_result["matches"])


def test_search_logs_caps_results_and_reports_total(tmp_path):
    log_file = tmp_path / "repeated.log"
    log_file.write_text("\n".join(["alert evil.example"] * 5), encoding="utf-8")

    result = _decode(search_logs(str(log_file), ["evil.example"], max_results=2))

    assert len(result["matches"]) == 2
    assert result["returned_matches"] == 2
    assert result["total_matches_found"] == 5
    assert result["truncated"] is True


def test_search_logs_returns_error_for_missing_source(tmp_path):
    result = _decode(search_logs(str(tmp_path / "missing.log"), ["evil.example"]))

    assert "error" in result
    assert "not found" in result["error"].lower()


def test_search_logs_time_range_smoke(tmp_path):
    log_file = tmp_path / "timed.log"
    log_file.write_text(
        "2026-08-31T23:59:59Z evil.example before range\n"
        "2026-09-01T12:00:00Z evil.example in range\n"
        "evil.example without timestamp\n"
        "2026-09-02T00:00:01Z evil.example after range\n",
        encoding="utf-8",
    )

    result = _decode(search_logs(
        str(log_file),
        ["evil.example"],
        time_range={
            "start": "2026-09-01T00:00:00Z",
            "end": "2026-09-02T00:00:00Z",
        },
    ))

    assert [match["line_number"] for match in result["matches"]] == [2, 3]
