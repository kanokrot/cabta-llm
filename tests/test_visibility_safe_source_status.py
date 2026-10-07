"""Tests for safe source status metadata in SOC report payloads."""

import json

import pytest

from src.web.visibility import (
    ADMIN,
    INCIDENT_RESPONDER,
    SOC,
    THREAT_HUNTER,
    serialize_report_payload,
)


def _report_job(source_data):
    return {
        "id": "visibility-source-status-test",
        "analysis_type": "ioc",
        "status": "completed",
        "params": {"value": "192.0.2.1", "ioc_type": "ipv4"},
        "result": {"sources": {"circl": source_data}},
    }


def test_soc_payload_keeps_only_http_status_and_no_raw_error_text():
    job = _report_job({
        "status": "⚠",
        "score": 0,
        "error": r"HTTP 401 <script>x</script> C:\secret\key",
    })

    payload = serialize_report_payload(job, SOC)
    source = payload["sources"]["circl"]
    serialized = json.dumps(payload, ensure_ascii=False)

    assert set(source) == {"status", "score", "http_status"}
    assert source["http_status"] == 401
    assert "error" not in source
    assert "secret" not in serialized
    assert "<script>" not in serialized


@pytest.mark.parametrize(
    "source_data",
    [
        {"error": "HTTP 999"},
        {"error": "HTTP abc"},
        {"error": None},
        {},
    ],
)
def test_soc_payload_omits_invalid_or_absent_http_status(source_data):
    payload = serialize_report_payload(
        _report_job({"status": "⚠", "score": 0, **source_data}), SOC
    )
    assert "http_status" not in payload["sources"]["circl"]
    assert "error" not in payload["sources"]["circl"]


@pytest.mark.parametrize(
    ("feed_status", "is_included"),
    [("unavailable", True), ("available", False), ("UNAVAILABLE", False), (None, False)],
)
def test_soc_payload_only_passes_unavailable_feed_status(feed_status, is_included):
    payload = serialize_report_payload(
        _report_job({"status": "⚠", "feed_status": feed_status}), SOC
    )
    source = payload["sources"]["circl"]
    assert set(source) == ({"status", "feed_status"} if is_included else {"status"})
    assert (source.get("feed_status") == "unavailable") is is_included


@pytest.mark.parametrize("role", [INCIDENT_RESPONDER, THREAT_HUNTER, ADMIN])
def test_detailed_role_source_payload_remains_unchanged(role):
    error_value = r"HTTP 401 <script>x</script> C:\secret\key"
    job = _report_job({
        "status": "⚠",
        "score": 0,
        "error": error_value,
        "feed_status": "unavailable",
    })

    payload = serialize_report_payload(job, role)

    assert json.dumps(payload, ensure_ascii=False, separators=(",", ":")) == (
        '{"sources":{"circl":{"status":"⚠","score":0,'
        '"error":"HTTP 401 <script>x</script> C:\\\\secret\\\\key",'
        '"feed_status":"unavailable"}}}'
    )
