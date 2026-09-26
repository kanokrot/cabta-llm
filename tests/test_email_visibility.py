import pytest

from src.web.visibility import (
    ADMIN,
    INCIDENT_RESPONDER,
    SOC,
    TEAM_LEAD,
    THREAT_HUNTER,
    serialize_analysis_job,
)


EMAIL_FIELDS = {
    "email_data",
    "composite_score",
    "base_phishing_score",
    "forensics",
    "advanced_analysis",
    "detection_rules",
    "llm_analysis",
    "iocs_found",
}


def _email_job(**result_overrides):
    result = {
        "email_data": {
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
            "urls": ["https://example.test"],
            "ips": ["192.0.2.10"],
            "domains": ["example.test"],
            "from": "sender@example.test",
            "to": "recipient@example.test",
            "subject": "Test subject",
            "date": "2026-09-26T00:00:00Z",
            "reply_to": "reply@example.test",
            "attachments": [
                {
                    "filename": "report.pdf",
                    "content_type": "application/pdf",
                    "size": 1234,
                }
            ],
        },
        "composite_score": 88,
        "base_phishing_score": 71,
        "forensics": {"authentication": {"spf": "pass"}},
        "advanced_analysis": {"risk_factors": ["suspicious_link"]},
        "detection_rules": {"sigma": "rule-id"},
        "llm_analysis": {"verdict": "phishing", "summary": "Suspicious"},
        "iocs_found": {"urls": ["https://example.test"]},
    }
    result.update(result_overrides)
    return {
        "id": "email-job-1",
        "analysis_type": "email",
        "status": "completed",
        "progress": 100,
        "verdict": "PHISHING",
        "score": 88,
        "result": result,
    }


def test_soc_analyst_sees_no_new_email_fields():
    output = serialize_analysis_job(_email_job(), role=SOC)
    assert EMAIL_FIELDS.isdisjoint(output)
    assert output["verdict"] == "PHISHING"
    assert output["score"] == 88


def test_team_lead_sees_no_new_email_fields():
    output = serialize_analysis_job(_email_job(), role=TEAM_LEAD)
    assert EMAIL_FIELDS.isdisjoint(output)
    assert output["verdict"] == "PHISHING"
    assert output["score"] == 88


def _assert_full_email_fields(output):
    assert EMAIL_FIELDS.issubset(output)
    assert output["email_data"]["spf"] == "pass"
    assert output["email_data"]["attachments"] == [
        {
            "filename": "report.pdf",
            "content_type": "application/pdf",
            "size": 1234,
        }
    ]
    assert output["email_data"]["urls"] == ["https://example.test"]
    assert output["composite_score"] == 88
    assert output["base_phishing_score"] == 71
    assert output["forensics"]["authentication"]["spf"] == "pass"
    assert output["advanced_analysis"]["risk_factors"] == ["suspicious_link"]
    assert output["detection_rules"]["sigma"] == "rule-id"
    assert output["llm_analysis"]["verdict"] == "phishing"
    assert output["iocs_found"]["urls"] == ["https://example.test"]


def test_incident_responder_sees_full_email_fields():
    _assert_full_email_fields(
        serialize_analysis_job(_email_job(), role=INCIDENT_RESPONDER)
    )


@pytest.mark.parametrize("role", [THREAT_HUNTER, ADMIN])
def test_threat_hunter_and_admin_see_full_email_fields(role):
    _assert_full_email_fields(serialize_analysis_job(_email_job(), role=role))


def test_body_text_and_body_html_never_exposed():
    output = serialize_analysis_job(
        _email_job(
            email_data={
                "body_text": "SECRET_BODY_TEXT",
                "body_html": "SECRET_BODY_HTML",
                "subject": "safe",
            }
        ),
        role=ADMIN,
    )
    serialized = repr(output)
    assert "body_text" not in serialized
    assert "body_html" not in serialized
    assert "SECRET_BODY_TEXT" not in serialized
    assert "SECRET_BODY_HTML" not in serialized


def test_raw_output_never_exposed():
    output = serialize_analysis_job(
        _email_job(raw_output={"secret": "SECRET_RAW_OUTPUT"}),
        role=ADMIN,
    )
    serialized = repr(output)
    assert "raw_output" not in serialized
    assert "SECRET_RAW_OUTPUT" not in serialized


def test_attachment_metadata_only_no_binary_content():
    output = serialize_analysis_job(
        _email_job(
            email_data={
                "attachments": [
                    {
                        "filename": "payload.bin",
                        "content_type": "application/octet-stream",
                        "size": 42,
                        "content": "FAKE_BASE64_CONTENT",
                        "data": "FAKE_DATA",
                        "base64": "FAKE_BASE64",
                        "provider_payload": "FAKE_PROVIDER_PAYLOAD",
                    }
                ]
            }
        ),
        role=ADMIN,
    )
    assert output["email_data"]["attachments"] == [
        {
            "filename": "payload.bin",
            "content_type": "application/octet-stream",
            "size": 42,
        }
    ]
    serialized = repr(output)
    assert "FAKE_BASE64_CONTENT" not in serialized
    assert "FAKE_DATA" not in serialized
    assert "FAKE_BASE64" not in serialized
    assert "FAKE_PROVIDER_PAYLOAD" not in serialized


def test_file_branch_unaffected():
    file_job = {
        "id": "file-job-1",
        "analysis_type": "file",
        "status": "completed",
        "progress": 100,
        "current_step": "done",
        "verdict": "CLEAN",
        "score": 0,
        "created_at": "2026-09-26T00:00:00Z",
        "completed_at": "2026-09-26T00:01:00Z",
        "params": {
            "filename": "sample.exe",
            "sha256": "a" * 64,
            "size": 42,
        },
        "result": {
            "summary": "No threat found",
            "confidence": 0.9,
            "entropy_analysis": {"entropy": 2.1},
            "static_analysis": {"file_type": "PE"},
            "capabilities": ["network"],
            "detection_rules": {"sigma": "rule-id"},
        },
    }
    assert serialize_analysis_job(file_job, role=SOC) == {
        "id": "file-job-1",
        "analysis_type": "file",
        "status": "completed",
        "progress": 100,
        "current_step": "done",
        "verdict": "CLEAN",
        "score": 0,
        "created_at": "2026-09-26T00:00:00Z",
        "completed_at": "2026-09-26T00:01:00Z",
        "filename": "sample.exe",
        "sha256": "a" * 64,
        "size": 42,
        "summary": "No threat found",
        "confidence": 0.9,
        "entropy_analysis": {"entropy": 2.1},
        "static_analysis": {"file_type": "PE"},
        "capabilities": ["network"],
        "detection_rules": {"sigma": "rule-id"},
    }


@pytest.mark.parametrize("role", [SOC, TEAM_LEAD, INCIDENT_RESPONDER, THREAT_HUNTER, ADMIN])
def test_verdict_and_score_preserved_for_email_regardless_of_role(role):
    output = serialize_analysis_job(_email_job(), role=role)
    assert output["verdict"] == "PHISHING"
    assert output["score"] == 88


def test_email_headers_exposed_for_detailed_roles():
    header_analysis = {
        "received_chain": ["192.0.2.10"],
        "originating_ip": "198.51.100.10",
        "message_id": "<message@example.test>",
        "return_path": "sender@example.test",
        "from_address": "Sender <sender@example.test>",
        "anomalies": ["Message-ID domain mismatch"],
    }
    output = serialize_analysis_job(
        _email_job(advanced_analysis={"header_analysis": header_analysis}),
        role=INCIDENT_RESPONDER,
    )

    assert output["email_data"]["headers"] == header_analysis


def test_email_headers_absent_for_non_detailed_role():
    header_analysis = {
        "received_chain": ["192.0.2.10"],
        "originating_ip": "198.51.100.10",
        "message_id": "<message@example.test>",
        "return_path": "sender@example.test",
        "from_address": "Sender <sender@example.test>",
        "anomalies": ["Message-ID domain mismatch"],
    }
    output = serialize_analysis_job(
        _email_job(advanced_analysis={"header_analysis": header_analysis}),
        role=SOC,
    )

    assert "headers" not in output.get("email_data", {})
    assert "email_data" not in output


def test_email_headers_missing_advanced_analysis_no_crash():
    output = serialize_analysis_job(
        _email_job(advanced_analysis=None),
        role=INCIDENT_RESPONDER,
    )

    assert "headers" not in output["email_data"]
