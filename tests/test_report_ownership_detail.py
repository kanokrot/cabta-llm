from src.web.visibility import ADMIN, INCIDENT_RESPONDER, SOC, serialize_report_job


def _job(user_id=42):
    return {
        "id": "report-job",
        "analysis_type": "file",
        "status": "completed",
        "progress": 100,
        "verdict": "MALICIOUS",
        "score": 85,
        "user_id": user_id,
        "params": {"filename": "sample.exe"},
        "result": {
            "hashes": {"sha256": "abc123"},
            "file_info": {"filename": "sample.exe"},
            "scoring": {"static": 40},
            "capabilities": [{"type": "execution", "summary": "runs"}],
            "detection_rules": {"sigma": "rule"},
        },
    }


def _assert_detailed_fields(report):
    result = report["result"]
    for field in ("hashes", "file_info", "scoring", "capabilities"):
        assert field in result


def _assert_reduced_fields(report):
    result = report["result"]
    for field in ("hashes", "file_info", "scoring", "capabilities"):
        assert field not in result


def test_owner_soc_analyst_sees_detailed_own_report():
    report = serialize_report_job(
        _job(user_id=42),
        role=SOC,
        viewer_user_id=42,
    )

    _assert_detailed_fields(report)


def test_non_owner_soc_analyst_sees_reduced_report():
    report = serialize_report_job(
        _job(user_id=42),
        role=SOC,
        viewer_user_id=99,
    )

    _assert_reduced_fields(report)


def test_incident_responder_sees_detailed_regardless_of_ownership():
    report = serialize_report_job(
        _job(user_id=42),
        role=INCIDENT_RESPONDER,
        viewer_user_id=99,
    )

    _assert_detailed_fields(report)


def test_no_viewer_user_id_falls_back_to_role_only():
    soc_report = serialize_report_job(_job(user_id=42), role=SOC)
    admin_report = serialize_report_job(_job(user_id=42), role=ADMIN)

    _assert_reduced_fields(soc_report)
    _assert_detailed_fields(admin_report)
