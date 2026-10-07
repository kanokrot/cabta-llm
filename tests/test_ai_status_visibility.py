import pytest

from src.web.visibility import (
    ADMIN,
    INCIDENT_RESPONDER,
    SOC,
    THREAT_HUNTER,
    serialize_report_job,
)


def _report(result, *, role=ADMIN, viewer_user_id=None, owner_id=None):
    job = {
        "id": "job-1",
        "analysis_type": "ioc",
        "params": {"value": "example.com", "ioc_type": "domain"},
        "result": result,
    }
    if owner_id is not None:
        job["user_id"] = owner_id
    return serialize_report_job(
        job,
        role=role,
        viewer_user_id=viewer_user_id,
    )["result"]


def _ai_keys(result):
    return {key for key in result if key.startswith("ai_")}


@pytest.mark.parametrize("status", ["disabled", "complete", "failed"])
def test_valid_ai_status_values_are_forwarded(status):
    result = _report({"ai_status": status})

    assert result["ai_status"] == status
    assert _ai_keys(result) == {"ai_status"}


@pytest.mark.parametrize("status", ["running", None, 5, "FAILED"])
def test_invalid_ai_status_values_are_dropped(status):
    result = _report({"ai_status": status})

    assert "ai_status" not in result
    assert _ai_keys(result) == set()


def test_ai_error_collapses_whitespace_strips_controls_and_truncates():
    message = "  first\nsecond\tpart\x00 " + ("x" * 400)
    result = _report({"ai_status": "failed", "ai_error": message})

    assert result["ai_error"] == "first second part " + ("x" * 282)
    assert len(result["ai_error"]) == 300
    assert not any(
        ord(character) < 32 or 127 <= ord(character) <= 159
        for character in result["ai_error"]
    )
    assert _ai_keys(result) == {"ai_status", "ai_error"}


def test_non_string_ai_error_is_dropped():
    result = _report({"ai_status": "failed", "ai_error": {"message": "error"}})

    assert result["ai_status"] == "failed"
    assert "ai_error" not in result
    assert _ai_keys(result) == {"ai_status"}


def test_empty_ai_error_is_dropped():
    result = _report({"ai_status": "failed", "ai_error": "   \n\t "})

    assert result["ai_status"] == "failed"
    assert "ai_error" not in result
    assert _ai_keys(result) == {"ai_status"}

def test_error_only_llm_analysis_keeps_ai_fields_but_omits_llm_details():
    result = _report(
        {
            "llm_analysis": {"error": "x"},
            "ai_status": "failed",
            "ai_error": "provider unavailable",
        }
    )

    assert result["ai_status"] == "failed"
    assert result["ai_error"] == "provider unavailable"
    assert "llm_analysis" not in result
    assert _ai_keys(result) == {"ai_status", "ai_error"}


def test_legacy_results_do_not_receive_ai_defaults():
    result = _report({"llm_analysis": {"note": "legacy note"}})

    assert "ai_status" not in result
    assert "ai_error" not in result
    assert "llm_analysis" not in result
    assert _ai_keys(result) == set()


def test_non_detailed_report_viewer_sees_status_but_not_error():
    result = _report(
        {"ai_status": "failed", "ai_error": "provider unavailable"},
        role=SOC,
    )

    assert result["ai_status"] == "failed"
    assert "ai_error" not in result
    assert _ai_keys(result) == {"ai_status"}


@pytest.mark.parametrize("role", [INCIDENT_RESPONDER, THREAT_HUNTER, ADMIN])
def test_detailed_report_roles_see_status_and_error(role):
    result = _report(
        {"ai_status": "failed", "ai_error": "provider unavailable"},
        role=role,
    )

    assert result["ai_status"] == "failed"
    assert result["ai_error"] == "provider unavailable"
    assert _ai_keys(result) == {"ai_status", "ai_error"}


def test_report_owner_sees_status_and_error():
    result = _report(
        {"ai_status": "failed", "ai_error": "provider unavailable"},
        role=SOC,
        viewer_user_id=123,
        owner_id=123,
    )

    assert result["ai_status"] == "failed"
    assert result["ai_error"] == "provider unavailable"
    assert _ai_keys(result) == {"ai_status", "ai_error"}
