"""Coverage for additive report-envelope persistence in Flow C."""

import pytest

from src.agent.agent_store import AgentStore
from src.agent.playbook_engine import PlaybookEngine, _scan_report_components


NATIVE_IOC_RESULT = {
    "ioc": "198.51.100.7",
    "ioc_type": "ip",
    "threat_score": 91,
    "verdict": "MALICIOUS",
    "sources": {"mock_intel": {"detections": "8/70"}},
}


class _MockPlaybookAgentLoop:
    def __init__(
        self, malware_result=None, investigation_result=None,
        forensic_malicious=False, email_malicious=False,
    ):
        self.config = {}
        self.malware_result = malware_result or {
            "composite_score": 0,
            "file_type": "exe",
            "hashes": {"sha256": "a" * 64},
            "string_analysis": {"suspicious_strings": ""},
        }
        self.investigation_result = investigation_result or NATIVE_IOC_RESULT
        self.forensic_malicious = forensic_malicious
        self.email_malicious = email_malicious

    async def run_tool(self, tool_name, params):
        tool = tool_name.rsplit("/", 1)[-1]
        if tool == "extract_iocs":
            return {
                "iocs": {
                    "ips": [],
                    "domains": [],
                    "urls": [],
                    "sha256": ["a" * 64],
                },
                "total": 0,
                "ips": [],
                "urls": [],
            }
        if tool == "generate_rules":
            return {"rules": {"sigma": ["rule: mock"]}}
        if tool == "email_security_check" and self.email_malicious:
            return {"score": "1/3"}
        if tool == "mitre_attack_mapper":
            return {
                "capabilities": [],
                "mitre_attacks": [{"id": "T1059", "technique": "Command Shell"}],
            }
        if tool == "malwarebazaar_hash_lookup" and self.forensic_malicious:
            return {"malicious": True}
        if tool == "analyze_malware":
            return self.malware_result
        if tool == "investigate_ioc":
            return self.investigation_result
        return {"ok": True}

    def _notify(self, session_id, payload):
        pass


def _engine(tmp_path, **kwargs):
    store = AgentStore(str(tmp_path / "envelope.db"))
    engine = PlaybookEngine(_MockPlaybookAgentLoop(**kwargs), store)
    # Several malware_analysis conditional tool gates point their true branch
    # back to themselves.  Keep this test fixture finite while exercising the
    # built-in playbook's tool/result flow; the YAML source remains untouched.
    for step in engine._cache["malware_analysis"]["_parsed_steps"]:
        if step.condition and step.tool:
            step.on_success = None
    return engine, store


async def _execute_and_approve(engine, store, playbook_id, input_data):
    session_id = await engine.execute(playbook_id, input_data)
    for _ in range(20):
        session = store.get_session(session_id)
        if session["status"] != "waiting_approval":
            return session_id, session
        await engine.execute_from_step(session_id, approved=True, approved_by="test")
    raise AssertionError("playbook did not finish after approval checkpoints")


BUILTIN_CASES = [
    ("alert_triage", {"alert_text": "Suspicious connection", "alert_source": "mock"},
     {"extracted_iocs", "final_answer"}),
    ("email_investigation", {"eml_path": "mock.eml"},
     {"extracted_iocs", "final_answer"}),
    ("exploit_reversing", {"sample_path": "mock.bin"},
     {"extracted_iocs", "generated_rules", "final_answer"}),
    ("forensic_triage", {
        "host_identifier": "host-1", "remote_username": "analyst",
        "remote_key_path": "mock-key",
    }, {"extracted_iocs", "mitre_findings", "final_answer"}),
    ("incident_response", {"incident_description": "Suspicious activity"},
     {"extracted_iocs", "generated_rules", "final_answer"}),
    ("malware_deep_dive", {
        "file_path": "mock.bin", "analysis_context": {"file_type": "exe"},
    }, {"generated_rules", "extracted_iocs", "final_answer"}),
    ("phishing_investigation", {"email_path": "mock.eml"},
     {"extracted_iocs", "final_answer"}),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("playbook_id,input_data,expected_fields", BUILTIN_CASES)
async def test_broken_playbooks_persist_expected_report_envelope(
    tmp_path, playbook_id, input_data, expected_fields
):
    engine, store = _engine(tmp_path)
    _, session = await _execute_and_approve(engine, store, playbook_id, input_data)

    assert session["status"] == "completed"
    envelope = session["metadata"]["report_envelope"]
    assert {key for key, value in envelope.items() if value is not None} - {"report_type"} == expected_fields
    assert session["metadata"].get("ioc_investigation_result") is None


@pytest.mark.asyncio
async def test_malware_analysis_zero_ioc_branch_has_final_answer(tmp_path):
    engine, store = _engine(tmp_path)
    _, session = await _execute_and_approve(
        engine, store, "malware_analysis", {"file_path": "clean.bin"}
    )

    assert session["status"] == "completed"
    envelope = session["metadata"]["report_envelope"]
    assert envelope["ioc_investigation"] is None
    assert envelope["final_answer"] is not None


@pytest.mark.asyncio
async def test_malware_analysis_positive_ioc_is_legacy_and_enveloped(tmp_path):
    engine, store = _engine(
        tmp_path,
        malware_result={
            "composite_score": 0,
            "file_type": "exe",
            "hashes": {"sha256": "a" * 64},
            "string_analysis": {"suspicious_strings": ""},
        },
        investigation_result=NATIVE_IOC_RESULT,
    )
    # The built-in positive-IOC edge points back to investigate_all_iocs. Keep
    # the test focused on persistence by allowing that successful call to fall
    # through to the next declared step.
    for step in engine._cache["malware_analysis"]["_parsed_steps"]:
        if step.name == "investigate_all_iocs":
            step.on_success = None

    original_extract = engine.agent_loop.run_tool

    async def positive_extract(tool_name, params):
        result = await original_extract(tool_name, params)
        if tool_name == "extract_iocs":
            result["total"] = 1
            result["sha256"] = ["a" * 64]
        return result

    engine.agent_loop.run_tool = positive_extract
    _, session = await _execute_and_approve(
        engine, store, "malware_analysis", {"file_path": "positive.bin"}
    )

    assert session["status"] == "completed"
    metadata = session["metadata"]
    assert metadata["ioc_investigation_result"] == NATIVE_IOC_RESULT
    assert metadata["report_envelope"]["ioc_investigation"] == NATIVE_IOC_RESULT


@pytest.mark.asyncio
async def test_forensic_triage_confirm_incident_classifies_tool_result(tmp_path):
    engine, store = _engine(tmp_path, forensic_malicious=True)
    session_id, session = await _execute_and_approve(
        engine,
        store,
        "forensic_triage",
        {
            "host_identifier": "host-1",
            "remote_username": "analyst",
            "remote_key_path": "mock-key",
            "suspicious_file_path": "mock.bin",
        },
    )

    assert session["status"] == "completed"
    envelope = session["metadata"]["report_envelope"]
    # Branch-exclusivity and malicious-narrative fix reference:
    # fix(forensic_triage): add on_success/on_failure to confirm_incident and
    # document_malicious_incident (2026-09-11; commit pending Lol review;
    # no commit created in this run).
    assert envelope["generated_rules"] == {"rules": {"sigma": ["rule: mock"]}}
    assert envelope["final_answer"] is not None
    assert envelope["extracted_iocs"] is not None
    assert envelope["mitre_findings"] is not None
    final_answer_steps = [
        step for step in store.get_steps(session_id)
        if step.get("step_type") == "final_answer"
    ]
    assert len(final_answer_steps) == 1
    assert "Malicious incident confirmed" in final_answer_steps[0]["content"]


MALICIOUS_BRANCH_CASES = [
    (
        "forensic_triage",
        {"host_identifier": "host-1", "remote_username": "analyst", "remote_key_path": "mock-key", "suspicious_file_path": "mock.bin"},
        {"forensic_malicious": True},
        "confirm_incident",
        "document_malicious_incident",
        "document_benign",
    ),
    (
        "phishing_investigation",
        {"email_path": "mock.eml"},
        {"email_malicious": True},
        "confirm_phishing",
        "document_confirmed_phishing",
        "document_benign",
    ),
    (
        "email_investigation",
        {"eml_path": "mock.eml"},
        {"email_malicious": True},
        "confirm_malicious_email",
        "document_malicious_email",
        "document_clean_email",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "playbook_id,input_data,loop_kwargs,malicious_step,final_step,clean_step",
    MALICIOUS_BRANCH_CASES,
)
async def test_malicious_branch_excludes_clean_branch(
    tmp_path,
    monkeypatch,
    playbook_id,
    input_data,
    loop_kwargs,
    malicious_step,
    final_step,
    clean_step,
):
    import src.agent.playbook_engine as playbook_engine_module

    captured_context = {}
    original_scan = playbook_engine_module._scan_report_components

    def capture_context(context, step_names=None):
        captured_context.update(context)
        return original_scan(context, step_names)

    monkeypatch.setattr(
        playbook_engine_module,
        "_scan_report_components",
        capture_context,
    )
    engine, store = _engine(tmp_path, **loop_kwargs)
    session_id, session = await _execute_and_approve(engine, store, playbook_id, input_data)

    assert session["status"] == "completed"
    assert captured_context[malicious_step]
    assert captured_context[final_step]
    assert clean_step not in captured_context
    assert any(
        step.get("step_type") == "final_answer"
        for step in store.get_steps(session_id)
    )


@pytest.mark.asyncio
async def test_ioc_triage_legacy_result_is_unchanged_and_additive(tmp_path):
    engine, store = _engine(tmp_path)
    _, session = await _execute_and_approve(
        engine, store, "ioc_triage", {"ioc": "198.51.100.7", "ioc_type": "ip"}
    )

    metadata = session["metadata"]
    assert metadata["ioc_investigation_result"] == NATIVE_IOC_RESULT
    assert metadata["report_envelope"]["ioc_investigation"] == NATIVE_IOC_RESULT


@pytest.mark.asyncio
async def test_no_report_components_persist_no_report_metadata(tmp_path):
    engine, store = _engine(tmp_path)
    playbook_id = engine.register_playbook(
        "no report terminal", "test", [{"name": "ordinary", "tool": "mock_tool"}]
    )
    _, session = await _execute_and_approve(engine, store, playbook_id, {})

    assert session["status"] == "completed"
    assert "ioc_investigation_result" not in session["metadata"]
    assert "report_envelope" not in session["metadata"]


def test_report_component_precedence_for_rules_and_iocs():
    early_rules = {"rules": {"sigma": ["early"]}}
    final_rules = {"rules": {"sigma": ["final"]}}
    early_iocs = {"iocs": {"ips": ["192.0.2.1"]}}
    final_iocs = {"iocs": {"ips": ["192.0.2.2"]}}
    components = _scan_report_components({
        "early_rules": early_rules,
        "early_iocs": early_iocs,
        "final_rules": final_rules,
        "final_ioc_extraction": final_iocs,
        "early_rules_rules": early_rules["rules"],
        "last_result": final_iocs,
    })

    assert components["generated_rules"] == {"rules": {"sigma": ["final"]}}
    assert components["extracted_iocs"] == {"iocs": {"ips": ["192.0.2.2"]}}
