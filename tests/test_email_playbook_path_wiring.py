"""Offline regression tests for email playbook result paths."""

import re
from unittest.mock import AsyncMock, MagicMock
import json

import pytest

from src.agent.agent_store import AgentStore
from src.agent.playbook_engine import PlaybookEngine, _resolve_var
from src.utils.ioc_extractor import IOCExtractor


EMAIL_TEXT = (
    "Review https://evilcorp.biz/login and evilcorp.biz from "
    "8.8.8.8. Contact analyst@evilcorp.biz. SHA256 "
    "44d88612fea8a8f36de82e1278abb02f8e3f4a3b5a9b20d3a3f8c5a6d7e8f901."
)
ATTACHMENT = {
    "filename": "invoice.docx",
    "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "size": 24,
}
ATTACHMENT_RESULT = {
    "filename": ATTACHMENT["filename"],
    "verdict": "CLEAN",
    "hashes": {
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "sha256": "44d88612fea8a8f36de82e1278abb02f8e3f4a3b5a9b20d3a3f8c5a6d7e8f901",
    },
    "file_info": {"name": ATTACHMENT["filename"], "size": ATTACHMENT["size"]},
}


def _engine(store=None):
    agent_loop = MagicMock()
    agent_loop.config = {}
    return PlaybookEngine(agent_loop=agent_loop, agent_store=store or MagicMock())


def test_email_playbook_fixed_paths_resolve_to_real_fields():
    engine = _engine()
    expected_iocs = IOCExtractor.extract_all(EMAIL_TEXT)
    context = {
        "parse_email": {
            "email_data": {
                "from_domain": "evilcorp.biz",
                "body_text": EMAIL_TEXT,
                "attachments": [ATTACHMENT],
            },
            "attachment_analysis": {
                "total_attachments": 1,
                "malicious_attachments": 0,
                "suspicious_attachments": 0,
                "results": [ATTACHMENT_RESULT],
            },
        },
        "extract_email_iocs": {"iocs": expected_iocs},
        "extract_iocs": {"iocs": expected_iocs},
    }

    for playbook_id, extractor_step in (
        ("email_investigation", "extract_email_iocs"),
        ("phishing_investigation", "extract_iocs"),
    ):
        playbook = engine.get_playbook(playbook_id)
        assert playbook is not None, f"{playbook_id}.yaml was not loaded"

        checked = set()
        for step in playbook["steps"]:
            name = step["name"]
            for_each = step.get("for_each")
            if isinstance(for_each, str) and for_each.startswith(
                ("parse_email.attachment_analysis.", f"{extractor_step}.iocs.")
            ):
                value = _resolve_var(for_each, context)
                assert isinstance(value, list) and value, (
                    f"{playbook_id}.{name}: {for_each} resolved to {value!r}"
                )
                checked.add(name)

            condition = step.get("condition") or {}
            condition_text = condition.get("if", "") if isinstance(condition, dict) else condition
            for path in re.findall(r"\{\{\s*([^{}]+?)\s*\}\}", condition_text):
                if path.startswith(("parse_email.attachment_analysis.", f"{extractor_step}.iocs.")):
                    condition_context = {**context, "item": ATTACHMENT_RESULT}
                    value = _resolve_var(path, condition_context)
                    assert value is not None, (
                        f"{playbook_id}.{name}: condition path {path} resolved to None"
                    )
                    if path.startswith(f"{extractor_step}.iocs."):
                        assert isinstance(value, list) and value, (
                            f"{playbook_id}.{name}: condition path {path} is empty or not a list"
                        )
                    checked.add(name)

            params = step.get("params") or {}
            for value in params.values():
                if value == "{{parse_email.email_data.from_domain}}":
                    assert _resolve_var("parse_email.email_data.from_domain", context), (
                        f"{playbook_id}.{name}: sender domain parameter is empty"
                    )
                    checked.add(name)
                elif value == "{{parse_email.email_data.body_text}}":
                    assert _resolve_var("parse_email.email_data.body_text", context), (
                        f"{playbook_id}.{name}: body text parameter is empty"
                    )
                    checked.add(name)
                elif value == "{{item.hashes.sha256}}":
                    resolved_hash = _resolve_var("item.hashes.sha256", {"item": ATTACHMENT_RESULT})
                    assert resolved_hash, f"{playbook_id}.{name}: attachment hash parameter is empty"
                    checked.add(name)

            serialized_step = json.dumps(step)
            assert "{{item.path}}" not in serialized_step, (
                f"{playbook_id}.{name}: references unavailable item.path"
            )
            assert "{{item.sha256}}" not in serialized_step, (
                f"{playbook_id}.{name}: references unavailable item.sha256"
            )

        assert checked, f"{playbook_id}: no fixed paths were checked"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "playbook_id,input_name,expected_final_fragment",
    [
        ("email_investigation", "eml_path", "Email investigation report:"),
        ("phishing_investigation", "email_path", "Phishing analysis report:"),
    ],
)
async def test_one_attached_email_uses_analyzer_hash_and_reaches_final(
    tmp_path, playbook_id, input_name, expected_final_fragment
):
    store = AgentStore(str(tmp_path / f"{playbook_id}.db"))
    agent_loop = MagicMock()
    agent_loop.config = {}
    calls = []

    async def run_tool(tool_name, params, **kwargs):
        calls.append((tool_name, dict(params)))
        if tool_name == "analyze_email":
            return {
                "email_data": {
                    "from": "analyst@evilcorp.biz",
                    "from_domain": "evilcorp.biz",
                    "body_text": EMAIL_TEXT,
                    "attachments": [ATTACHMENT],
                },
                "attachment_analysis": {
                    "total_attachments": 1,
                    "malicious_attachments": 0,
                    "suspicious_attachments": 0,
                    "results": [ATTACHMENT_RESULT],
                },
            }
        if tool_name == "extract_iocs":
            return {"iocs": IOCExtractor.extract_all(params["text"])}
        if tool_name.endswith("email_security_check"):
            return {"score": "3/3", "spf": "pass", "dkim": "pass", "dmarc": "pass"}
        return {"malicious": False, "suspicious": False, "found": False, "blocklisted": False}

    agent_loop.run_tool = AsyncMock(side_effect=run_tool)
    agent_loop._notify = MagicMock()
    engine = PlaybookEngine(agent_loop=agent_loop, agent_store=store)

    session_id = await engine.execute(playbook_id, {input_name: "offline-message.eml"})
    session = store.get_session(session_id)
    steps = store.get_steps(session_id)

    assert session["status"] == "completed"
    assert any(
        step["step_type"] == "final_answer" and expected_final_fragment in step["content"]
        for step in steps
    ), f"{playbook_id} did not reach its final-answer step"
    hash_calls = [
        params for tool, params in calls
        if tool == "mcp:threat_intel_tools/malwarebazaar_hash_lookup"
    ]
    assert len(hash_calls) == 1, f"{playbook_id} did not check the analyzer's attachment hash"
    assert hash_calls[0]["hash_value"] == ATTACHMENT_RESULT["hashes"]["sha256"]


@pytest.mark.asyncio
async def test_malicious_alert_triage_does_not_run_low_priority_document(tmp_path):
    class ParentOnlyEngine(PlaybookEngine):
        async def _execute_session(self, session_id, playbook_id, *args, **kwargs):
            if playbook_id == "incident_response":
                return session_id
            return await super()._execute_session(session_id, playbook_id, *args, **kwargs)

    store = AgentStore(str(tmp_path / "agent.db"))
    added_steps = []
    add_step = store.add_step

    def record_step(**kwargs):
        added_steps.append(kwargs)
        return add_step(**kwargs)

    store.add_step = record_step
    agent_loop = MagicMock()
    agent_loop.config = {}

    async def run_tool(tool_name, params, **kwargs):
        if tool_name == "extract_iocs":
            return {"iocs": IOCExtractor.extract_all(params["text"])}
        return {"malicious": True}

    agent_loop.run_tool = AsyncMock(side_effect=run_tool)
    agent_loop._notify = MagicMock()
    engine = ParentOnlyEngine(agent_loop=agent_loop, agent_store=store)

    await engine.execute(
        "alert_triage",
        {"alert_text": EMAIL_TEXT, "alert_source": "offline-test"},
    )

    contents = [step.get("content", "") for step in added_steps]
    assert any("Triggering playbook: incident_response" in content for content in contents), (
        "malicious alert did not trigger Incident Response"
    )
    assert not any("Alert triage report:" in content for content in contents), (
        "low_priority_document ran after high_priority_response"
    )
