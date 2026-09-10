import json
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.agent.agent_loop import (
    AgentLoop,
    _build_flow_b_rag_blocks,
    _validate_rag_reference,
)
from src.agent.agent_state import AgentState
from src.rag.rag_knowledge_base import load_playbooks_from_yaml


def _reference(**metadata_overrides):
    metadata = {
        "schema_version": "cabta-rag-provenance/1",
        "citation_id": "mitre_t1566_001",
        "knowledge_type": "attack_pattern",
        "source_name": "MITRE ATT&CK",
        "source_url": "https://attack.mitre.org/techniques/T1566/001/",
        "source_version": "ATT&CK v19.2",
        "confidence": 100,
        "tlp": "TLP:CLEAR",
        "created": "2026-08-09T05:07:48Z",
        "modified": "2026-09-10T17:15:26Z",
        "revoked": False,
    }
    metadata.update(metadata_overrides)
    return {
        "text": "Spearphishing attachments can deliver malware.",
        "metadata": metadata,
        "distance": 0.2,
    }


def _finding(reference):
    return {
        "type": "tool_result",
        "tool": "investigate_ioc",
        "result": {"verdict": "MALICIOUS", "rag_references": [reference]},
    }


def test_all_seed_entries_satisfy_flow_b_provenance_schema():
    documents = load_playbooks_from_yaml()

    assert len(documents) == 9
    for document in documents:
        valid, reason = _validate_rag_reference(document)
        assert valid, f"{document['id']}: {reason}"
        assert document["metadata"]["citation_id"] == document["id"]


def test_valid_provenance_is_rendered_with_stable_citation_id():
    context, sources = _build_flow_b_rag_blocks([_finding(_reference())])

    assert "[KB:mitre_t1566_001]" in context
    assert "Spearphishing attachments" in context
    assert "https://attack.mitre.org/techniques/T1566/001/" in sources


def test_missing_required_provenance_is_excluded(caplog):
    reference = _reference()
    del reference["metadata"]["source_url"]

    with caplog.at_level(logging.WARNING):
        context, sources = _build_flow_b_rag_blocks([_finding(reference)])

    assert context == ""
    assert sources == ""
    assert "invalid provenance" in caplog.text
    assert "source_url" in caplog.text


@pytest.mark.parametrize(
    "metadata_overrides, expected_reason",
    [
        ({"revoked": True}, "revoked"),
        ({"valid_until": "2020-01-01T00:00:00Z"}, "expired"),
    ],
)
def test_inactive_knowledge_is_excluded(
    metadata_overrides,
    expected_reason,
    caplog,
):
    with caplog.at_level(logging.WARNING):
        context, _ = _build_flow_b_rag_blocks(
            [_finding(_reference(**metadata_overrides))]
        )

    assert context == ""
    assert expected_reason in caplog.text


def test_nested_ioc_rag_references_are_found_in_email_tool_result():
    email_finding = {
        "type": "tool_result",
        "tool": "analyze_email",
        "result": {
            "verdict": "PHISHING",
            "ioc_analysis": {
                "results": [
                    {
                        "ioc": "evil.example",
                        "rag_references": [_reference()],
                    }
                ]
            },
        },
    }

    context, _ = _build_flow_b_rag_blocks([email_finding])

    assert "[KB:mitre_t1566_001]" in context


@pytest.mark.asyncio
async def test_think_injects_only_validated_rag_context():
    valid = _reference()
    invalid = _reference(citation_id="invalid_entry")
    del invalid["metadata"]["source_url"]
    invalid["text"] = "UNVALIDATED TEXT MUST NOT LEAK"
    state = AgentState(goal="Investigate phishing")
    state.findings = [_finding(valid), _finding(invalid)]

    loop = object.__new__(AgentLoop)
    loop.tools = MagicMock()
    loop.tools.get_tools_for_llm.return_value = []
    loop.tool_selector = MagicMock()
    loop.tool_selector.build_tools_block.return_value = ""
    loop.tool_selector.build_playbooks_block.return_value = ""
    loop.tool_selector.build_findings_block.side_effect = (
        lambda prompt_state: json.dumps(prompt_state.findings)
    )
    loop.tool_selector.filter_tools_for_goal.return_value = []
    loop._chat_with_tools = AsyncMock(
        return_value={"action": "final_answer", "answer": "done"}
    )

    await loop._think(state)

    messages = loop._chat_with_tools.await_args.args[0]
    prompt = messages[0]["content"]
    assert "Validated RAG context (Flow B only)" in prompt
    assert "[KB:mitre_t1566_001]" in prompt
    assert "UNVALIDATED TEXT MUST NOT LEAK" not in prompt
    assert '"rag_references"' not in prompt


@pytest.mark.asyncio
async def test_final_summary_appends_sources_deterministically():
    state = AgentState(goal="Investigate phishing")
    state.findings = [
        _finding(_reference()),
        {
            "type": "final_answer",
            "answer": "Confirmed phishing activity.",
            "verdict": "MALICIOUS",
        },
    ]
    loop = object.__new__(AgentLoop)

    summary = await loop._generate_summary(state)

    assert summary.startswith("[MALICIOUS] Confirmed phishing activity.")
    assert "Knowledge sources:" in summary
    assert "[KB:mitre_t1566_001]" in summary
