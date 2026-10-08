"""Greeting example chips stay fixed, localized, and role safe."""

import asyncio
from pathlib import Path

from src.web import chat_intents
from src.utils.ioc_extractor import IOCExtractor


class _GateLoop:
    async def _chat_with_tools(self, messages, tools):
        return '{"intent":"converse","reply":"LLM greeting"}'


def _reply(message, role="Threat Hunter"):
    return asyncio.run(chat_intents.route_chat_message(_GateLoop(), message, role=role))


def test_english_greeting_gets_fixed_english_examples():
    result = _reply("hello")

    assert result["intent"] == "converse"
    assert result["examples"] == [
        "Investigate 8.8.8.8",
        "Analyze this suspicious domain: evil.com",
        "Hunt for threats matching: 8.8.8.8",
        "Triage the alert: repeated failed logins from 8.8.8.8",
    ]
    assert result["response"].endswith("How can I help?")
    assert IOCExtractor.extract_all("8.8.8.8")["all_iocs"] == ["8.8.8.8"]
    assert IOCExtractor.extract_all("evil.com")["all_iocs"] == ["evil.com"]


def test_thai_help_gets_fixed_thai_examples():
    result = _reply("ช่วยอะไรได้บ้าง")

    assert result["examples"] == [
        "ตรวจสอบ IOC: 8.8.8.8",
        "ตรวจสอบโดเมนที่น่าสงสัย: evil.com",
        "ค้นหาภัยคุกคามที่เกี่ยวข้องกับ: 8.8.8.8",
        "คัดกรองการแจ้งเตือน: พบการเข้าสู่ระบบล้มเหลวซ้ำจาก 8.8.8.8",
    ]
    assert result["response"].endswith("ช่วยอะไรได้บ้าง")


def test_llm_unavailable_greeting_still_gets_examples(monkeypatch):
    async def unavailable(*_args, **_kwargs):
        return None

    monkeypatch.setattr(chat_intents, "gate_chat_intent", unavailable)
    result = asyncio.run(
        chat_intents.route_chat_message(None, "hi", role="Threat Hunter")
    )

    assert result["examples"]
    assert result["actions"] == []
    assert result["response"].endswith("How can I help?")


def test_investigation_intent_does_not_get_examples():
    async def investigate(_agent_loop, _message, _history=None, role=None):
        return {"intent": "investigate", "reply": ""}

    original = chat_intents.gate_chat_intent
    chat_intents.gate_chat_intent = investigate
    try:
        result = asyncio.run(
            chat_intents.route_chat_message(_GateLoop(), "Investigate 8.8.8.8", role="Threat Hunter")
        )
    finally:
        chat_intents.gate_chat_intent = original

    assert result is None


def test_incident_responder_and_unknown_role_get_no_investigative_examples():
    assert _reply("hello", role="Incident Responder")["examples"] == []
    assert _reply("hello", role=None)["examples"] == []


def test_instant_reply_chips_only_prefill_and_use_text_nodes():
    template = (Path(__file__).parents[1] / "templates" / "agent_chat.html").read_text(encoding="utf-8")
    start = template.index("function renderInstantReply(data, btn)")
    end = template.index("function parseApiResponse", start)
    renderer = template[start:end]

    assert "button.textContent = example" in renderer
    assert "quickAction(example)" in renderer
    assert "send(" not in renderer
    assert "innerHTML" not in renderer


def test_investigate_classification_contract_is_unchanged():
    assert chat_intents.classify_intent("Investigate 8.8.8.8") is None
    assert chat_intents.classify_intent("hello") == "greeting"
