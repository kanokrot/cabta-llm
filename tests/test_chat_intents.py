import pytest

from src.web.chat_intents import build_instant_reply, classify_intent


@pytest.mark.parametrize(
    ("text", "intent"),
    [
        ("hello", "greeting"),
        ("hi", "greeting"),
        ("hey", "greeting"),
        ("good morning", "greeting"),
        ("good afternoon", "greeting"),
        ("good evening", "greeting"),
        ("สวัสดี", "greeting"),
        ("สวัสดีครับ", "greeting"),
        ("สวัสดีค่ะ", "greeting"),
        ("หวัดดี", "greeting"),
        ("help", "help"),
        ("/help", "help"),
        ("?", "help"),
        ("menu", "help"),
        ("what can you do", "help"),
        ("what can you do?", "help"),
        ("how do i use this", "help"),
        ("ช่วยอะไรได้บ้าง", "help"),
        ("ทำอะไรได้บ้าง", "help"),
        ("ใช้งานยังไง", "help"),
        ("วิธีใช้", "help"),
        ("  HeLLo!!!  ", "greeting"),
        ("\tWHAT   CAN YOU DO?? ", "help"),
        ("สวัสดีครับๆ", "greeting"),
    ],
)
def test_classifies_full_message_intents(text, intent):
    assert classify_intent(text) == intent


@pytest.mark.parametrize(
    "text",
    [
        "help me analyze 8.8.8.8",
        "hello 1.1.1.1",
        "analyze 8.8.8.8",
        "asdfghjkl",
        "investigate the ioc: evil.com",
        "h" * 41,
        "",
        "   ",
    ],
)
def test_does_not_classify_other_messages(text):
    assert classify_intent(text) is None


@pytest.mark.parametrize(
    ("intent", "text", "response"),
    [
        ("greeting", "hello", "How can I help you today?"),
        ("greeting", "สวัสดี", "มีอะไรให้ช่วยวันนี้ไหมครับ?"),
        ("help", "help", "I can help with these security tasks:"),
        ("help", "ช่วยอะไรได้บ้าง", "ผมช่วยงานด้านความปลอดภัยเหล่านี้ได้ครับ:"),
    ],
)
def test_reply_language_follows_input_language(intent, text, response):
    assert build_instant_reply(intent, text)["response"] == response


def test_instant_reply_shape_and_starter_action_prefixes():
    english = build_instant_reply("help", "help")
    thai = build_instant_reply("help", "ช่วยอะไรได้บ้าง")
    expected_prefixes = [
        "Investigate the IOC: ",
        "Analyze the malware file at: ",
        "Analyze the phishing email at: ",
        "Hunt for threats matching: ",
        "Triage the alert: ",
        "Generate detection rules for: ",
    ]

    assert english["type"] == "instant"
    assert english["intent"] == "help"
    assert english["session_id"] is None
    assert len(english["actions"]) == len(thai["actions"]) == 6
    assert [action["prefix"] for action in english["actions"]] == expected_prefixes
    assert [action["prefix"] for action in thai["actions"]] == expected_prefixes
    assert all(set(action) == {"label", "prefix", "description"} for action in english["actions"])
