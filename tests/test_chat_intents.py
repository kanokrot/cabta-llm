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
        ("hello there", "greeting"),
        ("hi there", "greeting"),
        ("hey there", "greeting"),
        ("how are you", "greeting"),
        ("\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35", "greeting"),
        ("\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35\u0e04\u0e23\u0e31\u0e1a", "greeting"),
        ("\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35\u0e04\u0e48\u0e30", "greeting"),
        ("\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35\u0e04\u0e23\u0e31\u0e1a\u0e1c\u0e21", "greeting"),
        ("\u0e2b\u0e27\u0e31\u0e14\u0e14\u0e35", "greeting"),
        ("\u0e2b\u0e27\u0e31\u0e14\u0e14\u0e35\u0e04\u0e23\u0e31\u0e1a", "greeting"),
        ("help", "help"),
        ("/help", "help"),
        ("?", "help"),
        ("menu", "help"),
        ("what can you do", "help"),
        ("what can you do?", "help"),
        ("how do i use this", "help"),
        ("\u0e0a\u0e48\u0e27\u0e22\u0e2d\u0e30\u0e44\u0e23\u0e44\u0e14\u0e49\u0e1a\u0e49\u0e32\u0e07", "help"),
        ("\u0e17\u0e33\u0e2d\u0e30\u0e44\u0e23\u0e44\u0e14\u0e49\u0e1a\u0e49\u0e32\u0e07", "help"),
        ("\u0e43\u0e0a\u0e49\u0e07\u0e32\u0e19\u0e22\u0e31\u0e07\u0e44\u0e07", "help"),
        ("\u0e27\u0e34\u0e18\u0e35\u0e43\u0e0a\u0e49", "help"),
        ("  HeLLo!!!  ", "greeting"),
        ("\tWHAT   CAN YOU DO?? ", "help"),
        ("\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35\u0e04\u0e23\u0e31\u0e1a\u0e46", "greeting"),
    ],
)
def test_classifies_full_message_greetings_and_help(text, intent):
    assert classify_intent(text) == intent


@pytest.mark.parametrize(
    "text",
    [
        "thanks a lot",
        "asdfghjkl",
        "\u0e02\u0e2d\u0e1a\u0e04\u0e38\u0e13\u0e21\u0e32\u0e01",
    ],
)
def test_classifies_short_non_investigative_messages_as_need_ioc(text):
    assert classify_intent(text, allow_need_ioc=True) == "need_ioc"
    assert classify_intent(text, allow_need_ioc=False) is None


@pytest.mark.parametrize(
    "text",
    [
        "analyze 8.8.8.8",
        "investigate the ioc: evil.com",
        "hunt for APT29",
        "triage this alert",
        "\u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a\u0e21\u0e31\u0e25\u0e41\u0e27\u0e23\u0e4c",
        "CVE-2024-3094",
        "a" * 41,
    ],
)
def test_investigation_requests_and_long_text_are_not_need_ioc(text):
    assert classify_intent(text, allow_need_ioc=True) is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("hello 1.1.1.1", None),
        ("help me analyze 8.8.8.8", None),
        ("", None),
        ("   ", None),
    ],
)
def test_ioc_and_empty_messages_do_not_get_instant_routing(text, expected):
    assert classify_intent(text, allow_need_ioc=True) is expected


@pytest.mark.parametrize(
    ("intent", "text", "response"),
    [
        ("greeting", "hello", "How can I help you today?"),
        (
            "greeting",
            "\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35",
            "\u0e21\u0e35\u0e2d\u0e30\u0e44\u0e23\u0e43\u0e2b\u0e49\u0e0a\u0e48\u0e27\u0e22\u0e27\u0e31\u0e19\u0e19\u0e35\u0e49\u0e44\u0e2b\u0e21\u0e04\u0e23\u0e31\u0e1a?",
        ),
        ("help", "help", "I can help with these security tasks:"),
        (
            "help",
            "\u0e0a\u0e48\u0e27\u0e22\u0e2d\u0e30\u0e44\u0e23\u0e44\u0e14\u0e49\u0e1a\u0e49\u0e32\u0e07",
            "\u0e1c\u0e21\u0e0a\u0e48\u0e27\u0e22\u0e07\u0e32\u0e19\u0e14\u0e49\u0e32\u0e19\u0e04\u0e27\u0e32\u0e21\u0e1b\u0e25\u0e2d\u0e14\u0e20\u0e31\u0e22\u0e40\u0e2b\u0e25\u0e48\u0e32\u0e19\u0e35\u0e49\u0e44\u0e14\u0e49\u0e04\u0e23\u0e31\u0e1a:",
        ),
        (
            "need_ioc",
            "thanks a lot",
            "I didn't find an IOC in that. Paste an IP, domain, URL or file hash, or pick an action below.",
        ),
        (
            "need_ioc",
            "\u0e02\u0e2d\u0e1a\u0e04\u0e38\u0e13\u0e21\u0e32\u0e01",
            "\u0e44\u0e21\u0e48\u0e1e\u0e1a IOC \u0e43\u0e19\u0e02\u0e49\u0e2d\u0e04\u0e27\u0e32\u0e21\u0e19\u0e35\u0e49 \u0e27\u0e32\u0e07 IP, \u0e42\u0e14\u0e40\u0e21\u0e19, URL \u0e2b\u0e23\u0e37\u0e2d\u0e41\u0e2e\u0e0a\u0e17\u0e35\u0e48\u0e15\u0e49\u0e2d\u0e07\u0e01\u0e32\u0e23\u0e15\u0e23\u0e27\u0e08 \u0e2b\u0e23\u0e37\u0e2d\u0e40\u0e25\u0e37\u0e2d\u0e01\u0e14\u0e49\u0e32\u0e19\u0e25\u0e48\u0e32\u0e07\u0e44\u0e14\u0e49\u0e40\u0e25\u0e22\u0e04\u0e23\u0e31\u0e1a",
        ),
    ],
)
def test_reply_language_and_copy(intent, text, response):
    assert build_instant_reply(intent, text)["response"] == response


def test_instant_reply_shape_and_starter_action_prefixes():
    english = build_instant_reply("need_ioc", "thanks a lot")
    thai = build_instant_reply("need_ioc", "\u0e02\u0e2d\u0e1a\u0e04\u0e38\u0e13\u0e21\u0e32\u0e01")
    expected_prefixes = [
        "Investigate the IOC: ",
        "Analyze the malware file at: ",
        "Analyze the phishing email at: ",
        "Hunt for threats matching: ",
        "Triage the alert: ",
        "Generate detection rules for: ",
    ]

    assert english["type"] == "instant"
    assert english["intent"] == "need_ioc"
    assert english["session_id"] is None
    assert len(english["actions"]) == len(thai["actions"]) == 6
    assert [action["prefix"] for action in english["actions"]] == expected_prefixes
    assert [action["prefix"] for action in thai["actions"]] == expected_prefixes
    assert all(set(action) == {"label", "prefix", "description"} for action in english["actions"])
