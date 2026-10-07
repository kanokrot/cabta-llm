"""Small, deterministic intent handling for common Agent Chat messages."""

import unicodedata
from typing import Optional

from ..utils.ioc_extractor import IOCExtractor


_GREETING_INTENTS = {
    "hello",
    "hi",
    "hey",
    "good morning",
    "good afternoon",
    "good evening",
    "hello there",
    "hi there",
    "hey there",
    "how are you",
    "\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35",
    "\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35\u0e04\u0e23\u0e31\u0e1a",
    "\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35\u0e04\u0e48\u0e30",
    "\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35\u0e04\u0e23\u0e31\u0e1a\u0e1c\u0e21",
    "\u0e2b\u0e27\u0e31\u0e14\u0e14\u0e35",
    "\u0e2b\u0e27\u0e31\u0e14\u0e14\u0e35\u0e04\u0e23\u0e31\u0e1a",
}

_HELP_INTENTS = {
    "help",
    "/help",
    "?",
    "menu",
    "what can you do",
    "what can you do?",
    "how do i use this",
    "\u0e0a\u0e48\u0e27\u0e22\u0e2d\u0e30\u0e44\u0e23\u0e44\u0e14\u0e49\u0e1a\u0e49\u0e32\u0e07",
    "\u0e17\u0e33\u0e2d\u0e30\u0e44\u0e23\u0e44\u0e14\u0e49\u0e1a\u0e49\u0e32\u0e07",
    "\u0e43\u0e0a\u0e49\u0e07\u0e32\u0e19\u0e22\u0e31\u0e07\u0e44\u0e07",
    "\u0e27\u0e34\u0e18\u0e35\u0e43\u0e0a\u0e49",
}

INVESTIGATIVE_KEYWORDS = (
    "investigate", "analyze", "analyse", "hunt", "triage", "detect", "rule",
    "malware", "phishing", "email", "playbook", "alert", "ioc", "cve",
    "ransomware", "apt", "mitre", "sigma", "yara", "report",
    "\u0e15\u0e23\u0e27\u0e08", "\u0e27\u0e34\u0e40\u0e04\u0e23\u0e32\u0e30\u0e2b\u0e4c",
    "\u0e04\u0e49\u0e19\u0e2b\u0e32", "\u0e2a\u0e37\u0e1a\u0e2a\u0e27\u0e19",
    "\u0e21\u0e31\u0e25\u0e41\u0e27\u0e23\u0e4c", "\u0e1f\u0e34\u0e0a\u0e0a\u0e34\u0e07",
    "\u0e2d\u0e35\u0e40\u0e21\u0e25", "\u0e01\u0e0e", "\u0e41\u0e08\u0e49\u0e07\u0e40\u0e15\u0e37\u0e2d\u0e19",
)

_ACTIONS_EN = (
    ("IOC Investigation", "Investigate the IOC: ", "Investigate an IP, domain, URL, or hash."),
    ("Malware Analysis", "Analyze the malware file at: ", "Analyze a suspicious file and its behavior."),
    ("Email Forensics", "Analyze the phishing email at: ", "Inspect a suspicious or phishing email."),
    ("Threat Hunt", "Hunt for threats matching: ", "Search for matching indicators and activity."),
    ("Alert Triage", "Triage the alert: ", "Triage an alert and prioritize the response."),
    ("Detection Rules", "Generate detection rules for: ", "Create detection rules from observed threats."),
)

_ACTIONS_TH = (
    ("\u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a IOC", "Investigate the IOC: ", "\u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a IP, \u0e42\u0e14\u0e40\u0e21\u0e19, URL \u0e2b\u0e23\u0e37\u0e2d\u0e41\u0e2e\u0e0a"),
    ("\u0e27\u0e34\u0e40\u0e04\u0e23\u0e32\u0e30\u0e2b\u0e4c\u0e21\u0e31\u0e25\u0e41\u0e27\u0e23\u0e4c", "Analyze the malware file at: ", "\u0e27\u0e34\u0e40\u0e04\u0e23\u0e32\u0e30\u0e2b\u0e4c\u0e44\u0e1f\u0e25\u0e4c\u0e41\u0e25\u0e30\u0e1e\u0e24\u0e15\u0e34\u0e01\u0e23\u0e23\u0e21\u0e17\u0e35\u0e48\u0e19\u0e48\u0e32\u0e2a\u0e07\u0e2a\u0e31\u0e22"),
    ("\u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a\u0e2d\u0e35\u0e40\u0e21\u0e25", "Analyze the phishing email at: ", "\u0e15\u0e23\u0e27\u0e08\u0e2a\u0e2d\u0e1a\u0e2d\u0e35\u0e40\u0e21\u0e25\u0e17\u0e35\u0e48\u0e19\u0e48\u0e32\u0e2a\u0e07\u0e2a\u0e31\u0e22\u0e2b\u0e23\u0e37\u0e2d\u0e2d\u0e35\u0e40\u0e21\u0e25\u0e1f\u0e34\u0e0a\u0e0a\u0e34\u0e07"),
    ("\u0e04\u0e49\u0e19\u0e2b\u0e32\u0e20\u0e31\u0e22\u0e04\u0e38\u0e01\u0e04\u0e32\u0e21", "Hunt for threats matching: ", "\u0e04\u0e49\u0e19\u0e2b\u0e32\u0e15\u0e31\u0e27\u0e1a\u0e48\u0e07\u0e0a\u0e35\u0e49\u0e41\u0e25\u0e30\u0e01\u0e34\u0e08\u0e01\u0e23\u0e23\u0e21\u0e17\u0e35\u0e48\u0e15\u0e23\u0e07\u0e01\u0e31\u0e19"),
    ("\u0e04\u0e31\u0e14\u0e01\u0e23\u0e2d\u0e07\u0e01\u0e32\u0e23\u0e41\u0e08\u0e49\u0e07\u0e40\u0e15\u0e37\u0e2d\u0e19", "Triage the alert: ", "\u0e04\u0e31\u0e14\u0e01\u0e23\u0e2d\u0e07\u0e01\u0e32\u0e23\u0e41\u0e08\u0e49\u0e07\u0e40\u0e15\u0e37\u0e2d\u0e19\u0e41\u0e25\u0e30\u0e08\u0e31\u0e14\u0e25\u0e33\u0e14\u0e31\u0e1a\u0e01\u0e32\u0e23\u0e15\u0e2d\u0e1a\u0e2a\u0e19\u0e2d\u0e07"),
    ("\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e01\u0e0e\u0e15\u0e23\u0e27\u0e08\u0e08\u0e31\u0e1a", "Generate detection rules for: ", "\u0e2a\u0e23\u0e49\u0e32\u0e07\u0e01\u0e0e\u0e15\u0e23\u0e27\u0e08\u0e08\u0e31\u0e1a\u0e08\u0e32\u0e01\u0e20\u0e31\u0e22\u0e04\u0e38\u0e01\u0e04\u0e32\u0e21\u0e17\u0e35\u0e48\u0e1e\u0e1a"),
)


def _normalize(text: str) -> str:
    normalized = unicodedata.normalize("NFC", text.strip().lower())
    if normalized == "?":
        return normalized
    normalized = normalized.rstrip("!? .\u0e46")
    return " ".join(normalized.split())


def _contains_ioc(text: str) -> bool:
    extracted = IOCExtractor.extract_all(text)
    return bool(
        extracted["ipv4"]
        or extracted.get("ipv6")
        or extracted["domains"]
        or extracted["urls"]
        or extracted["emails"]
        or any(extracted["hashes"].values())
        or extracted["cve_ids"]
    )


def classify_intent(text: str, allow_need_ioc: bool = True) -> Optional[str]:
    """Classify short full-message greetings/help and optional non-IOC chat."""
    if not isinstance(text, str):
        return None
    normalized = _normalize(text)
    if not normalized or len(normalized) > 40:
        return None
    if normalized in _GREETING_INTENTS:
        return "greeting"
    if normalized in _HELP_INTENTS:
        return "help"
    if not allow_need_ioc or _contains_ioc(text):
        return None
    if any(keyword in normalized for keyword in INVESTIGATIVE_KEYWORDS):
        return None
    return "need_ioc"


def build_instant_reply(intent: str, text: str) -> dict:
    """Build a localized, session-free response for a classified intent."""
    is_thai = any("\u0e00" <= char <= "\u0e7f" for char in text)
    if intent == "greeting":
        response = "\u0e21\u0e35\u0e2d\u0e30\u0e44\u0e23\u0e43\u0e2b\u0e49\u0e0a\u0e48\u0e27\u0e22\u0e27\u0e31\u0e19\u0e19\u0e35\u0e49\u0e44\u0e2b\u0e21\u0e04\u0e23\u0e31\u0e1a?" if is_thai else "How can I help you today?"
    elif intent == "help":
        response = (
            "\u0e1c\u0e21\u0e0a\u0e48\u0e27\u0e22\u0e07\u0e32\u0e19\u0e14\u0e49\u0e32\u0e19\u0e04\u0e27\u0e32\u0e21\u0e1b\u0e25\u0e2d\u0e14\u0e20\u0e31\u0e22\u0e40\u0e2b\u0e25\u0e48\u0e32\u0e19\u0e35\u0e49\u0e44\u0e14\u0e49\u0e04\u0e23\u0e31\u0e1a:"
            if is_thai
            else "I can help with these security tasks:"
        )
    elif intent == "need_ioc":
        response = (
            "\u0e44\u0e21\u0e48\u0e1e\u0e1a IOC \u0e43\u0e19\u0e02\u0e49\u0e2d\u0e04\u0e27\u0e32\u0e21\u0e19\u0e35\u0e49 \u0e27\u0e32\u0e07 IP, \u0e42\u0e14\u0e40\u0e21\u0e19, URL \u0e2b\u0e23\u0e37\u0e2d\u0e41\u0e2e\u0e0a\u0e17\u0e35\u0e48\u0e15\u0e49\u0e2d\u0e07\u0e01\u0e32\u0e23\u0e15\u0e23\u0e27\u0e08 \u0e2b\u0e23\u0e37\u0e2d\u0e40\u0e25\u0e37\u0e2d\u0e01\u0e14\u0e49\u0e32\u0e19\u0e25\u0e48\u0e32\u0e07\u0e44\u0e14\u0e49\u0e40\u0e25\u0e22\u0e04\u0e23\u0e31\u0e1a"
            if is_thai
            else "I didn't find an IOC in that. Paste an IP, domain, URL or file hash, or pick an action below."
        )
    else:
        raise ValueError(f"Unsupported chat intent: {intent}")

    actions = _ACTIONS_TH if is_thai else _ACTIONS_EN
    return {
        "type": "instant",
        "intent": intent,
        "response": response,
        "actions": [
            {"label": label, "prefix": prefix, "description": description}
            for label, prefix, description in actions
        ],
        "session_id": None,
    }
