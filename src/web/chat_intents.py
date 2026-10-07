"""Small, deterministic intent handling for common Agent Chat messages."""

import unicodedata
from typing import Optional


_GREETING_INTENTS = {
    "hello",
    "hi",
    "hey",
    "good morning",
    "good afternoon",
    "good evening",
    "สวัสดี",
    "สวัสดีครับ",
    "สวัสดีค่ะ",
    "หวัดดี",
}

_HELP_INTENTS = {
    "help",
    "/help",
    "?",
    "menu",
    "what can you do",
    "what can you do?",
    "how do i use this",
    "ช่วยอะไรได้บ้าง",
    "ทำอะไรได้บ้าง",
    "ใช้งานยังไง",
    "วิธีใช้",
}

_ACTIONS_EN = (
    ("IOC Investigation", "Investigate the IOC: ", "Investigate an IP, domain, URL, or hash."),
    ("Malware Analysis", "Analyze the malware file at: ", "Analyze a suspicious file and its behavior."),
    ("Email Forensics", "Analyze the phishing email at: ", "Inspect a suspicious or phishing email."),
    ("Threat Hunt", "Hunt for threats matching: ", "Search for matching indicators and activity."),
    ("Alert Triage", "Triage the alert: ", "Triage an alert and prioritize the response."),
    ("Detection Rules", "Generate detection rules for: ", "Create detection rules from observed threats."),
)

_ACTIONS_TH = (
    ("ตรวจสอบ IOC", "Investigate the IOC: ", "ตรวจสอบ IP, โดเมน, URL หรือแฮช"),
    ("วิเคราะห์มัลแวร์", "Analyze the malware file at: ", "วิเคราะห์ไฟล์และพฤติกรรมที่น่าสงสัย"),
    ("ตรวจสอบอีเมล", "Analyze the phishing email at: ", "ตรวจสอบอีเมลที่น่าสงสัยหรืออีเมลฟิชชิง"),
    ("ค้นหาภัยคุกคาม", "Hunt for threats matching: ", "ค้นหาตัวบ่งชี้และกิจกรรมที่ตรงกัน"),
    ("คัดกรองการแจ้งเตือน", "Triage the alert: ", "คัดกรองการแจ้งเตือนและจัดลำดับการตอบสนอง"),
    ("สร้างกฎตรวจจับ", "Generate detection rules for: ", "สร้างกฎตรวจจับจากภัยคุกคามที่พบ"),
)


def _normalize(text: str) -> str:
    normalized = unicodedata.normalize("NFC", text.strip().lower())
    if normalized == "?":
        return normalized
    normalized = normalized.rstrip("!? .ๆ")
    return " ".join(normalized.split())


def classify_intent(text: str) -> Optional[str]:
    """Return a greeting/help intent only when the entire short message matches."""
    if not isinstance(text, str):
        return None
    normalized = _normalize(text)
    if not normalized or len(normalized) > 40:
        return None
    if normalized in _GREETING_INTENTS:
        return "greeting"
    if normalized in _HELP_INTENTS:
        return "help"
    return None


def build_instant_reply(intent: str, text: str) -> dict:
    """Build a localized, session-free response for a classified intent."""
    is_thai = any("\u0e00" <= char <= "\u0e7f" for char in text)
    if intent == "greeting":
        response = "มีอะไรให้ช่วยวันนี้ไหมครับ?" if is_thai else "How can I help you today?"
    elif intent == "help":
        response = (
            "ผมช่วยงานด้านความปลอดภัยเหล่านี้ได้ครับ:"
            if is_thai
            else "I can help with these security tasks:"
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
