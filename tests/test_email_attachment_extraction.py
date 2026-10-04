import asyncio
from email.message import EmailMessage

from src.tools.email_analyzer import EmailAnalyzer


def _analyzer() -> EmailAnalyzer:
    return EmailAnalyzer({"analysis": {"enable_rag": False}})


def _extract(message: EmailMessage) -> dict:
    return asyncio.run(_analyzer()._extract_email_data(message))


def _base_message() -> EmailMessage:
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["To"] = "recipient@example.test"
    message["Subject"] = "Attachment extraction test"
    return message


def test_text_plain_attachment_is_not_added_to_body():
    message = _base_message()
    message.set_content("visible body")
    message.add_attachment("attached plain text", subtype="plain", filename="probe.txt")

    data = _extract(message)

    assert data["attachments"] == [
        {"filename": "probe.txt", "content_type": "text/plain", "size": len("attached plain text\n".encode())}
    ]
    assert data["body_text"] == "visible body\n"
    assert "attached plain text" not in data["body_text"]


def test_text_html_attachment_is_not_added_to_html_body():
    message = _base_message()
    message.set_content("visible body")
    message.add_attachment("<p>attached html</p>", subtype="html", filename="probe.html")

    data = _extract(message)

    assert data["attachments"] == [
        {"filename": "probe.html", "content_type": "text/html", "size": len("<p>attached html</p>\n".encode())}
    ]
    assert "attached html" not in data["body_html"]


def test_binary_attachment_keeps_existing_attachment_shape():
    message = _base_message()
    message.set_content("visible body")
    payload = b"\x00\x01probe-bin"
    message.add_attachment(payload, maintype="application", subtype="octet-stream", filename="probe.bin")

    data = _extract(message)

    assert data["attachments"] == [
        {"filename": "probe.bin", "content_type": "application/octet-stream", "size": len(payload)}
    ]
    assert data["body_text"] == "visible body\n"


def test_multipart_alternative_body_parts_are_not_attachments():
    message = _base_message()
    message.set_content("plain body")
    message.add_alternative("<p>html body</p>", subtype="html")

    data = _extract(message)

    assert data["attachments"] == []
    assert "plain body" in data["body_text"]
    assert "html body" in data["body_html"]


def test_non_multipart_email_body_is_unchanged():
    message = _base_message()
    message.set_content("single body")

    data = _extract(message)

    assert data["attachments"] == []
    assert data["body_text"] == "single body\n"
    assert data["body_html"] == ""


def test_attachment_without_filename_uses_unnamed():
    message = _base_message()
    message.set_content("visible body")
    message.make_mixed()
    attachment = EmailMessage()
    attachment.set_content("unnamed attachment")
    attachment["Content-Disposition"] = "attachment"
    message.attach(attachment)

    data = _extract(message)

    assert data["attachments"] == [
        {"filename": "unnamed", "content_type": "text/plain", "size": len("unnamed attachment\n".encode())}
    ]
    assert data["body_text"] == "visible body\n"
    assert "unnamed attachment" not in data["body_text"]
