from src.integrations.notification_policy import event_frequency
from src.integrations.notifications import NotificationManager


class FakeChannel:
    def __init__(self):
        self.calls = []

    def send(self, subject, message):
        self.calls.append((subject, message))
        return {"success": True}


def _manager(create_on_verdict=("MALICIOUS", "SUSPICIOUS")):
    manager = NotificationManager.__new__(NotificationManager)
    manager.create_on_verdict = list(create_on_verdict)
    manager.channels = [FakeChannel()]
    manager.gmail_sender = None
    manager.notification_store = None
    return manager, manager.channels[0]


def test_legacy_verdict_alerts_only_send_for_configured_verdicts():
    for verdict in ("CLEAN", "UNKNOWN", "clean"):
        manager, channel = _manager()
        manager.notify("verdict_alert", {"verdict": verdict})
        assert channel.calls == []

    for verdict in ("MALICIOUS", "SUSPICIOUS"):
        manager, channel = _manager()
        manager.notify("verdict_alert", {"verdict": verdict})
        assert len(channel.calls) == 1


def test_non_verdict_events_still_send_to_legacy_channels():
    manager, channel = _manager()
    manager.notify("approval_required", {"verdict": "CLEAN"})
    assert len(channel.calls) == 1


def test_empty_create_on_verdict_suppresses_legacy_verdict_alerts():
    manager, channel = _manager(())
    manager.notify("verdict_alert", {"verdict": "MALICIOUS"})
    assert channel.calls == []


def test_gmail_policy_keeps_clean_verdict_as_none():
    assert event_frequency("verdict_alert", {"verdict": "CLEAN"}) == "none"
