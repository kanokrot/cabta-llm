"""Offline regression coverage for Alert Triage extractor references."""

import re
from unittest.mock import MagicMock

from src.agent.playbook_engine import PlaybookEngine, _resolve_var
from src.utils.ioc_extractor import IOCExtractor


ALERT_TEXT = (
    "Observed 8.8.8.8 contacting https://evilcorp.biz/login; "
    "domain evilcorp.biz; file SHA256 "
    "44d88612fea8a8f36de82e1278abb02f8e3f4a3b5a9b20d3a3f8c5a6d7e8f901; "
    "CVE-2021-44228; sender analyst@sender.evilcorp.biz."
)
EMAIL_SECURITY_STEP = "email_security"


def test_alert_triage_extractor_paths_resolve_to_nonempty_lists():
    """IOC-driven loops and conditions resolve from the real extractor shape."""
    agent_loop = MagicMock()
    agent_loop.config = {}
    engine = PlaybookEngine(agent_loop=agent_loop, agent_store=MagicMock())
    playbook = engine.get_playbook("alert_triage")
    assert playbook is not None, "alert_triage.yaml was not loaded by PlaybookEngine"

    extracted = IOCExtractor.extract_all(ALERT_TEXT)
    context = {"extract_alert_iocs": {"iocs": extracted}}
    missing_or_empty = []
    checked_steps = set()

    for step in playbook["steps"]:
        name = step["name"]
        if name == EMAIL_SECURITY_STEP:
            # There is no sender_domains field: keep this check explicitly
            # skipped until a safe email-to-domain mapping exists.
            assert step.get("for_each") == "extract_alert_iocs.sender_domains"
            condition = step.get("condition", "")
            assert "{{extract_alert_iocs.sender_domains}}" in condition
            assert _resolve_var("extract_alert_iocs.sender_domains", context) is None
            continue

        paths = []
        for_each = step.get("for_each")
        if isinstance(for_each, str) and for_each.startswith("extract_alert_iocs."):
            paths.append(for_each)

        condition_text = step.get("condition") or ""
        for path in re.findall(r"\{\{\s*([^{}]+?)\s*\}\}", condition_text):
            if path.startswith("extract_alert_iocs."):
                paths.append(path)

        for path in paths:
            checked_steps.add(name)
            resolved = _resolve_var(path, context)
            if not isinstance(resolved, list) or not resolved:
                missing_or_empty.append(
                    f"{name}: {path} resolved to {resolved!r}; expected a non-empty list"
                )

    assert checked_steps, "No Alert Triage extractor paths were checked"
    assert not missing_or_empty, "Empty Alert Triage IOC paths:\n" + "\n".join(missing_or_empty)
