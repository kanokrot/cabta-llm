"""Tests for the shared MITRE technique name and tactic lookup."""

from src.utils.mitre_technique_names import get_technique_name


def test_get_technique_name_returns_known_entries():
    assert get_technique_name("T1059.001") == {
        "name": "PowerShell",
        "tactic": "Execution",
    }
    assert get_technique_name("T1547") == {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
    }
    assert get_technique_name("T1105") == {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
    }
    assert get_technique_name("T1486") == {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
    }


def test_get_technique_name_returns_none_for_unknown_id():
    assert get_technique_name("T9999.999") is None
