"""UI presentation metadata for built-in local agent tools."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LocalToolPresentation:
    display_name: str
    icon: str


# The SVG icon set has no dedicated IOC, rules, sandbox, EDR, or MITRE icons.
# Use the closest existing security category icon without changing tool IDs.
LOCAL_TOOL_PRESENTATION: dict[str, LocalToolPresentation] = {
    "investigate_ioc": LocalToolPresentation("IOC Investigation", "threat-intel"),
    "analyze_malware": LocalToolPresentation("Malware Analysis", "malware"),
    "analyze_email": LocalToolPresentation("Email Analysis", "malware"),
    "extract_iocs": LocalToolPresentation("IOC Extractor", "threat-intel"),
    "generate_rules": LocalToolPresentation("Rule Generator", "malware"),
    "yara_scan": LocalToolPresentation("YARA Scanner", "malware"),
    "search_threat_intel": LocalToolPresentation("Threat Intel Search", "threat-intel"),
    "sandbox_submit": LocalToolPresentation("Sandbox Submit", "malware"),
    "correlate_findings": LocalToolPresentation("MITRE Correlation", "malware"),
    "recall_ioc": LocalToolPresentation("IOC Recall", "threat-intel"),
    "isolate_device": LocalToolPresentation("Device Isolation", "malware"),
    "block_ip": LocalToolPresentation("IP Block", "network"),
    "extract_file_hash_pairs": LocalToolPresentation("File Hash Pairs", "forensics"),
    "quarantine_file": LocalToolPresentation("File Quarantine", "malware"),
}


def get_local_tool_presentation(tool_name: str) -> LocalToolPresentation | None:
    """Return presentation metadata for a local tool, if explicitly mapped."""
    return LOCAL_TOOL_PRESENTATION.get(str(tool_name))
