"""UI presentation metadata for built-in local agent tools."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LocalToolPresentation:
    display_name: str
    icon: str
    ui_category: str


# The SVG icon set has no dedicated IOC, rules, sandbox, EDR, or MITRE icons.
# Use the closest existing security category icon without changing tool IDs.
LOCAL_TOOL_PRESENTATION: dict[str, LocalToolPresentation] = {
    "investigate_ioc": LocalToolPresentation("IOC Investigation", "threat-intel", "Threat Intel"),
    "analyze_malware": LocalToolPresentation("Malware Analysis", "malware", "Malware"),
    "analyze_email": LocalToolPresentation("Email Analysis", "malware", "Malware"),
    "extract_iocs": LocalToolPresentation("IOC Extractor", "threat-intel", "Threat Intel"),
    "generate_rules": LocalToolPresentation("Rule Generator", "malware", "Malware"),
    "yara_scan": LocalToolPresentation("YARA Scanner", "malware", "Malware"),
    "search_threat_intel": LocalToolPresentation("Threat Intel Search", "threat-intel", "Threat Intel"),
    "sandbox_submit": LocalToolPresentation("Sandbox Submit", "malware", "Malware"),
    "correlate_findings": LocalToolPresentation("MITRE Correlation", "malware", "Forensics"),
    "recall_ioc": LocalToolPresentation("IOC Recall", "threat-intel", "Threat Intel"),
    "isolate_device": LocalToolPresentation("Device Isolation", "malware", "Response"),
    "block_ip": LocalToolPresentation("IP Block", "network", "Response"),
    "extract_file_hash_pairs": LocalToolPresentation("File Hash Pairs", "forensics", "Forensics"),
    "quarantine_file": LocalToolPresentation("File Quarantine", "malware", "Response"),
}


def get_local_tool_presentation(tool_name: str) -> LocalToolPresentation | None:
    """Return presentation metadata for a local tool, if explicitly mapped."""
    return LOCAL_TOOL_PRESENTATION.get(str(tool_name))
