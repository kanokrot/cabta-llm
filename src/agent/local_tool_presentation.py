"""UI presentation metadata for built-in local agent tools."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LocalToolPresentation:
    display_name: str
    icon: str
    ui_category: str
    summary: str


# The SVG icon set has no dedicated IOC, rules, sandbox, EDR, or MITRE icons.
# Use the closest existing security category icon without changing tool IDs.
LOCAL_TOOL_PRESENTATION: dict[str, LocalToolPresentation] = {
    "investigate_ioc": LocalToolPresentation(
        "IOC Investigation", "threat-intel", "Threat Intel",
        "Scores an IP, domain, URL, or hash using the configured threat intelligence sources.",
    ),
    "analyze_malware": LocalToolPresentation(
        "Malware Analysis", "malware", "Malware",
        "Analyzes a file for malware indicators, including signatures and file structure.",
    ),
    "analyze_email": LocalToolPresentation(
        "Email Analysis", "malware", "Malware",
        "Checks an email file for phishing signals, header anomalies, and attachments.",
    ),
    "extract_iocs": LocalToolPresentation(
        "IOC Extractor", "threat-intel", "Threat Intel",
        "Finds IP addresses, domains, URLs, and file hashes in supplied text.",
    ),
    "generate_rules": LocalToolPresentation(
        "Rule Generator", "malware", "Malware",
        "Builds detection rules from analysis results for the selected security platforms.",
    ),
    "yara_scan": LocalToolPresentation(
        "YARA Scanner", "malware", "Malware",
        "Scans a file against the built-in YARA rules and reports matching rules.",
    ),
    "search_threat_intel": LocalToolPresentation(
        "Threat Intel Search", "threat-intel", "Threat Intel",
        "Searches configured threat intelligence sources for an indicator or keyword.",
    ),
    "sandbox_submit": LocalToolPresentation(
        "Sandbox Submit", "malware", "Malware",
        "Submits a file for dynamic analysis in an isolated sandbox.",
    ),
    "correlate_findings": LocalToolPresentation(
        "MITRE Correlation", "malware", "Forensics",
        "Connects investigation, network, log, and timeline findings to related indicators and techniques.",
    ),
    "recall_ioc": LocalToolPresentation(
        "IOC Recall", "threat-intel", "Threat Intel",
        "Looks up earlier investigation results for an indicator in local memory.",
    ),
    "isolate_device": LocalToolPresentation(
        "Device Isolation", "malware", "Response",
        "Records a simulated device isolation action without changing the real network.",
    ),
    "block_ip": LocalToolPresentation(
        "IP Block", "network", "Response",
        "Records a simulated IP block action without changing firewall rules.",
    ),
    "extract_file_hash_pairs": LocalToolPresentation(
        "File Hash Pairs", "forensics", "Forensics",
        "Pairs file paths with SHA-256 hashes found in file metadata results.",
    ),
    "quarantine_file": LocalToolPresentation(
        "File Quarantine", "malware", "Response",
        "Copies an available file into the local quarantine folder and records the action.",
    ),
}


def get_local_tool_presentation(tool_name: str) -> LocalToolPresentation | None:
    """Return presentation metadata for a local tool, if explicitly mapped."""
    return LOCAL_TOOL_PRESENTATION.get(str(tool_name))
