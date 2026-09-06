"""Static MITRE ATT&CK technique name and tactic lookup.

Entries were sourced from ``src/utils/mitre_mapper.py`` (``MITRE_MAPPING``
and ``category_mapping``) and ``src/agent/correlation.py``
(``_TTP_PATTERNS``) as of this fix. Duplicate technique IDs keep the first
entry found in that source order.
"""

from typing import Dict, Optional


TECHNIQUE_NAMES: Dict[str, Dict[str, str]] = {
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
    "T1059.005": {"name": "Visual Basic", "tactic": "Execution"},
    "T1218.005": {"name": "Mshta", "tactic": "Defense Evasion"},
    "T1218.011": {"name": "Rundll32", "tactic": "Defense Evasion"},
    "T1218.010": {"name": "Regsvr32", "tactic": "Defense Evasion"},
    "T1047": {
        "name": "Windows Management Instrumentation",
        "tactic": "Execution",
    },
    "T1053.005": {"name": "Scheduled Task", "tactic": "Persistence"},
    "T1547.001": {"name": "Registry Run Keys", "tactic": "Persistence"},
    "T1543.003": {"name": "Windows Service", "tactic": "Persistence"},
    "T1547.004": {"name": "Winlogon Helper DLL", "tactic": "Persistence"},
    "T1027": {"name": "Obfuscated Files", "tactic": "Defense Evasion"},
    "T1562.001": {
        "name": "Disable or Modify Tools",
        "tactic": "Defense Evasion",
    },
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access"},
    "T1056.002": {"name": "GUI Input Capture", "tactic": "Credential Access"},
    "T1558": {
        "name": "Steal or Forge Kerberos",
        "tactic": "Credential Access",
    },
    "T1555.004": {
        "name": "Windows Credential Manager",
        "tactic": "Credential Access",
    },
    "T1033": {"name": "System Owner Discovery", "tactic": "Discovery"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1016": {"name": "System Network Config Discovery", "tactic": "Discovery"},
    "T1087.001": {"name": "Local Account Discovery", "tactic": "Discovery"},
    "T1069.001": {"name": "Local Groups Discovery", "tactic": "Discovery"},
    "T1087.002": {"name": "Domain Account Discovery", "tactic": "Discovery"},
    "T1018": {"name": "Remote System Discovery", "tactic": "Discovery"},
    "T1069.002": {"name": "Domain Groups Discovery", "tactic": "Discovery"},
    "T1057": {"name": "Process Discovery", "tactic": "Discovery"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
    "T1021.006": {"name": "WinRM", "tactic": "Lateral Movement"},
    "T1115": {"name": "Clipboard Data", "tactic": "Collection"},
    "T1113": {"name": "Screen Capture", "tactic": "Collection"},
    "T1056.001": {"name": "Keylogging", "tactic": "Collection"},
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
    },
    "T1560.001": {"name": "Archive via Utility", "tactic": "Exfiltration"},
    "T1485": {"name": "Data Destruction", "tactic": "Impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
    },
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1056": {"name": "Input Capture", "tactic": "Collection"},
    "T1189": {"name": "Drive-by Compromise", "tactic": "initial-access"},
    "T1204.002": {"name": "Malicious File", "tactic": "execution"},
    "T1548.002": {
        "name": "Bypass User Account Control",
        "tactic": "privilege-escalation",
    },
    "T1134": {
        "name": "Access Token Manipulation",
        "tactic": "privilege-escalation",
    },
    "T1027.002": {"name": "Software Packing", "tactic": "defense-evasion"},
    "T1140": {
        "name": "Deobfuscate/Decode Files or Information",
        "tactic": "defense-evasion",
    },
    "T1055.012": {"name": "Process Hollowing", "tactic": "defense-evasion"},
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "lateral-movement",
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactic": "lateral-movement",
    },
    "T1071.001": {"name": "Web Protocols", "tactic": "command-and-control"},
    "T1071.004": {"name": "DNS", "tactic": "command-and-control"},
    "T1090.003": {"name": "Multi-hop Proxy", "tactic": "command-and-control"},
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic": "exfiltration",
    },
}


def get_technique_name(technique_id: str) -> Optional[Dict[str, str]]:
    """Return known name/tactic metadata for a technique ID, or ``None``."""
    return TECHNIQUE_NAMES.get(technique_id)
