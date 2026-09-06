"""Snapshot and integrity tests for canonical MITRE keyword patterns."""

from src.agent.correlation import _TTP_PATTERNS
from src.utils.mitre_keyword_patterns import (
    EXCLUDED_CONFLICTS,
    KEYWORD_TECHNIQUE_MAP,
)
from src.utils.mitre_mapper import MITRE_MAPPING
from src.utils.mitre_technique_names import get_technique_name


EXPECTED_MITRE_MAPPING = {
    'powershell': {'technique': 'T1059.001', 'tactic': 'Execution', 'name': 'PowerShell'},
    'cmd.exe': {'technique': 'T1059.003', 'tactic': 'Execution', 'name': 'Windows Command Shell'},
    'wscript': {'technique': 'T1059.005', 'tactic': 'Execution', 'name': 'Visual Basic'},
    'cscript': {'technique': 'T1059.005', 'tactic': 'Execution', 'name': 'Visual Basic'},
    'mshta': {'technique': 'T1218.005', 'tactic': 'Defense Evasion', 'name': 'Mshta'},
    'rundll32': {'technique': 'T1218.011', 'tactic': 'Defense Evasion', 'name': 'Rundll32'},
    'regsvr32': {'technique': 'T1218.010', 'tactic': 'Defense Evasion', 'name': 'Regsvr32'},
    'wmic': {'technique': 'T1047', 'tactic': 'Execution', 'name': 'Windows Management Instrumentation'},
    'invoke-expression': {'technique': 'T1059.001', 'tactic': 'Execution', 'name': 'PowerShell'},
    'iex': {'technique': 'T1059.001', 'tactic': 'Execution', 'name': 'PowerShell'},
    'schtasks': {'technique': 'T1053.005', 'tactic': 'Persistence', 'name': 'Scheduled Task'},
    'scheduled task': {'technique': 'T1053.005', 'tactic': 'Persistence', 'name': 'Scheduled Task'},
    'new-scheduledtask': {'technique': 'T1053.005', 'tactic': 'Persistence', 'name': 'Scheduled Task'},
    'currentversion\\run': {'technique': 'T1547.001', 'tactic': 'Persistence', 'name': 'Registry Run Keys'},
    'currentversion\\runonce': {'technique': 'T1547.001', 'tactic': 'Persistence', 'name': 'Registry Run Keys'},
    'startup folder': {'technique': 'T1547.001', 'tactic': 'Persistence', 'name': 'Registry Run Keys'},
    'new-service': {'technique': 'T1543.003', 'tactic': 'Persistence', 'name': 'Windows Service'},
    'sc create': {'technique': 'T1543.003', 'tactic': 'Persistence', 'name': 'Windows Service'},
    'userinit': {'technique': 'T1547.004', 'tactic': 'Persistence', 'name': 'Winlogon Helper DLL'},
    'winlogon': {'technique': 'T1547.004', 'tactic': 'Persistence', 'name': 'Winlogon Helper DLL'},
    'encodedcommand': {'technique': 'T1027', 'tactic': 'Defense Evasion', 'name': 'Obfuscated Files'},
    '-enc': {'technique': 'T1027', 'tactic': 'Defense Evasion', 'name': 'Obfuscated Files'},
    '-e ': {'technique': 'T1027', 'tactic': 'Defense Evasion', 'name': 'Obfuscated Files'},
    'base64': {'technique': 'T1027', 'tactic': 'Defense Evasion', 'name': 'Obfuscated Files'},
    'set-mppreference': {'technique': 'T1562.001', 'tactic': 'Defense Evasion', 'name': 'Disable or Modify Tools'},
    'disablerealtimemonitoring': {'technique': 'T1562.001', 'tactic': 'Defense Evasion', 'name': 'Disable or Modify Tools'},
    'disablebehaviormonitoring': {'technique': 'T1562.001', 'tactic': 'Defense Evasion', 'name': 'Disable or Modify Tools'},
    'disableioavprotection': {'technique': 'T1562.001', 'tactic': 'Defense Evasion', 'name': 'Disable or Modify Tools'},
    'add-mppreference': {'technique': 'T1562.001', 'tactic': 'Defense Evasion', 'name': 'Disable or Modify Tools'},
    'exclusionpath': {'technique': 'T1562.001', 'tactic': 'Defense Evasion', 'name': 'Disable or Modify Tools'},
    'amsi': {'technique': 'T1562.001', 'tactic': 'Defense Evasion', 'name': 'Disable or Modify Tools'},
    'virtualalloc': {'technique': 'T1055', 'tactic': 'Defense Evasion', 'name': 'Process Injection'},
    'virtualprotect': {'technique': 'T1055', 'tactic': 'Defense Evasion', 'name': 'Process Injection'},
    'createremotethread': {'technique': 'T1055', 'tactic': 'Defense Evasion', 'name': 'Process Injection'},
    'writeprocessmemory': {'technique': 'T1055', 'tactic': 'Defense Evasion', 'name': 'Process Injection'},
    'ntcreatethreadex': {'technique': 'T1055', 'tactic': 'Defense Evasion', 'name': 'Process Injection'},
    'mimikatz': {'technique': 'T1003.001', 'tactic': 'Credential Access', 'name': 'LSASS Memory'},
    'sekurlsa': {'technique': 'T1003.001', 'tactic': 'Credential Access', 'name': 'LSASS Memory'},
    'lsass': {'technique': 'T1003.001', 'tactic': 'Credential Access', 'name': 'LSASS Memory'},
    'procdump': {'technique': 'T1003.001', 'tactic': 'Credential Access', 'name': 'LSASS Memory'},
    'minidump': {'technique': 'T1003.001', 'tactic': 'Credential Access', 'name': 'LSASS Memory'},
    'get-credential': {'technique': 'T1056.002', 'tactic': 'Credential Access', 'name': 'GUI Input Capture'},
    'kerberos::': {'technique': 'T1558', 'tactic': 'Credential Access', 'name': 'Steal or Forge Kerberos'},
    'dpapi': {'technique': 'T1555.004', 'tactic': 'Credential Access', 'name': 'Windows Credential Manager'},
    'whoami': {'technique': 'T1033', 'tactic': 'Discovery', 'name': 'System Owner Discovery'},
    'systeminfo': {'technique': 'T1082', 'tactic': 'Discovery', 'name': 'System Information Discovery'},
    'ipconfig': {'technique': 'T1016', 'tactic': 'Discovery', 'name': 'System Network Config Discovery'},
    'net user': {'technique': 'T1087.001', 'tactic': 'Discovery', 'name': 'Local Account Discovery'},
    'net group': {'technique': 'T1069.001', 'tactic': 'Discovery', 'name': 'Local Groups Discovery'},
    'net localgroup': {'technique': 'T1069.001', 'tactic': 'Discovery', 'name': 'Local Groups Discovery'},
    'get-aduser': {'technique': 'T1087.002', 'tactic': 'Discovery', 'name': 'Domain Account Discovery'},
    'get-adcomputer': {'technique': 'T1018', 'tactic': 'Discovery', 'name': 'Remote System Discovery'},
    'get-adgroup': {'technique': 'T1069.002', 'tactic': 'Discovery', 'name': 'Domain Groups Discovery'},
    'get-wmiobject': {'technique': 'T1082', 'tactic': 'Discovery', 'name': 'System Information Discovery'},
    'tasklist': {'technique': 'T1057', 'tactic': 'Discovery', 'name': 'Process Discovery'},
    'get-process': {'technique': 'T1057', 'tactic': 'Discovery', 'name': 'Process Discovery'},
    'psexec': {'technique': 'T1570', 'tactic': 'Lateral Movement', 'name': 'Lateral Tool Transfer'},
    'invoke-wmimethod': {'technique': 'T1047', 'tactic': 'Execution', 'name': 'WMI'},
    'invoke-command': {'technique': 'T1021.006', 'tactic': 'Lateral Movement', 'name': 'WinRM'},
    'enter-pssession': {'technique': 'T1021.006', 'tactic': 'Lateral Movement', 'name': 'WinRM'},
    'clipboard': {'technique': 'T1115', 'tactic': 'Collection', 'name': 'Clipboard Data'},
    'screenshot': {'technique': 'T1113', 'tactic': 'Collection', 'name': 'Screen Capture'},
    'keylogger': {'technique': 'T1056.001', 'tactic': 'Collection', 'name': 'Keylogging'},
    'downloadstring': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'downloadfile': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'downloaddata': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'invoke-webrequest': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'invoke-restmethod': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'webclient': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'start-bitstransfer': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'certutil': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'bitsadmin': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'compress-archive': {'technique': 'T1560.001', 'tactic': 'Exfiltration', 'name': 'Archive via Utility'},
    '7z': {'technique': 'T1560.001', 'tactic': 'Exfiltration', 'name': 'Archive via Utility'},
    'rar': {'technique': 'T1560.001', 'tactic': 'Exfiltration', 'name': 'Archive via Utility'},
    'cipher /w': {'technique': 'T1485', 'tactic': 'Impact', 'name': 'Data Destruction'},
    'vssadmin delete': {'technique': 'T1490', 'tactic': 'Impact', 'name': 'Inhibit System Recovery'},
    'bcdedit': {'technique': 'T1490', 'tactic': 'Impact', 'name': 'Inhibit System Recovery'},
    'wbadmin delete': {'technique': 'T1490', 'tactic': 'Impact', 'name': 'Inhibit System Recovery'},
    'phishing': {'technique': 'T1566', 'tactic': 'Initial Access', 'name': 'Phishing'},
    'spearphishing': {'technique': 'T1566.001', 'tactic': 'Initial Access', 'name': 'Spearphishing Attachment'},
    'macro': {'technique': 'T1566.001', 'tactic': 'Initial Access', 'name': 'Spearphishing Attachment'},
}


EXPECTED_TTP_PATTERNS = [
    ("phishing", "T1566", "Phishing", "initial-access"),
    ("spearphish", "T1566.001", "Spearphishing Attachment", "initial-access"),
    ("drive-by", "T1189", "Drive-by Compromise", "initial-access"),
    ("powershell", "T1059.001", "PowerShell", "execution"),
    ("cmd.exe", "T1059.003", "Windows Command Shell", "execution"),
    ("wscript", "T1059.005", "Visual Basic", "execution"),
    ("cscript", "T1059.005", "Visual Basic", "execution"),
    ("macro", "T1204.002", "Malicious File", "execution"),
    ("vba", "T1204.002", "Malicious File", "execution"),
    ("shellcode", "T1059", "Command and Scripting Interpreter", "execution"),
    ("registry run", "T1547.001", "Registry Run Keys", "persistence"),
    ("scheduled task", "T1053.005", "Scheduled Task", "persistence"),
    ("startup folder", "T1547.001", "Registry Run Keys", "persistence"),
    ("service", "T1543.003", "Windows Service", "persistence"),
    ("uac bypass", "T1548.002", "Bypass User Account Control", "privilege-escalation"),
    ("token", "T1134", "Access Token Manipulation", "privilege-escalation"),
    ("obfuscation", "T1027", "Obfuscated Files or Information", "defense-evasion"),
    ("packed", "T1027.002", "Software Packing", "defense-evasion"),
    ("base64", "T1140", "Deobfuscate/Decode Files or Information", "defense-evasion"),
    ("injection", "T1055", "Process Injection", "defense-evasion"),
    ("hollow", "T1055.012", "Process Hollowing", "defense-evasion"),
    ("amsi bypass", "T1562.001", "Disable or Modify Tools", "defense-evasion"),
    ("mimikatz", "T1003.001", "LSASS Memory", "credential-access"),
    ("credential dump", "T1003", "OS Credential Dumping", "credential-access"),
    ("keylog", "T1056.001", "Keylogging", "credential-access"),
    ("whoami", "T1033", "System Owner/User Discovery", "discovery"),
    ("ipconfig", "T1016", "System Network Configuration Discovery", "discovery"),
    ("net view", "T1018", "Remote System Discovery", "discovery"),
    ("systeminfo", "T1082", "System Information Discovery", "discovery"),
    ("psexec", "T1570", "Lateral Tool Transfer", "lateral-movement"),
    ("wmi", "T1047", "Windows Management Instrumentation", "lateral-movement"),
    ("rdp", "T1021.001", "Remote Desktop Protocol", "lateral-movement"),
    ("smb", "T1021.002", "SMB/Windows Admin Shares", "lateral-movement"),
    ("screenshot", "T1113", "Screen Capture", "collection"),
    ("clipboard", "T1115", "Clipboard Data", "collection"),
    ("c2", "T1071", "Application Layer Protocol", "command-and-control"),
    ("beacon", "T1071.001", "Web Protocols", "command-and-control"),
    ("dns tunnel", "T1071.004", "DNS", "command-and-control"),
    ("tor", "T1090.003", "Multi-hop Proxy", "command-and-control"),
    ("exfiltrat", "T1041", "Exfiltration Over C2 Channel", "exfiltration"),
    ("upload", "T1567", "Exfiltration Over Web Service", "exfiltration"),
    ("ransom", "T1486", "Data Encrypted for Impact", "impact"),
    ("wiper", "T1485", "Data Destruction", "impact"),
    ("encrypt", "T1486", "Data Encrypted for Impact", "impact"),
]


def test_canonical_technique_ids_have_known_metadata():
    missing = {
        technique_id
        for technique_id in KEYWORD_TECHNIQUE_MAP.values()
        if get_technique_name(technique_id) is None
    }

    assert missing == set()


def test_canonical_keywords_exclude_conflicts():
    assert set(KEYWORD_TECHNIQUE_MAP).isdisjoint(EXCLUDED_CONFLICTS)
    assert EXCLUDED_CONFLICTS == {
        'base64': ['T1027', 'T1140'],
        'macro': ['T1566.001', 'T1204.002'],
    }


def test_mitre_mapping_snapshot_is_unchanged():
    assert MITRE_MAPPING == EXPECTED_MITRE_MAPPING
    assert list(MITRE_MAPPING.items()) == list(EXPECTED_MITRE_MAPPING.items())


def test_ttp_patterns_snapshot_is_unchanged():
    assert _TTP_PATTERNS == EXPECTED_TTP_PATTERNS
