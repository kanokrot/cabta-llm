"""Presentation metadata for MCP tools.

The MCP name is deliberately kept separate from this module.  The key is the
server name plus the raw MCP function name, while the values are UI-only
labels and icons.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MCPToolPresentation:
    display_name: str
    ui_category: str
    icon: str
    summary: str
    examples: tuple[str, ...]
    logo: str | None = None


UI_CATEGORY_ICONS = {
    "Network": "network",
    "OSINT": "osint",
    "Threat Intel": "threat-intel",
    "Malware": "malware",
    "Forensics": "forensics",
}

_INTERNAL_CATEGORY_TO_UI = {
    "analysis": "Malware",
    "forensics": "Forensics",
    "network": "Network",
    "osint": "OSINT",
    "threat_intel": "Threat Intel",
}


def _item(
    display_name: str,
    ui_category: str,
    summary: str,
    examples: tuple[str, ...],
    logo: str | None = None,
) -> MCPToolPresentation:
    return MCPToolPresentation(
        display_name=display_name,
        ui_category=ui_category,
        icon=UI_CATEGORY_ICONS[ui_category],
        summary=summary,
        examples=examples,
        logo=logo,
    )


# Every registered tool in the eight configured MCP servers has an explicit
# entry.  Keep this keyed by the raw MCP name, not the registry's server.name
# identifier, so presentation metadata cannot affect dispatch or persistence.
MCP_TOOL_PRESENTATION: dict[tuple[str, str], MCPToolPresentation] = {
    ("osint_tools", "whois_lookup"): _item("WHOIS Lookup", "OSINT", "Look up registration and ownership information for a domain or IP address.", ("Check a domain's registration record", "Inspect the WHOIS server response")),
    ("osint_tools", "dns_resolve"): _item("DNS Resolve", "Network", "Resolve requested DNS record types for a domain.", ("Resolve A and AAAA records", "Inspect MX, NS, TXT, or CNAME records")),
    ("osint_tools", "geoip_lookup"): _item("IP Geolocation", "OSINT", "Look up geographic location and ASN information for an IP address.", ("Identify an IP's country and region", "Review ASN and organization details")),
    ("osint_tools", "reverse_dns"): _item("Reverse DNS", "Network", "Find hostnames and aliases associated with an IP address.", ("Find the PTR hostname for an IP", "Review resolved aliases and addresses")),
    ("osint_tools", "ssl_certificate_info"): _item("SSL Certificate", "Network", "Retrieve and inspect an SSL/TLS certificate for a host and port.", ("Inspect certificate subject and issuer", "Check TLS version and cipher details")),
    ("osint_tools", "http_headers"): _item("HTTP Headers", "Network", "Retrieve HTTP response headers for a URL and assess security-related headers.", ("Inspect server and content headers", "Review common security headers")),
    ("osint_tools", "subdomain_enumerate"): _item("Subdomain Enumerate", "OSINT", "Find subdomains from Certificate Transparency logs through crt.sh.", ("Discover certificate-listed subdomains", "Review names associated with a domain")),
    ("osint_tools", "email_security_check"): _item("Email Security", "OSINT", "Check a domain's email-security DNS configuration.", ("Review SPF and DMARC records", "Check DKIM selector records")),

    ("free_osint_tools", "openphish_lookup"): _item("OpenPhish Check", "OSINT", "Check whether a URL appears in the OpenPhish phishing feed.", ("Check a suspicious URL", "Review matching phishing URLs")),
    ("free_osint_tools", "crtsh_subdomain_search"): _item("crt.sh Subdomains", "OSINT", "Discover subdomains through Certificate Transparency data from crt.sh.", ("Search certificates for a domain", "List certificate names and subdomains")),
    ("free_osint_tools", "shodan_internetdb_lookup"): _item("Shodan InternetDB", "OSINT", "Query Shodan InternetDB for exposed services and host information without an API key.", ("Review exposed ports for an IP", "Inspect hostnames, CPEs, and vulnerabilities")),
    ("free_osint_tools", "ransomwatch_check"): _item("RansomWatch Check", "Threat Intel", "Check ransomware-group activity and recent victims from Ransomwatch.", ("Search for a ransomware group", "Review matching victim information")),
    ("free_osint_tools", "malpedia_malware_search"): _item("Malpedia Search", "Malware", "Search Malpedia for information about a malware family.", ("Search a malware family name", "Review matching family metadata")),
    ("free_osint_tools", "circl_misp_feed_check"): _item("CIRCL MISP Feed", "Threat Intel", "Check an IOC against CIRCL public threat feeds and lookup services.", ("Check an IP or hash", "Review known-file or feed context")),
    ("free_osint_tools", "darksearch_query"): _item("Ahmia Search", "OSINT", "Search public Ahmia.fi indexes for dark-web pages matching a query.", ("Search for a domain or keyword", "Review indexed result links")),
    ("free_osint_tools", "hudsonrock_check"): _item("HudsonRock Check", "Threat Intel", "Check whether a domain is associated with info-stealer compromises.", ("Check a corporate domain", "Review compromised-employee summary data")),
    ("free_osint_tools", "epss_top_exploited"): _item("EPSS Lookup", "Threat Intel", "Retrieve EPSS exploitation probability for a CVE or a list of highly scored CVEs.", ("Look up a CVE's EPSS score", "Review top exploited CVEs")),
    ("free_osint_tools", "typosquat_detect"): _item("Typosquat Detect", "OSINT", "Generate domain permutations and check which potential typosquats resolve.", ("Check lookalike domains", "Review resolving permutations")),
    ("free_osint_tools", "paste_site_search"): _item("Paste Search", "OSINT", "Search public paste and code indexes for a query.", ("Search for a domain or keyword", "Review matching public snippets")),

    ("network_tools", "parse_pcap"): _item("PCAP Analyzer", "Network", "Parse a PCAP or PCAPNG file and summarize captured packets.", ("Inspect packet counts and protocols", "Review source and destination activity")),
    ("network_tools", "analyze_zeek_logs"): _item("Zeek Analyzer", "Network", "Parse Zeek TSV logs and identify suspicious patterns.", ("Analyze a conn.log file", "Review parsed network events")),
    ("network_tools", "analyze_suricata_alerts"): _item("Suricata Alerts", "Network", "Parse Suricata EVE JSON logs and extract alert events.", ("Review Suricata alerts", "Summarize alert types and signatures")),
    ("network_tools", "dns_lookup"): _item("DNS Lookup", "Network", "Perform DNS lookups for the requested record types.", ("Resolve A, AAAA, MX, NS, or TXT records", "Compare DNS results for a domain")),
    ("network_tools", "whois_lookup"): _item("WHOIS Lookup", "Network", "Query WHOIS over the raw WHOIS protocol for a domain or IP address.", ("Inspect registrar and registration data", "Follow a referral WHOIS server")),
    ("network_tools", "geoip_lookup"): _item("IP Geolocation", "Network", "Perform a free IP geolocation lookup through ip-api.com.", ("Locate an IP address", "Review ISP, ASN, and organization fields")),
    ("network_tools", "port_check"): _item("Port Check", "Network", "Check selected ports on a host using socket connections.", ("Check common ports on a host", "Identify open or filtered ports")),
    ("network_tools", "analyze_network_iocs"): _item("Network IOC Extractor", "Network", "Extract IPs, domains, URLs, email addresses, and hashes from text.", ("Extract IOCs from an alert", "Summarize indicators by type")),

    ("malwoverview_tools", "malwoverview_hash_lookup"): _item("Hash Reputation", "Threat Intel", "Check a file hash against the malware-intelligence sources used by Malware Overview.", ("Check an MD5, SHA1, or SHA256", "Compare reputation-source results")),
    ("malwoverview_tools", "malwoverview_domain_check"): _item("Domain Reputation", "Threat Intel", "Check a domain against the free threat-intelligence sources used by Malware Overview.", ("Review domain reputation", "Compare URLhaus and ThreatFox context")),
    ("malwoverview_tools", "malwoverview_ip_check"): _item("IP Reputation", "Threat Intel", "Check an IP address against the free threat-intelligence sources used by Malware Overview.", ("Review IP reputation", "Compare tracker and blocklist context")),
    ("malwoverview_tools", "malwoverview_url_check"): _item("URL Reputation", "Threat Intel", "Check a URL against the free threat-intelligence sources used by Malware Overview.", ("Review URL reputation", "Compare malware-URL intelligence")),
    ("malwoverview_tools", "malwoverview_sample_download_info"): _item("Sample Information", "Malware", "Retrieve download information for a known malware sample hash.", ("Check sample availability", "Review sample download metadata")),
    ("malwoverview_tools", "malwoverview_triage"): _item("File Triage", "Malware", "Triage a local file by computing hashes and checking threat intelligence.", ("Triage a suspicious file", "Review hashes and reputation results")),
    ("malwoverview_tools", "malwoverview_yara_from_report"): _item("YARA Draft", "Malware", "Generate a basic YARA rule skeleton from analysis-report text.", ("Draft a rule from report IOCs", "Review extracted hashes and indicators")),

    ("forensics_tools", "file_metadata"): _item("File Metadata", "Forensics", "Extract metadata and basic file-identification information for forensic analysis.", ("Inspect a file's type and size", "Review timestamps and metadata")),
    ("forensics_tools", "carve_files"): _item("File Carving", "Forensics", "Carve embedded files from a binary using known magic-byte signatures.", ("Recover embedded files", "Review carved file types and offsets")),
    ("forensics_tools", "parse_windows_prefetch"): _item("Prefetch Parser", "Forensics", "Parse a Windows Prefetch file for execution and forensic details.", ("Inspect a program's prefetch record", "Review execution and file references")),
    ("forensics_tools", "parse_lnk_file"): _item("LNK Parser", "Forensics", "Parse a Windows shortcut file and extract its forensic fields.", ("Inspect a shortcut target", "Review path, timestamps, and link metadata")),
    ("forensics_tools", "timeline_csv_parse"): _item("Timeline Parser", "Forensics", "Parse forensic timeline CSV files such as Plaso or KAPE output.", ("Load a forensic timeline", "Review normalized event entries")),
    ("forensics_tools", "analyze_event_log"): _item("Event Log Analyzer", "Forensics", "Analyze exported Windows event logs in XML or CSV form.", ("Review exported event records", "Identify suspicious event entries")),
    ("forensics_tools", "string_analysis"): _item("String Analysis", "Forensics", "Extract and categorize strings from a binary file.", ("Extract ASCII and Unicode strings", "Find URLs, paths, and indicators")),
    ("forensics_tools", "search_logs"): _item("Log Search", "Forensics", "Search local log files or directories for IOC and keyword matches.", ("Search logs for an indicator", "Limit results to a time range")),
    ("forensics_tools", "mitre_attack_mapper"): _item("MITRE Mapper", "Forensics", "Map forensic findings to a capa-compatible MITRE ATT&CK summary.", ("Map findings to ATT&CK techniques", "Review mapped capabilities")),

    ("remnux_tools", "olevba_analyze"): _item("VBA Analyzer", "Malware", "Analyze Office documents for VBA macros using oletools.", ("Check a document for macros", "Review suspicious VBA keywords")),
    ("remnux_tools", "rtfobj_analyze"): _item("RTF Analyzer", "Malware", "Analyze RTF files for embedded objects and exploit indicators.", ("Inspect RTF objects", "Review exploit-related indicators")),
    ("remnux_tools", "pe_analyze"): _item("PE Analyzer", "Malware", "Analyze the structure and suspicious indicators of a Portable Executable.", ("Inspect PE headers and sections", "Review imports and suspicious indicators")),
    ("remnux_tools", "yara_scan"): _item("YARA Scanner", "Malware", "Scan a file with a YARA rules file for malware-pattern matches.", ("Scan a file with local rules", "Review matching rule names")),
    ("remnux_tools", "hash_file"): _item("Hash Calculator", "Forensics", "Calculate multiple cryptographic hashes for a file.", ("Calculate MD5, SHA1, and SHA256", "Compare a file hash with intelligence")),
    ("remnux_tools", "file_entropy"): _item("Entropy Analyzer", "Malware", "Calculate Shannon entropy for a file and its PE sections when applicable.", ("Measure overall file entropy", "Review PE-section entropy")),
    ("remnux_tools", "oleobj_extract"): _item("OLE Extractor", "Malware", "Extract embedded objects from OLE files and Office documents.", ("Inspect embedded OLE objects", "Review extraction warnings")),

    ("threat_intel_tools", "urlhaus_lookup"): _item("URLhaus Lookup", "Threat Intel", "Look up a URL, domain, or IP in URLhaus.", ("Check a suspicious URL", "Review malware-distribution context")),
    ("threat_intel_tools", "malwarebazaar_hash_lookup"): _item("MalwareBazaar Lookup", "Threat Intel", "Look up a file hash in MalwareBazaar.", ("Check a sample hash", "Review malware sample metadata")),
    ("threat_intel_tools", "threatfox_ioc_lookup"): _item("ThreatFox Lookup", "Threat Intel", "Search ThreatFox for information about an indicator of compromise.", ("Check an IP, domain, URL, or hash", "Review IOC tags and malware context")),
    ("threat_intel_tools", "feodo_tracker_check"): _item("Feodo Check", "Threat Intel", "Check whether an IP is listed as a botnet C2 server in Feodo Tracker.", ("Check an IP for botnet C2 activity", "Review tracker status")),
    ("threat_intel_tools", "tor_exit_node_check"): _item("Tor Exit Check", "Threat Intel", "Check whether an IP address is a known Tor exit node.", ("Check an IP against the Tor list", "Review the current exit-node count")),
    ("threat_intel_tools", "blocklist_check"): _item("Blocklist Check", "Threat Intel", "Check an IP address against multiple free blocklists.", ("Check an IP for blocklist hits", "Review findings and risk level")),
    ("threat_intel_tools", "recent_malware_samples"): _item("Recent Malware", "Threat Intel", "Retrieve recent malware samples from MalwareBazaar.", ("Review recently submitted samples", "Inspect recent sample metadata")),
    ("threat_intel_tools", "threatfox_recent_iocs"): _item("Recent IOCs", "Threat Intel", "Retrieve recent indicators from ThreatFox.", ("Review recent IOCs", "Limit results by age and count")),

    ("remote_tools", "system_info_collect"): _item("System Information", "Forensics", "Collect system information from an allowlisted, host-key-pinned target.", ("Collect remote host details", "Review operating-system information")),
    ("remote_tools", "process_list_collect"): _item("Process List", "Forensics", "Collect the process list from an allowlisted, host-key-pinned target.", ("Review running processes", "Investigate a remote process list")),
    ("remote_tools", "netstat_collect"): _item("Network Connections", "Network", "Collect network connections from an allowlisted, pinned target.", ("Review remote listening ports", "Inspect active connections")),
    ("remote_tools", "event_log_collect"): _item("Remote Event Log", "Forensics", "Collect journal events from an allowlisted, host-key-pinned target.", ("Collect remote events", "Limit events to a time range")),
    ("remote_tools", "autoruns_check"): _item("Autoruns Check", "Forensics", "Collect persistence mechanisms from an allowlisted, pinned target.", ("Review remote autoruns", "Investigate persistence entries")),
}


def fallback_presentation(raw_tool_name: str, category: str = "") -> MCPToolPresentation:
    """Build safe UI metadata for a newly discovered, unmapped tool."""
    ui_category = _INTERNAL_CATEGORY_TO_UI.get(category, "Malware")
    display_name = str(raw_tool_name or "Tool").replace("_", " ").title()
    return _item(
        display_name,
        ui_category,
        "Tool description is not available from the registered metadata.",
        ("Open the technical tool details",),
    )


def get_mcp_tool_presentation(
    server_name: str,
    raw_tool_name: str,
    category: str = "",
) -> MCPToolPresentation:
    """Return explicit metadata, with a deterministic UI-only fallback."""
    return MCP_TOOL_PRESENTATION.get(
        (str(server_name), str(raw_tool_name)),
        fallback_presentation(raw_tool_name, category),
    )
