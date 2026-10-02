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


def _item(display_name: str, ui_category: str) -> MCPToolPresentation:
    return MCPToolPresentation(
        display_name=display_name,
        ui_category=ui_category,
        icon=UI_CATEGORY_ICONS[ui_category],
    )


# Every registered tool in the eight configured MCP servers has an explicit
# entry.  Keep this keyed by the raw MCP name, not the registry's server.name
# identifier, so presentation metadata cannot affect dispatch or persistence.
MCP_TOOL_PRESENTATION: dict[tuple[str, str], MCPToolPresentation] = {
    ("osint_tools", "whois_lookup"): _item("WHOIS Lookup", "OSINT"),
    ("osint_tools", "dns_resolve"): _item("DNS Resolve", "Network"),
    ("osint_tools", "geoip_lookup"): _item("IP Geolocation", "OSINT"),
    ("osint_tools", "reverse_dns"): _item("Reverse DNS", "Network"),
    ("osint_tools", "ssl_certificate_info"): _item("SSL Certificate", "Network"),
    ("osint_tools", "http_headers"): _item("HTTP Headers", "Network"),
    ("osint_tools", "subdomain_enumerate"): _item("Subdomain Enumerate", "OSINT"),
    ("osint_tools", "email_security_check"): _item("Email Security", "OSINT"),

    ("free_osint_tools", "openphish_lookup"): _item("OpenPhish Check", "OSINT"),
    ("free_osint_tools", "crtsh_subdomain_search"): _item("crt.sh Subdomains", "OSINT"),
    ("free_osint_tools", "shodan_internetdb_lookup"): _item("Shodan InternetDB", "OSINT"),
    ("free_osint_tools", "ransomwatch_check"): _item("RansomWatch Check", "Threat Intel"),
    ("free_osint_tools", "malpedia_malware_search"): _item("Malpedia Search", "Malware"),
    ("free_osint_tools", "circl_misp_feed_check"): _item("CIRCL MISP Feed", "Threat Intel"),
    ("free_osint_tools", "darksearch_query"): _item("Ahmia Search", "OSINT"),
    ("free_osint_tools", "hudsonrock_check"): _item("HudsonRock Check", "Threat Intel"),
    ("free_osint_tools", "epss_top_exploited"): _item("EPSS Lookup", "Threat Intel"),
    ("free_osint_tools", "typosquat_detect"): _item("Typosquat Detect", "OSINT"),
    ("free_osint_tools", "paste_site_search"): _item("Paste Search", "OSINT"),

    ("network_tools", "parse_pcap"): _item("PCAP Analyzer", "Network"),
    ("network_tools", "analyze_zeek_logs"): _item("Zeek Analyzer", "Network"),
    ("network_tools", "analyze_suricata_alerts"): _item("Suricata Alerts", "Network"),
    ("network_tools", "dns_lookup"): _item("DNS Lookup", "Network"),
    ("network_tools", "whois_lookup"): _item("WHOIS Lookup", "Network"),
    ("network_tools", "geoip_lookup"): _item("IP Geolocation", "Network"),
    ("network_tools", "port_check"): _item("Port Check", "Network"),
    ("network_tools", "analyze_network_iocs"): _item("Network IOC Extractor", "Network"),

    ("malwoverview_tools", "malwoverview_hash_lookup"): _item("Hash Reputation", "Threat Intel"),
    ("malwoverview_tools", "malwoverview_domain_check"): _item("Domain Reputation", "Threat Intel"),
    ("malwoverview_tools", "malwoverview_ip_check"): _item("IP Reputation", "Threat Intel"),
    ("malwoverview_tools", "malwoverview_url_check"): _item("URL Reputation", "Threat Intel"),
    ("malwoverview_tools", "malwoverview_sample_download_info"): _item("Sample Information", "Malware"),
    ("malwoverview_tools", "malwoverview_triage"): _item("File Triage", "Malware"),
    ("malwoverview_tools", "malwoverview_yara_from_report"): _item("YARA Draft", "Malware"),

    ("forensics_tools", "file_metadata"): _item("File Metadata", "Forensics"),
    ("forensics_tools", "carve_files"): _item("File Carving", "Forensics"),
    ("forensics_tools", "parse_windows_prefetch"): _item("Prefetch Parser", "Forensics"),
    ("forensics_tools", "parse_lnk_file"): _item("LNK Parser", "Forensics"),
    ("forensics_tools", "timeline_csv_parse"): _item("Timeline Parser", "Forensics"),
    ("forensics_tools", "analyze_event_log"): _item("Event Log Analyzer", "Forensics"),
    ("forensics_tools", "string_analysis"): _item("String Analysis", "Forensics"),
    ("forensics_tools", "search_logs"): _item("Log Search", "Forensics"),
    ("forensics_tools", "mitre_attack_mapper"): _item("MITRE Mapper", "Forensics"),

    ("remnux_tools", "olevba_analyze"): _item("VBA Analyzer", "Malware"),
    ("remnux_tools", "rtfobj_analyze"): _item("RTF Analyzer", "Malware"),
    ("remnux_tools", "pe_analyze"): _item("PE Analyzer", "Malware"),
    ("remnux_tools", "yara_scan"): _item("YARA Scanner", "Malware"),
    ("remnux_tools", "hash_file"): _item("Hash Calculator", "Forensics"),
    ("remnux_tools", "file_entropy"): _item("Entropy Analyzer", "Malware"),
    ("remnux_tools", "oleobj_extract"): _item("OLE Extractor", "Malware"),

    ("threat_intel_tools", "urlhaus_lookup"): _item("URLhaus Lookup", "Threat Intel"),
    ("threat_intel_tools", "malwarebazaar_hash_lookup"): _item("MalwareBazaar Lookup", "Threat Intel"),
    ("threat_intel_tools", "threatfox_ioc_lookup"): _item("ThreatFox Lookup", "Threat Intel"),
    ("threat_intel_tools", "feodo_tracker_check"): _item("Feodo Check", "Threat Intel"),
    ("threat_intel_tools", "tor_exit_node_check"): _item("Tor Exit Check", "Threat Intel"),
    ("threat_intel_tools", "blocklist_check"): _item("Blocklist Check", "Threat Intel"),
    ("threat_intel_tools", "recent_malware_samples"): _item("Recent Malware", "Threat Intel"),
    ("threat_intel_tools", "threatfox_recent_iocs"): _item("Recent IOCs", "Threat Intel"),

    ("remote_tools", "system_info_collect"): _item("System Information", "Forensics"),
    ("remote_tools", "process_list_collect"): _item("Process List", "Forensics"),
    ("remote_tools", "netstat_collect"): _item("Network Connections", "Network"),
    ("remote_tools", "event_log_collect"): _item("Remote Event Log", "Forensics"),
    ("remote_tools", "autoruns_check"): _item("Autoruns Check", "Forensics"),
}


def fallback_presentation(raw_tool_name: str, category: str = "") -> MCPToolPresentation:
    """Build safe UI metadata for a newly discovered, unmapped tool."""
    ui_category = _INTERNAL_CATEGORY_TO_UI.get(category, "Malware")
    display_name = str(raw_tool_name or "Tool").replace("_", " ").title()
    return _item(display_name, ui_category)


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
