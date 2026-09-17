"""Static, fail-closed classification for the MCP tools we operate.

MCP servers are not trusted to describe their own authorization properties.
The discovery layer keeps only the ordinary MCP schema and overlays this
allowlist.  A tool absent from it is deliberately classified as dangerous and
therefore is not available to Threat Hunters.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MCPToolClassification:
    category: str
    is_dangerous: bool = False
    requires_approval: bool = False


UNCLASSIFIED_MCP_TOOL = MCPToolClassification(
    category="mcp_unclassified",
    is_dangerous=True,
    requires_approval=True,
)


# Explicit tool names are intentional: a newly exposed server tool must be
# reviewed and classified before a Threat Hunter can discover or execute it.
MCP_TOOL_CLASSIFICATIONS: dict[tuple[str, str], MCPToolClassification] = {}


def _add(server: str, category: str, names: tuple[str, ...], *,
         dangerous: bool = False, approval: bool = False) -> None:
    classification = MCPToolClassification(category, dangerous, approval)
    for name in names:
        MCP_TOOL_CLASSIFICATIONS[(server, name)] = classification


OSINT_TOOLS = (
    "whois_lookup", "dns_resolve", "geoip_lookup", "reverse_dns",
    "ssl_certificate_info", "http_headers", "subdomain_enumerate",
    "email_security_check",
)
_add("osint_tools", "osint", OSINT_TOOLS)
_add("free_osint_tools", "osint", (
    "openphish_lookup", "crtsh_subdomain_search", "shodan_internetdb_lookup",
    "ransomwatch_check", "malpedia_malware_search", "circl_misp_feed_check",
    "darksearch_query", "hudsonrock_check", "epss_top_exploited",
    "typosquat_detect", "paste_site_search",
))
_add("network_tools", "network", (
    "parse_pcap", "analyze_zeek_logs", "analyze_suricata_alerts", "dns_lookup",
    "whois_lookup", "geoip_lookup", "port_check", "analyze_network_iocs",
))
_add("malwoverview_tools", "threat_intel", (
    "malwoverview_hash_lookup", "malwoverview_domain_check",
    "malwoverview_ip_check", "malwoverview_url_check",
    "malwoverview_sample_download_info", "malwoverview_yara_from_report",
))
_add("malwoverview_tools", "analysis", ("malwoverview_triage",))
_add("forensics_tools", "forensics", (
    "file_metadata", "carve_files", "parse_windows_prefetch", "parse_lnk_file",
    "timeline_csv_parse", "analyze_event_log", "string_analysis", "search_logs",
    "mitre_attack_mapper",
))
_add("remnux_tools", "analysis", (
    "olevba_analyze", "rtfobj_analyze", "pe_analyze", "yara_scan", "hash_file",
    "file_entropy", "oleobj_extract",
))
_add("threat_intel_tools", "threat_intel", (
    "urlhaus_lookup", "malwarebazaar_hash_lookup", "threatfox_ioc_lookup",
    "feodo_tracker_check", "tor_exit_node_check", "blocklist_check",
    "recent_malware_samples", "threatfox_recent_iocs",
))
_add("remote_tools", "forensics", (
    "system_info_collect", "process_list_collect", "netstat_collect",
    "event_log_collect", "autoruns_check",
), dangerous=True, approval=True)


SERVER_CATEGORIES = {
    "osint_tools": "osint",
    "free_osint_tools": "osint",
    "network_tools": "network",
    "malwoverview_tools": "threat_intel",
    "forensics_tools": "forensics",
    "remnux_tools": "analysis",
    "threat_intel_tools": "threat_intel",
    "remote_tools": "forensics",
}


def classify_mcp_tool(server_name: str, tool_name: str) -> dict[str, Any]:
    """Return a copy-safe classification, defaulting to dangerous."""
    classification = MCP_TOOL_CLASSIFICATIONS.get(
        (str(server_name), str(tool_name)), UNCLASSIFIED_MCP_TOOL
    )
    return {
        "category": classification.category,
        "is_dangerous": classification.is_dangerous,
        "requires_approval": classification.requires_approval,
    }


def decorate_mcp_tool(server_name: str, tool: dict[str, Any]) -> dict[str, Any]:
    """Keep safe discovery fields and overlay trusted static metadata."""
    name = tool.get("name", "") if isinstance(tool, dict) else ""
    decorated = {
        "name": name,
        "description": tool.get("description", "") if isinstance(tool, dict) else "",
        "inputSchema": tool.get("inputSchema", tool.get("parameters", {}))
        if isinstance(tool, dict) else {},
    }
    decorated.update(classify_mcp_tool(server_name, name))
    return decorated
