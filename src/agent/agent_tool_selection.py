"""
Tool selection helpers for the agent loop: filtering the tool list sent to
the LLM, guessing a first tool/params from the investigation goal, building
prompt blocks, and auto-enrichment tool selection.
"""

import logging
import re
from typing import List

logger = logging.getLogger(__name__)


class ToolSelector:
    """Encapsulates tool-filtering and prompt-block-building logic."""

    def __init__(self, tools, playbook_engine=None):
        self.tools = tools
        self.playbook_engine = playbook_engine

    def filter_tools_for_goal(
        self, all_tools: List[dict], goal: str, state,
    ) -> List[dict]:
        """Return a filtered subset of tools relevant to the investigation goal.

        Small LLMs (8B-14B) can't handle 90+ tool definitions effectively.
        We keep all 10 local tools + the most relevant MCP tools, capped
        at ~30 total to stay within the model's effective context.
        """
        MAX_TOOLS = 30
        goal_lower = goal.lower()

        # Always include all local tools (10)
        local_tools = [
            t for t in all_tools
            if not t.get('function', {}).get('name', '').count('.')
        ]

        # Categorize MCP tools by relevance to the goal
        mcp_tools = [
            t for t in all_tools
            if t.get('function', {}).get('name', '').count('.')
        ]

        if len(local_tools) + len(mcp_tools) <= MAX_TOOLS:
            return all_tools  # Small enough, send all

        # Score MCP tools by relevance
        is_ip = any(kw in goal_lower for kw in ('ip', 'address', '185.', '10.', '192.'))
        is_domain = any(kw in goal_lower for kw in ('domain', 'dns', '.com', '.org', '.net'))
        is_file = any(kw in goal_lower for kw in ('file', 'malware', 'exe', 'dll', 'binary', 'sample', 'pe '))
        is_email = any(kw in goal_lower for kw in ('email', 'eml', 'phish'))
        is_url = any(kw in goal_lower for kw in ('url', 'http', 'link'))
        is_hash = any(kw in goal_lower for kw in ('hash', 'sha256', 'md5', 'sha1'))
        is_vuln = any(kw in goal_lower for kw in ('cve', 'vuln', 'exploit'))

        # [FIX] Define relevant server prefixes per category — must match
        # the *actual* connected MCP server names (see /api/mcp/servers),
        # not the placeholder names from the original scaffold.
        ioc_servers = {
            'threat_intel_tools',
        }
        file_servers = {
            'remnux_tools',
        }
        email_servers = {
            'remnux_tools',  # olevba_analyze / rtfobj_analyze for attachments
        }
        vuln_servers: set = set()  # no vulnerability MCP server connected yet

        # Build set of wanted server prefixes
        wanted = set()
        if is_ip or is_domain or is_url:
            wanted |= ioc_servers
        if is_file or is_hash:
            wanted |= file_servers
        if is_email:
            wanted |= email_servers
        if is_vuln:
            wanted |= vuln_servers
        # If nothing specific, include the most useful general ones
        if not wanted:
            wanted = ioc_servers

        # Filter MCP tools
        relevant_mcp = []
        other_mcp = []
        for t in mcp_tools:
            name = t.get('function', {}).get('name', '')
            server = name.split('.')[0] if '.' in name else ''
            if server in wanted:
                relevant_mcp.append(t)
            else:
                other_mcp.append(t)

        # Fill remaining slots with other MCP tools
        remaining = MAX_TOOLS - len(local_tools) - len(relevant_mcp)
        selected = local_tools + relevant_mcp
        if remaining > 0:
            selected += other_mcp[:remaining]

        logger.info(
            "[AGENT] Filtered tools: %d local + %d relevant MCP + %d other = %d total "
            "(from %d available)",
            len(local_tools), len(relevant_mcp),
            min(remaining, len(other_mcp)) if remaining > 0 else 0,
            len(selected), len(all_tools),
        )
        return selected

    def get_enrichment_mcp_tools(
        self, primary_tool: str, params: dict, goal: str,
    ) -> List[tuple]:
        """Return a list of (mcp_tool_name, params) for auto-enrichment.

        After the primary local tool runs, these MCP tools provide
        additional context without relying on the LLM to pick them.

        [FIX] Tool names now match the actually-connected MCP servers
        (threat_intel_tools, remnux_tools) instead of placeholder names
        that never resolved to a registered tool.
        """
        import re
        result = []

        if primary_tool == 'investigate_ioc':
            ioc_val = params.get('ioc', '')
            # Check if it's an IP
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc_val):
                result.extend([
                    ('threat_intel_tools.blocklist_check', {'ip': ioc_val}),
                    ('threat_intel_tools.feodo_tracker_check', {'ip': ioc_val}),
                    ('threat_intel_tools.tor_exit_node_check', {'ip': ioc_val}),
                    ('threat_intel_tools.threatfox_ioc_lookup', {'indicator': ioc_val}),
                ])
            elif re.match(r'[a-zA-Z0-9]', ioc_val) and '.' in ioc_val:
                # Domain / URL
                result.extend([
                    ('threat_intel_tools.urlhaus_lookup', {'indicator': ioc_val}),
                    ('threat_intel_tools.threatfox_ioc_lookup', {'indicator': ioc_val}),
                ])
            elif re.match(r'^[a-fA-F0-9]{32,64}$', ioc_val):
                # Hash
                result.extend([
                    ('threat_intel_tools.malwarebazaar_hash_lookup', {'hash_value': ioc_val}),
                    ('threat_intel_tools.threatfox_ioc_lookup', {'indicator': ioc_val}),
                ])

        elif primary_tool == 'analyze_malware':
            file_path = params.get('file_path', params.get('ioc', ''))
            if file_path:
                result.extend([
                    ('remnux_tools.hash_file', {'file_path': file_path}),
                    ('remnux_tools.file_entropy', {'file_path': file_path}),
                    ('remnux_tools.pe_analyze', {'file_path': file_path}),
                    ('remnux_tools.yara_scan', {'file_path': file_path}),
                ])

        elif primary_tool == 'analyze_email':
            file_path = params.get('file_path', params.get('eml_path', ''))
            # Extract IOCs from goal for enrichment
            ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', goal)
            if file_path:
                if file_path.lower().endswith(('.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm')):
                    result.append(
                        ('remnux_tools.olevba_analyze', {'file_path': file_path}),
                    )
                elif file_path.lower().endswith('.rtf'):
                    result.append(
                        ('remnux_tools.rtfobj_analyze', {'file_path': file_path}),
                    )
            if ip_match:
                result.append(
                    ('threat_intel_tools.blocklist_check', {'ip': ip_match.group(1)}),
                )

        # Only include MCP tools that are actually registered
        available = []
        for tool_name, tool_params in result:
            if self.tools.get_tool(tool_name) is not None:
                available.append((tool_name, tool_params))
        return available[:4]  # Max 4 enrichment calls

    def guess_first_tool(self, goal: str) -> str:
        """Pick the most appropriate tool name based on the investigation goal."""
        goal_lower = goal.lower()

        # File / malware analysis keywords
        if any(kw in goal_lower for kw in ('file', 'malware', 'sample', 'binary',
                                            'exe', 'dll', 'pdf', 'macro', '.eml')):
            if any(kw in goal_lower for kw in ('.eml', 'email', 'phish')):
                return 'analyze_email'
            return 'analyze_malware'

        # Default: treat as IOC investigation
        return 'investigate_ioc'

    def guess_tool_params(self, goal: str) -> dict:
        """Extract the most likely tool parameter from the goal text."""
        import re

        tool = self.guess_first_tool(goal)

        # Try to extract a file path first (for file/email analysis)
        path_match = re.search(r'([A-Z]:[/\\][\w/\\.\- ]+|/[\w/.\- ]+)', goal)
        if path_match:
            path_val = path_match.group(1)
            if tool in ('analyze_malware', 'analyze_email'):
                return {"file_path": path_val}
            return {"ioc": path_val}

        # Try to extract an IP address
        ip_match = re.search(
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', goal,
        )
        if ip_match:
            return {"ioc": ip_match.group(1)}

        # Try to extract a domain
        domain_match = re.search(
            r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b',
            goal,
        )
        if domain_match:
            candidate = domain_match.group(1)
            # Filter out common non-domain words
            if '.' in candidate and candidate.lower() not in ('e.g', 'i.e', 'vs.'):
                return {"ioc": candidate}

        # Try to extract a hash (MD5/SHA1/SHA256)
        hash_match = re.search(r'\b([a-fA-F0-9]{32,64})\b', goal)
        if hash_match:
            return {"ioc": hash_match.group(1)}

        # Try to extract a URL
        url_match = re.search(r'(https?://\S+)', goal)
        if url_match:
            return {"ioc": url_match.group(1)}

        # Fallback: use the full goal text as input
        return {"ioc": goal}

    def build_tools_block(self) -> str:
        """Format registered tools into a readable list for the prompt."""
        lines = []
        for td in self.tools.list_tools():
            approval_tag = " [REQUIRES APPROVAL]" if td.requires_approval else ""
            params_desc = ", ".join(
                f"{k}: {v.get('type', 'any')}"
                for k, v in td.parameters.get("properties", {}).items()
            )
            lines.append(
                f"- {td.name}({params_desc}){approval_tag}: {td.description}"
            )
        return "\n".join(lines) if lines else "(no tools registered)"

    def build_playbooks_block(self) -> str:
        """Format available playbooks into a readable list for the prompt."""
        if self.playbook_engine is None:
            return ""
        try:
            playbooks = self.playbook_engine.list_playbooks()
            if not playbooks:
                return ""
            lines = ["Available playbooks (use run_playbook action to execute):"]
            for pb in playbooks:
                step_count = pb.get('step_count', 0)
                desc = pb.get('description', '')
                if len(desc) > 120:
                    desc = desc[:120] + "..."
                lines.append(f"- {pb['id']} ({step_count} steps): {desc}")
            return "\n".join(lines)
        except Exception:
            return ""

    @staticmethod
    def build_findings_block(state) -> str:
        """Summarise findings so far (capped to keep context manageable)."""
        import json
        if not state.findings:
            return "(none yet)"
        # Show last 10 findings to avoid blowing up context window
        recent = state.findings[-10:]
        parts = []
        for i, f in enumerate(recent):
            preview = json.dumps(f, default=str)
            if len(preview) > 600:
                preview = preview[:600] + "..."
            parts.append(f"[{f.get('step', i)}] {preview}")
        return "\n".join(parts)

    @staticmethod
    def has_successful_evidence(state) -> bool:
        """True if at least one tool_result finding succeeded (no 'error' key)."""
        for f in state.findings:
            if f.get("type") == "tool_result":
                result = f.get("result", {})
                if isinstance(result, dict) and not result.get("error"):
                    return True
        return False
