"""
Tool Registry - Unified registry for local analysis tools and remote MCP tools.

Each tool is described by a ToolDefinition (JSON-schema parameters, source, category)
and optionally backed by a local async executor function.
"""

import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------- #
#  Simulated Containment Actions (P0.1)
#
#  These are demo/proof-of-concept stand-ins for real EDR/firewall
#  integrations. They never touch the network or host stack - each one
#  only appends a JSON record to a local file under data/simulated_actions/.
# ---------------------------------------------------------------------- #

_SIMULATED_ACTIONS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "simulated_actions"


def _append_json_record(file_path: Path, record: Dict[str, Any]) -> None:
    """Append *record* to the JSON array stored at *file_path* (create if missing)."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    records: List[Dict[str, Any]] = []
    if file_path.exists():
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, list):
                records = loaded
        except (json.JSONDecodeError, OSError):
            records = []
    records.append(record)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, default=str)


async def isolate_device(device_id: str, isolation_type: str = "network", **_kw) -> Dict[str, Any]:
    """SIMULATED ACTION — ไม่ใช่ EDR/firewall integration จริง เขียน record ลง local JSON เท่านั้น สำหรับ demo/proof-of-concept

    Simulate isolating a device/host from the network. Appends a record to
    data/simulated_actions/isolated_devices.json.
    """
    try:
        record = {
            "device_id": device_id,
            "isolation_type": isolation_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        out_file = _SIMULATED_ACTIONS_DIR / "isolated_devices.json"
        _append_json_record(out_file, record)
        return {
            "status": "success",
            "simulated": True,
            "message": f"Simulated isolation of device '{device_id}' recorded.",
            "record": record,
            "record_file": str(out_file),
        }
    except Exception as exc:
        logger.error(f"[TOOLS] isolate_device failed: {exc}", exc_info=True)
        return {"status": "error", "simulated": True, "error": str(exc)}


async def block_ip(ip_address: str, reason: str = "", **_kw) -> Dict[str, Any]:
    """SIMULATED ACTION — ไม่ใช่ EDR/firewall integration จริง เขียน record ลง local JSON เท่านั้น สำหรับ demo/proof-of-concept

    Simulate blocking an IP address at the perimeter. Appends a record to
    data/simulated_actions/blocklist.json.
    """
    try:
        record = {
            "ip_address": ip_address,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        out_file = _SIMULATED_ACTIONS_DIR / "blocklist.json"
        _append_json_record(out_file, record)
        return {
            "status": "success",
            "simulated": True,
            "message": f"Simulated block of IP '{ip_address}' recorded.",
            "record": record,
            "record_file": str(out_file),
        }
    except Exception as exc:
        logger.error(f"[TOOLS] block_ip failed: {exc}", exc_info=True)
        return {"status": "error", "simulated": True, "error": str(exc)}


async def quarantine_file(file_path: str, **_kw) -> Dict[str, Any]:
    """SIMULATED ACTION — ไม่ใช่ EDR/firewall integration จริง เขียน record ลง local JSON เท่านั้น สำหรับ demo/proof-of-concept

    Simulate quarantining a file: copies (never moves) it into
    data/simulated_actions/quarantine/ and records metadata to
    data/simulated_actions/quarantine_log.json. If *file_path* does not
    exist on disk (common when it comes from an IOC rather than a real
    local path), records "simulated, source file not found" instead of
    raising.
    """
    try:
        quarantine_dir = _SIMULATED_ACTIONS_DIR / "quarantine"
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        log_file = _SIMULATED_ACTIONS_DIR / "quarantine_log.json"

        source = Path(file_path)
        if source.is_file():
            dest = quarantine_dir / source.name
            shutil.copy2(str(source), str(dest))
            record = {
                "file_path": file_path,
                "quarantined_path": str(dest),
                "note": "simulated, file copied to quarantine",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        else:
            record = {
                "file_path": file_path,
                "quarantined_path": None,
                "note": "simulated, source file not found",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        _append_json_record(log_file, record)
        return {
            "status": "success",
            "simulated": True,
            "message": record["note"],
            "record": record,
            "record_file": str(log_file),
        }
    except Exception as exc:
        logger.error(f"[TOOLS] quarantine_file failed: {exc}", exc_info=True)
        return {"status": "error", "simulated": True, "error": str(exc)}


@dataclass
class ToolDefinition:
    """Schema for a single tool available to the agent."""

    name: str                           # e.g. "investigate_ioc" or "remnux.analyze_file"
    description: str
    parameters: Dict[str, Any]          # JSON Schema for the params
    source: str                         # "local" or MCP server name
    category: str                       # analysis, threat_intel, sandbox, forensics, edr, re
    requires_approval: bool = False
    is_dangerous: bool = False          # If True, should run in sandbox

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "source": self.source,
            "category": self.category,
            "requires_approval": self.requires_approval,
            "is_dangerous": self.is_dangerous,
        }


class ToolRegistry:
    """Hold local + MCP tools and their executors."""

    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._executors: Dict[str, Callable[..., Coroutine]] = {}

    # ------------------------------------------------------------------ #
    #  Registration
    # ------------------------------------------------------------------ #

    def register_local_tool(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        category: str,
        executor: Callable[..., Coroutine],
        requires_approval: bool = False,
        is_dangerous: bool = False,
    ) -> None:
        """Register a local async tool executor."""
        td = ToolDefinition(
            name=name,
            description=description,
            parameters=parameters,
            source="local",
            category=category,
            requires_approval=requires_approval,
            is_dangerous=is_dangerous,
        )
        self._tools[name] = td
        self._executors[name] = executor
        logger.debug(f"[TOOLS] Registered local tool: {name} ({category})")

    def register_mcp_tools(
        self, server_name: str, tools_list: List[Dict[str, Any]],
    ) -> None:
        """Bulk-register tools discovered from an MCP server's list_tools response."""
        for t in tools_list:
            tool_name = f"{server_name}.{t['name']}"
            td = ToolDefinition(
                name=tool_name,
                description=t.get("description", ""),
                parameters=t.get("inputSchema", t.get("parameters", {})),
                source=server_name,
                category=t.get("category", "mcp"),
                requires_approval=t.get("requires_approval", False),
                is_dangerous=t.get("is_dangerous", False),
            )
            self._tools[tool_name] = td

        logger.info(
            f"[TOOLS] Registered {len(tools_list)} tools from MCP server: {server_name}"
        )

    def unregister_server(self, server_name: str) -> int:
        """Remove every tool that belongs to *server_name*. Returns count removed."""
        to_remove = [
            name for name, td in self._tools.items()
            if td.source == server_name
        ]
        for name in to_remove:
            del self._tools[name]
            self._executors.pop(name, None)
        logger.info(f"[TOOLS] Unregistered {len(to_remove)} tools from {server_name}")
        return len(to_remove)

    # ------------------------------------------------------------------ #
    #  Lookup
    # ------------------------------------------------------------------ #

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def list_tools(
        self,
        category: Optional[str] = None,
        source: Optional[str] = None,
    ) -> List[ToolDefinition]:
        """Return tools filtered by category and/or source."""
        result = list(self._tools.values())
        if category:
            result = [t for t in result if t.category == category]
        if source:
            result = [t for t in result if t.source == source]
        return result

    def get_tools_for_llm(self) -> List[Dict[str, Any]]:
        """Return tool definitions formatted for LLM tool_use / function calling."""
        out: List[Dict[str, Any]] = []
        for td in self._tools.values():
            out.append({
                "type": "function",
                "function": {
                    "name": td.name,
                    "description": td.description + (
                        " [REQUIRES APPROVAL]" if td.requires_approval else ""
                    ),
                    "parameters": td.parameters,
                },
            })
        return out

    # ------------------------------------------------------------------ #
    #  Execution
    # ------------------------------------------------------------------ #

    async def execute_local_tool(self, name: str, **kwargs) -> Dict[str, Any]:
        """Execute a registered local tool by name. Returns result dict.

        Performs intelligent parameter mapping: if the executor's required
        parameters are missing from *kwargs*, attempts to infer them from
        the first available value (handles LLM sending ``value`` instead of
        ``ioc``, etc.).
        """
        executor = self._executors.get(name)
        if executor is None:
            return {"error": f"No local executor for tool: {name}"}
        try:
            import inspect
            sig = inspect.signature(executor)
            mapped_kwargs = dict(kwargs)

            logger.info(
                f"[TOOLS] execute_local_tool('{name}') called with kwargs keys: "
                f"{list(kwargs.keys())} values: {kwargs}"
            )

            # ---- Strategy 0: unwrap nested 'params' dict ----
            # Sometimes the LLM stuffs the decision JSON into tool args:
            #   {"params": {"ioc": "..."}, "action": "use_tool", ...}
            if 'params' in mapped_kwargs and isinstance(mapped_kwargs['params'], dict):
                nested = mapped_kwargs['params']
                # Check if 'params' isn't actually a tool parameter
                if 'params' not in sig.parameters or any(
                    k in mapped_kwargs for k in ('action', 'tool', 'reasoning')
                ):
                    logger.info(f"[TOOLS] Unwrapping nested params for {name}: {nested}")
                    # Remove decision-level keys
                    for k in ('action', 'tool', 'reasoning', 'params'):
                        mapped_kwargs.pop(k, None)
                    # Merge the real params
                    mapped_kwargs.update(nested)

            # ---- smart parameter mapping ----
            # Comprehensive alias pool: covers all common names LLMs use
            alias_pool = [
                'value', 'input', 'query', 'target', 'indicator', 'data',
                'ip', 'ip_address', 'address', 'domain', 'url', 'hash',
                'ioc_value', 'host', 'hostname', 'file', 'path', 'text_input',
                'email', 'content', 'findings', 'result',
            ]

            # Collect required params that are missing
            missing_required = []
            for param_name, param in sig.parameters.items():
                if param_name in ('self', '_kw'):
                    continue
                if param.kind == inspect.Parameter.VAR_KEYWORD:
                    continue
                if param_name not in mapped_kwargs and param.default is inspect.Parameter.empty:
                    missing_required.append(param_name)

            for param_name in missing_required:
                # Strategy 1: try alias pool
                found = False
                for alias in alias_pool:
                    if alias in mapped_kwargs:
                        mapped_kwargs[param_name] = mapped_kwargs.pop(alias)
                        logger.info(
                            f"[TOOLS] Mapped '{alias}' -> '{param_name}' for {name}"
                        )
                        found = True
                        break

                if found:
                    continue

                # Strategy 2: if exactly one kwarg remains, use its value
                non_kw = {
                    k: v for k, v in mapped_kwargs.items()
                    if k not in ('_kw',) and k not in [
                        p for p in sig.parameters if p != param_name
                    ]
                }
                if len(non_kw) == 1:
                    only_key = next(iter(non_kw))
                    mapped_kwargs[param_name] = mapped_kwargs.pop(only_key)
                    logger.info(
                        f"[TOOLS] Mapped sole arg '{only_key}' -> '{param_name}' for {name}"
                    )
                    continue

                # Strategy 3: use ANY remaining string value as the param
                # (LLMs sometimes use arbitrary key names)
                for k, v in list(mapped_kwargs.items()):
                    if k.startswith('_'):
                        continue
                    if isinstance(v, str) and v.strip():
                        mapped_kwargs[param_name] = mapped_kwargs.pop(k)
                        logger.info(
                            f"[TOOLS] Mapped arbitrary arg '{k}' -> '{param_name}' for {name}"
                        )
                        found = True
                        break

            # Final check: log what we're calling with
            logger.info(
                f"[TOOLS] Calling {name} with mapped_kwargs: {mapped_kwargs}"
            )

            result = await executor(**mapped_kwargs)
            if not isinstance(result, dict):
                result = {"result": result}
            return result
        except TypeError as exc:
            # Catch the specific "missing required positional argument" error
            # and provide a helpful message
            logger.error(
                f"[TOOLS] Parameter mapping failed for {name}: {exc}. "
                f"Original kwargs: {kwargs}, Tool schema: "
                f"{self._tools.get(name, {})}"
            )
            return {"error": f"Parameter mapping failed for {name}: {exc}. The LLM sent: {kwargs}"}
        except Exception as exc:
            logger.error(f"[TOOLS] Execution failed for {name}: {exc}", exc_info=True)
            return {"error": str(exc)}

    # ------------------------------------------------------------------ #
    #  Default tool wiring
    # ------------------------------------------------------------------ #

    def register_default_tools(
        self,
        config: Dict,
        ioc_investigator=None,
        malware_analyzer=None,
        email_analyzer=None,
    ) -> None:
        """Wire up the built-in Blue Team Assistant tools as agent-callable tools.

        Each wrapper is an async function that delegates to the existing tool
        instances (IOCInvestigator, MalwareAnalyzer, EmailAnalyzer) so the agent
        can call them via the ReAct loop.
        """

        # -------------------------------------------------------------- #
        # 1. investigate_ioc
        # -------------------------------------------------------------- #
        if ioc_investigator is not None:
            async def _investigate_ioc(ioc: str, analysis_id: str = None, **_kw) -> Dict:
                return await ioc_investigator.investigate(ioc, analysis_id=analysis_id)

            self.register_local_tool(
                name="investigate_ioc",
                description=(
                    "Investigate an IOC (IP, domain, URL, or hash) against 20+ threat "
                    "intelligence sources. Returns threat score, verdict, and source details."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "ioc": {
                            "type": "string",
                            "description": "The indicator of compromise to investigate.",
                        },
                    },
                    "required": ["ioc"],
                },
                category="threat_intel",
                executor=_investigate_ioc,
            )

        # -------------------------------------------------------------- #
        # 2. analyze_malware
        # -------------------------------------------------------------- #
        if malware_analyzer is not None:
            async def _analyze_malware(file_path: str, **_kw) -> Dict:
                return await malware_analyzer.analyze(file_path)

            self.register_local_tool(
                name="analyze_malware",
                description=(
                    "Perform static analysis on a file (PE, ELF, PDF, Office, scripts). "
                    "Returns YARA matches, string analysis, imports, entropy, and threat score."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Absolute path to the file to analyze.",
                        },
                    },
                    "required": ["file_path"],
                },
                category="analysis",
                executor=_analyze_malware,
            )

        # -------------------------------------------------------------- #
        # 3. analyze_email
        # -------------------------------------------------------------- #
        if email_analyzer is not None:
            async def _analyze_email(email_path: str, **_kw) -> Dict:
                return await email_analyzer.analyze(email_path)

            self.register_local_tool(
                name="analyze_email",
                description=(
                    "Analyze an .eml email file for phishing indicators, header anomalies, "
                    "authentication results, IOCs, and attachments."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "email_path": {
                            "type": "string",
                            "description": "Absolute path to the .eml file.",
                        },
                    },
                    "required": ["email_path"],
                },
                category="analysis",
                executor=_analyze_email,
            )

        # -------------------------------------------------------------- #
        # 4. extract_iocs
        # -------------------------------------------------------------- #
        async def _extract_iocs(text: str, **_kw) -> Dict:
            from ..utils.ioc_extractor import IOCExtractor
            iocs = IOCExtractor.extract_all(text)
            return {"iocs": iocs}

        self.register_local_tool(
            name="extract_iocs",
            description=(
                "Extract IOCs (IPs, domains, URLs, hashes, emails) from arbitrary text."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text to extract IOCs from.",
                    },
                },
                "required": ["text"],
            },
            category="analysis",
            executor=_extract_iocs,
        )

        # -------------------------------------------------------------- #
        # 5. generate_rules
        # -------------------------------------------------------------- #
        async def _generate_rules(analysis_result: Dict = None, rule_type: str = 'all', **_kw) -> Dict:
            from ..detection.rule_generator import RuleGenerator

            if not analysis_result:
                return {"error": "analysis_result is required to generate detection rules."}

            if 'ioc' in analysis_result and 'ioc_type' in analysis_result:
                context = {
                    'verdict': analysis_result.get('verdict', 'Unknown'),
                    'malware_family': analysis_result.get('malware_family', 'Unknown'),
                }
                rules = RuleGenerator.generate_ioc_rules(
                    analysis_result['ioc'], analysis_result['ioc_type'], context
                )
            elif 'email_data' in analysis_result or 'from' in analysis_result or 'subject' in analysis_result:
                email_data = dict(analysis_result.get('email_data', analysis_result))
                if 'sender_domain' not in email_data:
                    sender = email_data.get('from', '')
                    email_data['sender_domain'] = (
                        sender.split('@')[-1].split('>')[0] if '@' in sender else ''
                    )
                if 'malicious_iocs' not in email_data:
                    ioc_results = analysis_result.get('ioc_analysis', {}).get('results', [])
                    email_data['malicious_iocs'] = [
                        r.get('ioc') for r in ioc_results if r.get('verdict') == 'MALICIOUS'
                    ][:10]
                rules = RuleGenerator.generate_email_rules(email_data)
            elif 'hashes' in analysis_result or 'file_info' in analysis_result or 'sha256' in analysis_result or 'filename' in analysis_result:
                file_data = dict(analysis_result)
                if 'sha256' not in file_data and 'hashes' in analysis_result:
                    file_data['sha256'] = analysis_result['hashes'].get('sha256', '')
                    file_data['md5'] = analysis_result['hashes'].get('md5', '')
                if 'filename' not in file_data and 'file_info' in analysis_result:
                    file_data['filename'] = analysis_result['file_info'].get('name', '')
                rules = RuleGenerator.generate_file_rules(file_data)
            else:
                return {
                    "error": (
                        "Unrecognized analysis_result shape. Expected an IOC result "
                        "(with 'ioc'/'ioc_type'), a file analysis result (with "
                        "'hashes'/'file_info'), or an email analysis result "
                        "(with 'email_data'/'from'/'subject')."
                    )
                }

            if rule_type != 'all':
                if rule_type in rules:
                    rules = {rule_type: rules[rule_type]}
                else:
                    return {
                        "error": (
                            f"Rule type '{rule_type}' is not supported for this "
                            f"analysis_result type. Available types: {list(rules.keys())}"
                        )
                    }

            return {"rules": rules}

        self.register_local_tool(
            name="generate_rules",
            description=(
                "Generate detection rules (KQL, Sigma, YARA, SPL) from analysis results."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "analysis_result": {
                        "type": "object",
                        "description": "Analysis result dict to generate rules from.",
                    },
                    "rule_type": {
                        "type": "string",
                        "enum": ["kql", "sigma", "yara", "spl", "all"],
                        "description": "Type of rule to generate. Default 'all'.",
                    },
                },
                "required": [],
            },
            category="detection",
            executor=_generate_rules,
        )

        # -------------------------------------------------------------- #
        # 6. yara_scan
        # -------------------------------------------------------------- #
        async def _yara_scan(file_path: str, **_kw) -> Dict:
            from ..utils.yara_scanner import YaraScanner
            scanner = YaraScanner()
            matches = scanner.scan(file_path)
            return {"matches": matches}

        self.register_local_tool(
            name="yara_scan",
            description="Scan a file against built-in YARA rules for malware signatures.",
            parameters={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to the file to scan.",
                    },
                },
                "required": ["file_path"],
            },
            category="analysis",
            executor=_yara_scan,
        )

        # -------------------------------------------------------------- #
        # 7. search_threat_intel
        # -------------------------------------------------------------- #
        if ioc_investigator is not None:
            async def _search_threat_intel(query: str, source: str = 'all', **_kw) -> Dict:
                """Search threat intel for a query string across all configured sources."""
                return await ioc_investigator.investigate(query)

            self.register_local_tool(
                name="search_threat_intel",
                description=(
                    "Search threat intelligence sources for any indicator or keyword. "
                    "Accepts IPs, domains, URLs, hashes, or keywords."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Indicator or keyword to search.",
                        },
                        "source": {
                            "type": "string",
                            "description": "Specific source to query, or 'all'.",
                            "default": "all",
                        },
                    },
                    "required": ["query"],
                },
                category="threat_intel",
                executor=_search_threat_intel,
            )

        # -------------------------------------------------------------- #
        # 8. sandbox_submit - Submit file to sandboxed analysis
        # -------------------------------------------------------------- #
        async def _sandbox_submit(file_path: str, **_kw) -> Dict:
            """Submit a file for sandbox analysis (Docker/VM/Cloud - NEVER host)."""
            try:
                from ..agent.sandbox_orchestrator import SandboxOrchestrator
                orch = SandboxOrchestrator(config)
                sandbox_info = orch.select_sandbox(file_path)
                result = await orch.submit_to_sandbox(file_path, sandbox_info)
                return result
            except Exception as e:
                return {"error": f"Sandbox submission failed: {e}"}

        self.register_local_tool(
            name="sandbox_submit",
            description=(
                "Submit a file for dynamic analysis in an isolated sandbox (Docker/VM/Cloud). "
                "NEVER executes on host. Returns analysis results from the sandbox."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to the file to submit.",
                    },
                },
                "required": ["file_path"],
            },
            category="sandbox",
            executor=_sandbox_submit,
            is_dangerous=True,
            requires_approval=True,
        )

        # -------------------------------------------------------------- #
        # 9. correlate_findings - Cross-correlate analysis findings
        # -------------------------------------------------------------- #
        async def _correlate_findings(
            ioc_results: Any = None,
            threat_intel: Any = None,
            network_analysis: Any = None,
            log_search: Any = None,
            timeline: Any = None,
            **_kw,
        ) -> Dict:
            """Correlate findings to identify related IOCs and MITRE ATT&CK TTPs."""
            try:
                from ..agent.correlation import CorrelationEngine

                findings = []
                for label, raw in [
                    ("ioc_results", ioc_results),
                    ("threat_intel", threat_intel),
                    ("network_analysis", network_analysis),
                    ("log_search", log_search),
                    ("timeline", timeline),
                ]:
                    if raw:
                        findings.append({"tool": label, "text": raw})

                for label, raw in _kw.items():
                    if raw:
                        findings.append({"tool": label, "text": raw})

                engine = CorrelationEngine()
                result = engine.correlate(findings)
                return result
            except Exception as e:
                return {"error": f"Correlation failed: {e}"}

        self.register_local_tool(
            name="correlate_findings",
            description=(
                "Cross-correlate analysis findings from multiple sources (IOC lookups, "
                "threat intel, network analysis, logs, and timelines) to identify "
                "related IOCs, MITRE ATT&CK TTPs, and compute an overall severity assessment."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "ioc_results": {
                        "type": "string",
                        "description": "Stringified list/dict of IOC investigation results.",
                    },
                    "threat_intel": {
                        "type": "string",
                        "description": "Stringified list/dict of threat intelligence lookup results.",
                    },
                    "network_analysis": {
                        "type": "string",
                        "description": "Stringified list/dict of network analysis results (PCAPs, flows).",
                    },
                    "log_search": {
                        "type": "string",
                        "description": "Stringified list/dict of log search results (SIEM, EDR).",
                    },
                    "timeline": {
                        "type": "string",
                        "description": "Stringified list/dict of host or event timeline results.",
                    },
                },
                "required": [],
            },
            category="analysis",
            executor=_correlate_findings,
        )

        # -------------------------------------------------------------- #
        # 10. recall_ioc - Check investigation memory for past results
        # -------------------------------------------------------------- #
        async def _recall_ioc(ioc: str, **_kw) -> Dict:
            """Recall previously investigated IOC results from memory."""
            try:
                from ..agent.memory import InvestigationMemory
                mem = InvestigationMemory()
                cached = mem.recall_ioc(ioc)
                if cached:
                    return {"cached": True, "result": cached}
                return {"cached": False, "message": f"No prior investigation found for {ioc}"}
            except Exception as e:
                return {"error": f"Memory recall failed: {e}"}

        self.register_local_tool(
            name="recall_ioc",
            description=(
                "Check investigation memory for previously analyzed IOC results. "
                "Avoids redundant lookups by returning cached verdicts."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "ioc": {
                        "type": "string",
                        "description": "IOC to recall from memory.",
                    },
                },
                "required": ["ioc"],
            },
            category="analysis",
            executor=_recall_ioc,
        )

        # -------------------------------------------------------------- #
        # 11. isolate_device (SIMULATED containment action, P0.1)
        # -------------------------------------------------------------- #
        self.register_local_tool(
            name="isolate_device",
            description=(
                "SIMULATED: Isolate a device/host from the network to prevent lateral "
                "movement. Does not perform a real EDR/firewall action - records the "
                "action to a local JSON file for demo/proof-of-concept purposes."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "device_id": {
                        "type": "string",
                        "description": "Identifier (hostname, IP, or asset ID) of the device to isolate.",
                    },
                    "isolation_type": {
                        "type": "string",
                        "description": "Type of isolation to simulate (e.g. 'network').",
                        "default": "network",
                    },
                },
                "required": ["device_id"],
            },
            category="edr",
            executor=isolate_device,
            requires_approval=True,
            is_dangerous=True,
        )

        # -------------------------------------------------------------- #
        # 12. block_ip (SIMULATED containment action, P0.1)
        # -------------------------------------------------------------- #
        self.register_local_tool(
            name="block_ip",
            description=(
                "SIMULATED: Block an IP address at the perimeter. Does not perform a "
                "real firewall/EDR action - records the action to a local JSON file "
                "for demo/proof-of-concept purposes."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "ip_address": {
                        "type": "string",
                        "description": "IP address to block.",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for blocking this IP.",
                        "default": "",
                    },
                },
                "required": ["ip_address"],
            },
            category="edr",
            executor=block_ip,
            requires_approval=True,
            is_dangerous=True,
        )

        # -------------------------------------------------------------- #
        # 13. quarantine_file (SIMULATED containment action, P0.1)
        # -------------------------------------------------------------- #
        self.register_local_tool(
            name="quarantine_file",
            description=(
                "SIMULATED: Quarantine a malicious file. Does not perform a real "
                "EDR quarantine action - copies the file (if present on disk) into "
                "a local quarantine folder and records the action to a local JSON "
                "file for demo/proof-of-concept purposes."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to quarantine.",
                    },
                },
                "required": ["file_path"],
            },
            category="edr",
            executor=quarantine_file,
            requires_approval=True,
            is_dangerous=True,
        )

        logger.info(
            f"[TOOLS] Registered {len(self._tools)} default tools"
        )
