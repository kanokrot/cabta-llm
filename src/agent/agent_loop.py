"""
Agent Loop - ReAct reasoning engine for autonomous security investigations.

The loop cycles through THINK -> ACT -> OBSERVE until the LLM decides to emit
a final answer or the step budget is exhausted.  Dangerous actions pause for
analyst approval (WAITING_HUMAN).
"""

import asyncio
import json
import logging
import time
import threading
from typing import Any, Dict, List, Optional

import aiohttp

from .agent_state import AgentPhase, AgentState
from .agent_store import AgentStore
from .tool_registry import ToolRegistry
from .agent_response_parsing import (
    extract_verdict,
    extract_deterministic_verdict,
    normalise_decision,
    parse_tool_call_response,
    extract_json,
    truncate,
)
from .agent_tool_selection import ToolSelector
from .agent_llm_backends import LLMBackend

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------- #
#  System prompt template
# -------------------------------------------------------------------- #

_SYSTEM_PROMPT = """\
You are a Blue Team Security Agent. You investigate security threats autonomously.

Investigation goal: {goal}

Previous findings:
{findings_block}

{playbooks_block}

INSTRUCTIONS:
1. You MUST use tools to gather evidence before drawing conclusions. Never answer from memory alone.
2. For IOC investigations: call investigate_ioc first, then use MCP tools like threat_intel_tools.blocklist_check, threat_intel_tools.threatfox_ioc_lookup, threat_intel_tools.feodo_tracker_check for deeper analysis.
3. For file analysis: call analyze_malware first, then use MCP tools like remnux_tools.pe_analyze, remnux_tools.yara_scan, remnux_tools.file_entropy, remnux_tools.hash_file for deeper analysis.
4. For email analysis: call analyze_email first, then use MCP tools like remnux_tools.olevba_analyze, remnux_tools.rtfobj_analyze for attachment analysis (if applicable).
5. After gathering evidence, call correlate_findings to produce the final verdict.
6. Only write a final text answer (no tool call) AFTER you have gathered real evidence from at least 2 tools.
7. When calling a tool, ONLY pass the tool's own parameters (e.g. {{"ioc": "8.8.8.8"}}). Do NOT include extra keys like "action", "reasoning", or "tool" in the arguments.
8. Use DIFFERENT tools each step. Never call the same tool with the same parameters twice.

If previous findings are "(none yet)", you MUST call a tool now. Do NOT skip to a conclusion.

RULES:
- Never execute malware on the host system. Use sandbox tools for dynamic analysis.
- Be methodical: gather evidence first, then correlate, then conclude.
- Only use the tools provided. Do NOT invent tool names.
"""

# Fallback prompt for when no native tool calling is available
_SYSTEM_PROMPT_NO_TOOLS = """\
You are a Blue Team Security Agent. You investigate security threats autonomously.

Available tools:
{tools_block}

{playbooks_block}

Investigation goal: {goal}

Previous findings:
{findings_block}

Decide your next action. Respond in JSON (no markdown, no extra text):
{{"action": "use_tool", "tool": "tool_name", "params": {{...}}, "reasoning": "why"}}
OR
{{"action": "run_playbook", "playbook_id": "playbook_name", "params": {{...}}, "reasoning": "why"}}
OR
{{"action": "final_answer", "answer": "investigation summary", "verdict": "MALICIOUS/SUSPICIOUS/CLEAN", "reasoning": "why"}}

IMPORTANT:
- Never execute malware on the host system. Use sandbox tools for dynamic analysis.
- Actions marked as requiring approval will pause for analyst review.
- Be methodical: gather evidence first, then correlate, then conclude.
- Only use tools that are listed above. Do NOT invent tool names.
- If a playbook matches the investigation goal, prefer running the playbook for structured analysis.
- Always include the "action" key in your JSON response.
"""

_SUMMARY_PROMPT = """\
You are a Blue Team Security Agent. Summarise the following investigation
in 3-5 sentences suitable for a SOC ticket.  Include the verdict
(MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN), key evidence, and recommended
next steps.

CRITICAL RULE: A tool error (e.g. "HTTP 401", "Timeout", "Connection failed")
is NOT evidence of malicious activity — it only means the lookup could not
be completed. If ALL findings below are tool errors and none contain actual
threat intelligence data (detections, reputation scores, botnet/malware
names, etc.), you MUST set the verdict to "UNKNOWN" and the recommended
next step MUST be to retry with a different tool or fix the failing
integration. Do NOT infer risk level from the mere fact that a lookup failed.

Goal: {goal}

Steps taken: {step_count}

Findings:
{findings_json}

Respond in plain text (no JSON).
"""


class AgentLoop:
    """Orchestrates the ReAct loop, delegates to LLM + tools."""

    def __init__(
        self,
        config: Dict[str, Any],
        tool_registry: ToolRegistry,
        agent_store: AgentStore,
        llm_analyzer=None,
        mcp_client=None,
        playbook_engine=None,
        notification_manager=None,
    ):
        self.config = config
        self.tools = tool_registry
        self.store = agent_store
        self.llm = llm_analyzer
        self.mcp_client = mcp_client
        self._playbook_engine = playbook_engine
        self.notification_manager = notification_manager

        agent_cfg = config.get('agent', {})
        self.max_steps = agent_cfg.get('max_steps', 50)

        # LLM connection settings (mirrors LLMAnalyzer)
        llm_cfg = config.get('llm', {})
        self.provider = llm_cfg.get('provider', 'ollama')
        self.ollama_endpoint = llm_cfg.get('ollama_endpoint', 'http://localhost:11434')
        self.ollama_model = llm_cfg.get('model', llm_cfg.get('ollama_model', 'llama3.2:3b'))
        self.anthropic_key = config.get('api_keys', {}).get('anthropic', '')
        self.anthropic_model = llm_cfg.get('anthropic_model', 'claude-sonnet-4-20250514')
        self.timeout = aiohttp.ClientTimeout(total=120)

        self.tool_selector = ToolSelector(
            tools=self.tools, playbook_engine=getattr(self, '_playbook_engine', None),
        )
        self.llm_backend = LLMBackend(
            provider=self.provider,
            tools=self.tools,
            ollama_model=self.ollama_model,
            ollama_endpoint=self.ollama_endpoint,
            anthropic_key=self.anthropic_key,
            anthropic_model=self.anthropic_model,
            timeout=self.timeout,
        )

        # Active sessions & pub-sub
        self._active_sessions: Dict[str, AgentState] = {}
        self._approval_events: Dict[str, asyncio.Event] = {}
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}
        self._main_loop: Optional[asyncio.AbstractEventLoop] = None  # set on first investigate()

    # ================================================================== #
    #  Public API
    # ================================================================== #

    async def investigate(
        self,
        goal: str,
        case_id: Optional[str] = None,
        playbook_id: Optional[str] = None,
        max_steps: Optional[int] = None,
    ) -> str:
        """Start an autonomous investigation. Returns *session_id* immediately."""

        session_id = self.store.create_session(
            goal=goal, case_id=case_id, playbook_id=playbook_id,
        )

        effective_max_steps = max_steps if max_steps is not None else self.max_steps
        state = AgentState(
            session_id=session_id,
            goal=goal,
            max_steps=effective_max_steps,
        )
        self._active_sessions[session_id] = state
        self._approval_events[session_id] = asyncio.Event()

        # Capture the main event loop so _notify() can safely push
        # messages to subscriber queues from background threads.
        try:
            self._main_loop = asyncio.get_running_loop()
        except RuntimeError:
            self._main_loop = None

        # Fire-and-forget the loop in a background thread so the caller
        # gets the session_id without blocking.
        def _run():
            asyncio.run(self._run_loop(session_id))

        t = threading.Thread(target=_run, daemon=True, name=f"agent-{session_id}")
        t.start()

        logger.info(f"[AGENT] Investigation started: {session_id} - {goal[:80]}")
        return session_id

    async def approve_action(self, session_id: str) -> bool:
        """Approve the pending action so the loop can resume."""
        state = self._active_sessions.get(session_id)
        if state is None or state.pending_approval is None:
            return False
        # Signal the event so _wait_for_approval unblocks
        evt = self._approval_events.get(session_id)
        if evt:
            state.pending_approval["approved"] = True
            evt.set()
        return True

    async def reject_action(self, session_id: str) -> bool:
        """Reject the pending action; the loop will skip it and re-think."""
        state = self._active_sessions.get(session_id)
        if state is None or state.pending_approval is None:
            return False
        evt = self._approval_events.get(session_id)
        if evt:
            state.pending_approval["approved"] = False
            evt.set()
        return True

    async def cancel_session(self, session_id: str) -> None:
        """Cancel a running investigation."""
        state = self._active_sessions.get(session_id)
        if state and not state.is_terminal():
            state.errors.append("Cancelled by analyst")
            state.phase = AgentPhase.FAILED  # direct set to avoid transition check
            self.store.update_session_status(session_id, 'failed', 'Cancelled by analyst')
            self._notify(session_id, {"type": "cancelled"})
            # Unblock any waiting approval
            evt = self._approval_events.get(session_id)
            if evt:
                evt.set()
        logger.info(f"[AGENT] Session cancelled: {session_id}")

    def get_state(self, session_id: str) -> Optional[Dict]:
        """Return live state dict (or None)."""
        state = self._active_sessions.get(session_id)
        return state.to_dict() if state else None

    async def run_tool(self, tool_name: str, params: Dict) -> Dict:
        """Execute a single tool by name (used by PlaybookEngine).

        Supports multiple tool name formats:
        - ``mcp:server-name/tool_name`` (playbook YAML format)
        - ``server-name.tool_name`` (internal registry format)
        - ``tool_name`` (local tool)

        Returns the tool result dict.
        """
        # ---- Normalise playbook-style "mcp:server/tool" references ----
        original_name = tool_name
        mcp_server = None
        mcp_tool = None

        if tool_name.startswith("mcp:"):
            # Format: mcp:server-name/tool_name
            rest = tool_name[4:]  # strip "mcp:"
            if "/" in rest:
                mcp_server, mcp_tool = rest.split("/", 1)
                # Convert to registry format: server-name.tool_name
                tool_name = f"{mcp_server}.{mcp_tool}"
            else:
                # mcp:tool_name (no server specified)
                tool_name = rest

        tool_def = self.tools.get_tool(tool_name)

        if tool_def is None and mcp_server and mcp_tool:
            # Tool not registered yet -- try calling MCP directly
            if self.mcp_client is not None:
                try:
                    result = await self.mcp_client.call_tool(
                        mcp_server, mcp_tool, params,
                    )
                    return result if isinstance(result, dict) else {"result": result}
                except Exception as exc:
                    return {"error": f"MCP tool '{original_name}' call failed: {exc}"}
            return {"error": f"MCP client not available for tool: {original_name}"}

        if tool_def is None:
            return {"error": f"Tool not found: {original_name}"}

        if tool_def.source == 'local':
            return await self.tools.execute_local_tool(tool_name, **params)
        elif self.mcp_client is not None:
            return await self.mcp_client.call_tool(
                tool_def.source, tool_name.split(".", 1)[-1], params,
            )
        else:
            return {"error": f"MCP client not available for tool: {original_name}"}

    # ------------------------------------------------------------------ #
    #  Pub / Sub
    # ------------------------------------------------------------------ #

    def subscribe(self, session_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(session_id, []).append(q)
        return q

    def unsubscribe(self, session_id: str, queue: asyncio.Queue) -> None:
        subs = self._subscribers.get(session_id, [])
        if queue in subs:
            subs.remove(queue)

    def _notify(self, session_id: str, message: Dict) -> None:
        """Push a message to all WebSocket subscribers for *session_id*.

        Thread-safe: if called from a background thread (agent loop),
        schedules the put on the main event loop so asyncio.Queue
        operations happen in the correct loop context.
        """
        subs = self._subscribers.get(session_id, [])
        if not subs:
            return

        main_loop = self._main_loop

        def _put_all():
            for q in subs:
                try:
                    q.put_nowait(message)
                except asyncio.QueueFull:
                    pass

        # If we have a reference to the main loop AND we're in a different
        # thread, use call_soon_threadsafe to schedule the put.
        if main_loop is not None and main_loop.is_running():
            try:
                main_loop.call_soon_threadsafe(_put_all)
                return
            except RuntimeError:
                pass  # loop closed, fall through

        # Fallback: direct put (works when called from the main loop)
        _put_all()

    # ================================================================== #
    #  Main ReAct Loop
    # ================================================================== #

    async def _run_loop(self, session_id: str) -> None:
        state = self._active_sessions.get(session_id)
        if state is None:
            return

        # Track previously called tools to prevent infinite loops
        _prev_tool_calls: list = []

        try:
            state.transition(AgentPhase.THINKING)

            while not state.is_terminal() and state.step_count < state.max_steps:
                # ---- THINK ----
                state.phase = AgentPhase.THINKING
                state.current_tool = None
                self._notify(session_id, {
                    "type": "phase", "phase": "thinking",
                    "step": state.step_count,
                    "max_steps": state.max_steps,
                })

                decision = await self._think(state)

                if decision is None:
                    # Retry once: LLM may have returned an unparseable
                    # response or had a transient connection issue.
                    logger.warning("[AGENT] First LLM call returned None, retrying...")
                    await asyncio.sleep(1)
                    decision = await self._think(state)

                if decision is None:
                    state.errors.append(
                        "LLM returned no decision. Verify Ollama is running "
                        f"({self.ollama_endpoint}) and model '{self.ollama_model}' "
                        "is pulled. Run: ollama pull " + self.ollama_model
                    )
                    state.transition(AgentPhase.FAILED)
                    break

                # Record the thinking step
                self.store.add_step(
                    session_id, state.step_count, 'thinking',
                    json.dumps(decision, default=str),
                )

                # ---- Check for final answer ----
                if decision.get('action') == 'final_answer':
                    summary = decision.get('answer', '')
                    verdict = decision.get('verdict', 'UNKNOWN')
                    state.add_finding({
                        "type": "final_answer",
                        "answer": summary,
                        "verdict": verdict,
                        "reasoning": decision.get('reasoning', ''),
                    })
                    self.store.add_step(
                        session_id, state.step_count, 'final_answer',
                        json.dumps(decision, default=str),
                    )

                    # Alert on high-severity verdicts (MALICIOUS/SUSPICIOUS by
                    # default -- configurable via notifications.create_on_verdict).
                    if self.notification_manager is not None and \
                            verdict in getattr(self.notification_manager, 'create_on_verdict', []):
                        try:
                            self.notification_manager.notify("verdict_alert", {
                                "ioc": state.goal,
                                "verdict": verdict,
                                "session_id": session_id,
                            })
                        except Exception as notify_exc:
                            logger.warning(
                                f"[AGENT] Notification dispatch failed: {notify_exc}"
                            )
                    break

                # ---- Check for run_playbook action ----
                if decision.get('action') == 'run_playbook':
                    pb_id = decision.get('playbook_id', '')
                    pb_params = decision.get('params', {})
                    reasoning = decision.get('reasoning', '')

                    if hasattr(self, '_playbook_engine') and self._playbook_engine:
                        self.store.add_step(
                            session_id, state.step_count, 'run_playbook',
                            json.dumps({
                                "playbook_id": pb_id,
                                "params": pb_params,
                                "reasoning": reasoning,
                            }, default=str),
                        )
                        self._notify(session_id, {
                            "type": "phase", "phase": "running_playbook",
                            "step": state.step_count, "playbook_id": pb_id,
                        })
                        try:
                            pb_session = await self._playbook_engine.execute(
                                pb_id, pb_params, case_id=state.goal,
                            )
                            state.add_finding({
                                "type": "playbook_completed",
                                "playbook_id": pb_id,
                                "session_id": pb_session,
                                "reasoning": reasoning,
                            })
                            self.store.add_step(
                                session_id, state.step_count, 'playbook_result',
                                json.dumps({
                                    "playbook_id": pb_id,
                                    "sub_session_id": pb_session,
                                    "status": "completed",
                                }, default=str),
                            )
                        except Exception as exc:
                            state.add_finding({
                                "type": "playbook_error",
                                "playbook_id": pb_id,
                                "error": str(exc),
                            })
                            self.store.add_step(
                                session_id, state.step_count, 'playbook_error',
                                json.dumps({
                                    "playbook_id": pb_id,
                                    "error": str(exc),
                                }, default=str),
                            )
                        state.step_count += 1
                        continue
                    else:
                        state.errors.append(f"Playbook engine not available for: {pb_id}")
                        state.step_count += 1
                        continue

                # ---- Validate action field ----
                action = decision.get('action', '')
                if action not in ('use_tool', 'final_answer', 'run_playbook'):
                    # LLM returned a JSON without a valid action - treat as
                    # a thinking step and continue so it can try again.
                    state.errors.append(
                        f"LLM returned invalid action '{action}'. "
                        "Expected: use_tool, final_answer, or run_playbook."
                    )
                    state.step_count += 1
                    continue

                # ---- Resolve tool ----
                tool_name = decision.get('tool', '')
                tool_def = self.tools.get_tool(tool_name)

                if tool_def is None:
                    # Unknown tool - record error and let agent re-think
                    state.errors.append(f"Unknown tool: {tool_name}")
                    state.add_finding({
                        "type": "error",
                        "message": f"Tool '{tool_name}' not found in registry.",
                    })
                    state.step_count += 1
                    continue

                # ---- Approval gate ----
                if tool_def.requires_approval:
                    state.request_approval(
                        decision,
                        f"Tool '{tool_name}' requires analyst approval before execution.",
                    )
                    state.phase = AgentPhase.WAITING_HUMAN
                    self._notify(session_id, {
                        "type": "approval_required",
                        "tool": tool_name,
                        "params": decision.get('params', {}),
                        "reason": state.pending_approval["reason"],
                    })

                    # Wait until approve/reject/cancel
                    approved = await self._wait_for_approval(session_id, state)
                    if state.is_terminal():
                        break

                    # Persist audit trail entry for the approval decision
                    self.store.add_audit_entry(
                        session_id=session_id,
                        action=tool_name,
                        action_type='approval_granted' if approved else 'approval_rejected',
                        actor='human',
                        requires_approval=True,
                        before_state=decision.get('params', {}),
                        status='approved' if approved else 'rejected',
                    )

                    if not approved:
                        # Rejected - skip tool and re-think
                        state.add_finding({
                            "type": "approval_rejected",
                            "tool": tool_name,
                        })
                        state.step_count += 1
                        state.transition(AgentPhase.THINKING)
                        continue
                    # Approved - fall through to ACT
                    state.transition(AgentPhase.ACTING)
                else:
                    state.transition(AgentPhase.ACTING)

                # ---- Duplicate call guard ----
                call_sig = (tool_name, json.dumps(decision.get('params', {}), sort_keys=True, default=str))
                if call_sig in _prev_tool_calls:
                    logger.warning(
                        "[AGENT] Duplicate tool call detected: %s. Checking for real evidence...",
                        tool_name,
                    )
                    if self.tool_selector.has_successful_evidence(state):
                        break  # มี evidence จริงแล้ว → ไปสรุปผล
                    elif state.step_count < state.max_steps - 1:
                        # ยังไม่มี evidence จริงเลย (มีแต่ error) → ลอง local tool
                        # ที่มี multi-source fallback แทนที่จะ break ไปสรุปผลจาก error
                        ioc_val = decision.get('params', {}).get('indicator') \
                            or decision.get('params', {}).get('ioc', '')
                        logger.warning(
                            "[AGENT] No successful evidence yet, retrying with "
                            "investigate_ioc (multi-source fallback) instead of giving up."
                        )
                        decision = {
                            "action": "use_tool",
                            "tool": "investigate_ioc",
                            "params": {"ioc": ioc_val},
                            "reasoning": "Retry via multi-source tool after duplicate + no successful evidence",
                        }
                        call_sig = ("investigate_ioc", ioc_val)
                    else:
                        state.errors.append(
                            "Step budget exhausted without successful evidence "
                            "(only tool errors collected)"
                        )
                        break
                _prev_tool_calls.append(call_sig)

                # ---- ACT ----
                state.current_tool = tool_name
                is_mcp = '.' in tool_name
                self._notify(session_id, {
                    "type": "phase", "phase": "acting",
                    "step": state.step_count, "max_steps": state.max_steps,
                    "tool": tool_name,
                    "tool_source": "mcp" if is_mcp else "local",
                    "tool_server": tool_name.split('.')[0] if is_mcp else None,
                    "params": decision.get('params', {}),
                })

                import time as _time
                _act_start = _time.time()
                result = await self._act(state, decision)
                _act_dur = int((_time.time() - _act_start) * 1000)

                # ---- OBSERVE ----
                state.transition(AgentPhase.OBSERVING)
                state.current_tool = None
                state.add_finding({
                    "type": "tool_result",
                    "tool": tool_name,
                    "params": decision.get('params', {}),
                    "result": result,
                })
                state.step_count += 1

                # Persist findings snapshot
                self.store.update_session_findings(session_id, state.findings)

                # Notify WS with tool result for live display
                self._notify(session_id, {
                    "type": "tool_result",
                    "step": state.step_count - 1,
                    "max_steps": state.max_steps,
                    "tool": tool_name,
                    "tool_source": "mcp" if is_mcp else "local",
                    "tool_server": tool_name.split('.')[0] if is_mcp else None,
                    "duration_ms": _act_dur,
                    "params": decision.get('params', {}),
                    "result": result,
                })

                # ---- AUTO-ENRICH with MCP tools ----
                # After first local tool, automatically run relevant MCP tools
                if (tool_name in ('investigate_ioc', 'analyze_malware', 'analyze_email')
                        and state.step_count <= 3
                        and state.step_count < state.max_steps - 1):
                    mcp_calls = self.tool_selector.get_enrichment_mcp_tools(
                        tool_name, decision.get('params', {}), state.goal,
                    )
                    logger.warning(
                        "[AGENT] Auto-enrich: %d MCP tools queued for %s",
                        len(mcp_calls), tool_name,
                    )
                    for mcp_tool, mcp_params in mcp_calls:
                        if state.step_count >= state.max_steps - 1:
                            break
                        try:
                            logger.warning(
                                "[AGENT] Auto-enrich: calling %s",
                                mcp_tool,
                            )
                            state.current_tool = mcp_tool
                            state.phase = AgentPhase.ACTING
                            mcp_server = mcp_tool.split('.')[0] if '.' in mcp_tool else None
                            self._notify(session_id, {
                                "type": "phase", "phase": "acting",
                                "step": state.step_count, "max_steps": state.max_steps,
                                "tool": mcp_tool,
                                "tool_source": "mcp",
                                "tool_server": mcp_server,
                                "params": mcp_params,
                            })
                            mcp_decision = {
                                "action": "use_tool",
                                "tool": mcp_tool,
                                "params": mcp_params,
                                "reasoning": "Auto-enrichment with MCP tool",
                            }
                            _mcp_start = _time.time()
                            mcp_result = await self._act(state, mcp_decision)
                            _mcp_dur = int((_time.time() - _mcp_start) * 1000)
                            state.phase = AgentPhase.OBSERVING
                            state.current_tool = None
                            state.add_finding({
                                "type": "tool_result",
                                "tool": mcp_tool,
                                "params": mcp_params,
                                "result": mcp_result,
                            })
                            state.step_count += 1
                            self.store.update_session_findings(
                                session_id, state.findings,
                            )
                            # Notify WS with MCP tool result
                            self._notify(session_id, {
                                "type": "tool_result",
                                "step": state.step_count - 1,
                                "max_steps": state.max_steps,
                                "tool": mcp_tool,
                                "tool_source": "mcp",
                                "tool_server": mcp_server,
                                "duration_ms": _mcp_dur,
                                "params": mcp_params,
                                "result": mcp_result,
                            })
                            logger.warning(
                                "[AGENT] Auto-enrich: %s done (%dms)", mcp_tool, _mcp_dur,
                            )
                        except Exception as enrich_exc:
                            logger.warning(
                                "[AGENT] Auto-enrich %s failed: %s",
                                mcp_tool, enrich_exc,
                            )
                            state.step_count += 1

                self._notify(session_id, {
                    "type": "observation",
                    "step": state.step_count,
                    "tool": tool_name,
                    "result_preview": truncate(json.dumps(result, default=str), 500),
                })

                # Transition back to THINKING for next iteration
                state.transition(AgentPhase.THINKING)

            # ---- Loop finished ----
            if not state.is_terminal():
                if state.step_count >= state.max_steps:
                    state.errors.append(f"Step limit ({state.max_steps}) reached")
                state.phase = AgentPhase.COMPLETED

            summary = await self._generate_summary(state)
            final_status = 'completed' if state.phase == AgentPhase.COMPLETED else 'failed'
            self.store.update_session_status(session_id, final_status, summary)
            self.store.update_session_findings(session_id, state.findings)

            self._notify(session_id, {
                "type": "completed",
                "status": final_status,
                "summary": summary,
                "steps": state.step_count,
            })

        except Exception as exc:
            logger.error(f"[AGENT] Loop error for {session_id}: {exc}", exc_info=True)
            state.errors.append(str(exc))
            state.phase = AgentPhase.FAILED
            self.store.update_session_status(session_id, 'failed', str(exc))
            self._notify(session_id, {"type": "failed", "error": str(exc)})

        finally:
            # Clean up
            self._approval_events.pop(session_id, None)

    # ================================================================== #
    #  THINK - ask LLM for next action
    # ================================================================== #

    async def _think(self, state: AgentState) -> Optional[Dict]:
        """Build context and call the LLM to decide the next action."""
        tools_block = self.tool_selector.build_tools_block()
        findings_block = self.tool_selector.build_findings_block(state)
        playbooks_block = self.tool_selector.build_playbooks_block()
        all_tools = self.tools.get_tools_for_llm()
        # Filter tools to a manageable set for the LLM
        tools_json = self.tool_selector.filter_tools_for_goal(all_tools, state.goal, state)
        has_native_tools = len(tools_json) > 0

        if has_native_tools:
            # Use the clean prompt that doesn't instruct JSON response format
            # (avoids LLM stuffing decision JSON into tool_call arguments)
            system_prompt = _SYSTEM_PROMPT.format(
                goal=state.goal,
                findings_block=findings_block,
                playbooks_block=playbooks_block,
            )
        else:
            system_prompt = _SYSTEM_PROMPT_NO_TOOLS.format(
                tools_block=tools_block,
                goal=state.goal,
                findings_block=findings_block,
                playbooks_block=playbooks_block,
            )

        messages = [
            {"role": "user", "content": system_prompt},
        ]

        # Attempt tool-calling API first, fall back to plain chat
        raw = await self._chat_with_tools(messages)
        logger.info(f"[AGENT] LLM raw response type={type(raw).__name__}, "
                     f"preview={str(raw)[:500] if raw else 'None'}")
        if raw is None:
            return None

        # If the LLM used native tool_call, convert to our decision dict
        if isinstance(raw, dict) and 'tool_calls' in raw:
            return self._parse_tool_call_response(raw)

        # Otherwise parse the text as JSON
        if isinstance(raw, str):
            parsed = self._extract_json(raw)
            if parsed is not None:
                # Normalise non-standard JSON formats into our decision dict
                parsed = normalise_decision(
                    parsed, state,
                    self.tool_selector.guess_first_tool,
                    self.tool_selector.guess_tool_params,
                )
                return parsed
            # If we can't parse JSON and native tools were available,
            # the LLM gave a plain text answer.
            if has_native_tools and raw.strip():
                # If we already have findings → real conclusion
                if state.findings:
                    deterministic_verdict = extract_deterministic_verdict(state.findings)
                    return {
                        "action": "final_answer",
                        "answer": raw.strip(),
                        "verdict": deterministic_verdict if deterministic_verdict else extract_verdict(raw),
                        "reasoning": "LLM provided text response after tool use",
                    }
                # No findings yet → auto-dispatch
                logger.warning(
                    "[AGENT] LLM gave text instead of tool call. "
                    "Auto-dispatching tool based on goal."
                )
                return {
                    "action": "use_tool",
                    "tool": self.tool_selector.guess_first_tool(state.goal),
                    "params": self.tool_selector.guess_tool_params(state.goal),
                    "reasoning": "Auto-dispatched: LLM did not call a tool",
                }
            return None

        # Already a dict (from JSON-mode response)
        if isinstance(raw, dict):
            return raw

        return None

    # ================================================================== #
    #  ACT - execute a tool
    # ================================================================== #

    async def _act(self, state: AgentState, decision: Dict) -> Dict:
        """Execute the tool specified in *decision*."""
        tool_name = decision.get('tool', '')
        params = decision.get('params', {})
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except json.JSONDecodeError:
                params = {}

        logger.info(f"[AGENT] _act: tool={tool_name}, params={params}")

        start = time.time()
        tool_def = None
        try:
            tool_def = self.tools.get_tool(tool_name)
            if tool_def is None:
                result = {"error": f"Tool not found: {tool_name}"}
            elif tool_def.source == 'local':
                result = await self.tools.execute_local_tool(tool_name, **params)
            elif self.mcp_client is not None:
                # MCP remote tool call
                result = await self.mcp_client.call_tool(
                    tool_def.source, tool_name.split(".", 1)[-1], params,
                )
                if not isinstance(result, dict):
                    result = {"result": result}
            else:
                result = {"error": f"MCP client not available for tool: {tool_name}"}
        except Exception as exc:
            logger.error(f"[AGENT] Tool {tool_name} failed: {exc}", exc_info=True)
            result = {"error": str(exc)}

        duration_ms = int((time.time() - start) * 1000)

        # Persist step
        self.store.add_step(
            state.session_id,
            state.step_count,
            'tool_call',
            json.dumps(decision, default=str),
            tool_name,
            json.dumps(params, default=str),
            json.dumps(result, default=str),
            duration_ms,
        )

        # Persist audit trail entry for this tool call
        self.store.add_audit_entry(
            session_id=state.session_id,
            action=tool_name,
            action_type='tool_call',
            actor='agent',
            requires_approval=bool(tool_def.requires_approval) if tool_def else False,
            after_state=result,
            status='error' if isinstance(result, dict) and 'error' in result else 'success',
        )

        return result

    # ================================================================== #
    #  Approval wait
    # ================================================================== #

    async def _wait_for_approval(
        self, session_id: str, state: AgentState,
    ) -> bool:
        """Block until the analyst approves/rejects or the session is cancelled.

        Returns True if approved, False if rejected or cancelled.
        """
        evt = self._approval_events.get(session_id)
        if evt is None:
            return False

        evt.clear()
        # Wait up to 30 minutes for human response
        try:
            await asyncio.wait_for(evt.wait(), timeout=1800)
        except asyncio.TimeoutError:
            state.errors.append("Approval timed out (30 min)")
            state.phase = AgentPhase.FAILED
            return False

        approval = state.clear_approval()
        if approval is None:
            return False
        return approval.get("approved", False)

    # ================================================================== #
    #  Summary generation
    # ================================================================== #

    async def _generate_summary(self, state: AgentState) -> str:
        """Ask the LLM to produce a concise investigation summary."""
        # If there is a final_answer finding, use it directly
        for f in reversed(state.findings):
            if f.get("type") == "final_answer":
                answer = f.get("answer", "")
                verdict = f.get("verdict", "")
                if answer:
                    return f"[{verdict}] {answer}"

        # Otherwise ask LLM to summarise
        findings_json = json.dumps(state.findings[-15:], default=str, indent=1)
        prompt = _SUMMARY_PROMPT.format(
            goal=state.goal,
            step_count=state.step_count,
            findings_json=findings_json[:4000],
        )

        try:
            raw = await self._call_llm_text(prompt)
            if raw:
                return raw[:2000]
        except Exception as exc:
            logger.warning(f"[AGENT] Summary generation failed: {exc}")

        # Fallback
        return (
            f"Investigation completed in {state.step_count} steps. "
            f"{len(state.findings)} findings collected. "
            f"Errors: {len(state.errors)}."
        )

    # ================================================================== #
    #  LLM communication (thin wrappers delegating to self.llm_backend;
    #  kept on AgentLoop because tests patch/call these directly)
    # ================================================================== #

    async def _chat_with_tools(
        self, messages: List[Dict],
    ) -> Optional[Any]:
        return await self.llm_backend.chat_with_tools(messages)

    async def _call_llm_text(self, prompt: str) -> Optional[str]:
        return await self.llm_backend.call_llm_text(prompt)

    async def _ollama_chat(
        self, messages: List[Dict], tools: List[Dict],
    ) -> Optional[Any]:
        return await self.llm_backend.ollama_chat(messages, tools)

    async def _ollama_generate(self, prompt: str) -> Optional[str]:
        return await self.llm_backend.ollama_generate(prompt)

    async def _anthropic_chat(
        self, messages: List[Dict], tools: List[Dict],
    ) -> Optional[Any]:
        return await self.llm_backend.anthropic_chat(messages, tools)

    async def _anthropic_generate(self, prompt: str) -> Optional[str]:
        return await self.llm_backend.anthropic_generate(prompt)

    # ================================================================== #
    #  Response parsing helpers (thin wrappers delegating to
    #  agent_response_parsing; kept on AgentLoop because tests call
    #  these directly, e.g. AgentLoop._extract_json / loop._parse_tool_call_response)
    # ================================================================== #

    def _parse_tool_call_response(self, raw: Dict) -> Optional[Dict]:
        return parse_tool_call_response(raw)

    @staticmethod
    def _extract_json(text: str) -> Optional[Dict]:
        return extract_json(text)
