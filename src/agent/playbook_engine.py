"""
Playbook Engine - Execute predefined investigation workflows.

Supports:
  - Sequential and conditional step execution
  - ``for_each`` iteration over dynamic result sets
  - Human-in-the-loop approval checkpoints
  - YAML-based playbook definitions (loaded from ``data/playbooks/``)
  - Runtime variable interpolation in tool parameters

A playbook is a list of steps.  Each step invokes a tool and can branch
based on the outcome (``on_success`` / ``on_failure`` / ``condition``).
"""

import asyncio
import json
import logging
import operator
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Import threat intel for enrichment
from ..integrations.threat_intel import ThreatIntelligence


logger = logging.getLogger(__name__)

# Try to import yaml; fall back gracefully if not installed
try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PlaybookStep:
    """One step in a playbook."""
    name: str
    tool: str
    params: Dict[str, Any] = field(default_factory=dict)
    condition: Optional[str] = None  # e.g. "verdict == 'MALICIOUS'"
    on_success: Optional[str] = None  # Name of the next step on success
    on_failure: Optional[str] = None  # Name of the next step on failure
    requires_approval: bool = False  # Pause for human approval
    for_each: Optional[str] = None  # Iterate over a context variable
    timeout: int = 120  # Per-step timeout in seconds
    description: str = ""
    action: Optional[str] = None  # e.g. "final_answer", "trigger_playbook", "input"

    def to_dict(self) -> Dict:
        d = {
            "name": self.name,
            "tool": self.tool,
            "params": self.params,
            "condition": self.condition,
            "on_success": self.on_success,
            "on_failure": self.on_failure,
            "requires_approval": self.requires_approval,
            "for_each": self.for_each,
            "timeout": self.timeout,
            "description": self.description,
        }
        if self.action:
            d["action"] = self.action
        return d

    @classmethod
    def from_dict(cls, d: Dict) -> "PlaybookStep":
        # Handle condition: can be a string or a dict with if/then/else
        raw_cond = d.get("condition")
        condition_str = None
        on_success = d.get("on_success")
        on_failure = d.get("on_failure")

        if isinstance(raw_cond, dict):
            # Playbook YAML format: condition: {if: "...", then: "step", else: "step"}
            condition_str = raw_cond.get("if")
            if isinstance(condition_str, str):
                condition_str = condition_str.strip()
            cond_then = raw_cond.get("then")
            cond_else = raw_cond.get("else")
            if cond_then and not on_success:
                on_success = cond_then
            if cond_else and not on_failure:
                on_failure = cond_else
        elif isinstance(raw_cond, str):
            condition_str = raw_cond

        return cls(
            name=d["name"],
            tool=d.get("tool", ""),
            params=d.get("params") or {},
            condition=condition_str,
            on_success=on_success,
            on_failure=on_failure,
            requires_approval=d.get("requires_approval", False),
            for_each=d.get("for_each"),
            timeout=d.get("timeout", 120),
            description=d.get("description", ""),
            action=d.get("action"),
        )


# ---------------------------------------------------------------------------
# Safe condition evaluator (no eval)
# ---------------------------------------------------------------------------

# Supported operators for condition parsing
_OPERATORS = {
    "==": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
}

# Regex to parse simple conditions like: variable op value
_SIMPLE_COND = re.compile(
    r"^\s*(\w[\w.]*)\s*(==|!=|>=?|<=?)\s*(.+?)\s*$"
)
# Regex to parse 'value in variable' conditions
_IN_COND = re.compile(
    r"""^\s*['"](.+?)['"]\s+in\s+(\w[\w.]*)\s*$"""
)
# Regex to parse 'variable in (val1, val2)' conditions
_VAR_IN_TUPLE = re.compile(
    r"""^\s*(\w[\w.]*)\s+in\s+\((.+?)\)\s*$"""
)


def _parse_literal(text: str) -> Any:
    """Parse a string literal into a Python value."""
    text = text.strip()
    if (text.startswith("'") and text.endswith("'")) or \
       (text.startswith('"') and text.endswith('"')):
        return text[1:-1]
    if text.lower() == "true":
        return True
    if text.lower() == "false":
        return False
    if text.lower() == "none":
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def _resolve_var(var_path: str, context: Dict) -> Any:
    """Resolve a dotted variable path in the context dict."""
    parts = var_path.split(".")
    obj = context
    for part in parts:
        if isinstance(obj, dict) and part in obj:
            obj = obj[part]
        else:
            return None
    return obj


def safe_evaluate_condition(condition: str, context: Dict) -> bool:
    """
    Evaluate a step condition safely WITHOUT using eval().

    Supported syntax:
    - ``verdict == 'MALICIOUS'``
    - ``score > 70``
    - ``score >= 50``
    - ``'ransomware' in tags``
    - ``file_type in ('PE', 'ELF')``
    - ``cond1 and cond2``   (split on ' and ')
    - ``cond1 or cond2``    (split on ' or ')

    Returns False on any parse error (safe default).
    """
    if not condition or not condition.strip():
        return True

    condition = condition.strip()

    try:
        # Handle 'and' by splitting
        if " and " in condition:
            parts = condition.split(" and ")
            return all(safe_evaluate_condition(p.strip(), context) for p in parts)

        # Handle 'or' by splitting
        if " or " in condition:
            parts = condition.split(" or ")
            return any(safe_evaluate_condition(p.strip(), context) for p in parts)

        # Flatten context: include last_result fields at top level
        flat_ctx = dict(context)
        lr = context.get("last_result", {})
        if isinstance(lr, dict):
            for k, v in lr.items():
                if k not in flat_ctx:
                    flat_ctx[k] = v
        # Also flatten one level of nested dicts
        for key, val in list(context.items()):
            if isinstance(val, dict):
                for k2, v2 in val.items():
                    fk = f"{key}_{k2}"
                    if fk not in flat_ctx:
                        flat_ctx[fk] = v2

        # Pattern: 'value' in variable
        m = _IN_COND.match(condition)
        if m:
            needle = m.group(1)
            haystack = _resolve_var(m.group(2), flat_ctx)
            if isinstance(haystack, (list, tuple, set)):
                return needle in haystack
            if isinstance(haystack, str):
                return needle in haystack
            return False

        # Pattern: variable in (val1, val2, ...)
        m = _VAR_IN_TUPLE.match(condition)
        if m:
            var_val = _resolve_var(m.group(1), flat_ctx)
            tuple_items = [_parse_literal(v.strip()) for v in m.group(2).split(",")]
            return var_val in tuple_items

        # Pattern: variable op value
        m = _SIMPLE_COND.match(condition)
        if m:
            left_val = _resolve_var(m.group(1), flat_ctx)
            op_str = m.group(2)
            right_val = _parse_literal(m.group(3))

            op_func = _OPERATORS.get(op_str)
            if op_func is None:
                return False

            # Type coercion for numeric comparisons
            if isinstance(right_val, (int, float)) and left_val is not None:
                try:
                    left_val = type(right_val)(left_val)
                except (ValueError, TypeError):
                    pass

            try:
                return op_func(left_val, right_val)
            except TypeError:
                return False

        # Unrecognised pattern
        logger.debug("[PLAYBOOK] Could not parse condition: %s", condition)
        return False

    except Exception as exc:
        logger.debug("[PLAYBOOK] Condition '%s' failed: %s", condition, exc)
        return False


_VERDICT_SEVERITY = {"MALICIOUS": 4, "PHISHING": 3, "SUSPICIOUS": 2, "SPAM": 1, "CLEAN": 0}


def _find_highest_verdict(context: Dict) -> Optional[str]:
    """สแกน context หา verdict ทุกตัวที่เกิดจาก tool results ระหว่าง playbook
    แล้วคืนตัวที่รุนแรงที่สุด (read-only, ไม่แก้ context)"""
    found = []
    for key, val in context.items():
        if key == "verdict" or key.endswith("_verdict"):
            if isinstance(val, str) and val.upper() in _VERDICT_SEVERITY:
                found.append(val.upper())
    if not found:
        return None
    return max(found, key=lambda v: _VERDICT_SEVERITY[v])


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class PlaybookEngine:
    """
    Loads and executes investigation playbooks.

    A playbook is identified by its ``playbook_id`` (which is either its
    file-stem for built-in YAML playbooks or the DB ``id`` for user-created
    ones).

    The engine delegates actual tool calls to the ``agent_loop``, which
    handles MCP tool routing, local tools, and result recording.
    """

    def __init__(self, agent_loop, agent_store, notification_manager=None):
        """
        Parameters
        ----------
        agent_loop
            An object with an async ``run_tool(tool_name, params) -> dict``
            method.
        agent_store
            An ``AgentStore`` instance for persistence.
        notification_manager
            Optional ``NotificationManager`` used to alert on approval
            checkpoints and executed approved actions. May be ``None``.
        """
        self.agent_loop = agent_loop
        self.store = agent_store
        self.notification_manager = notification_manager
        # Initialize ThreatIntelligence for context enrichment
        # TODO: This assumes the agent_loop's config is available. Refactor if needed.
        if hasattr(agent_loop, 'config'):
            self.threat_intel = ThreatIntelligence(agent_loop.config)
        else:
            self.threat_intel = None
            logger.warning("[PLAYBOOK] ThreatIntelligence not initialized for enrichment.")

        # Built-in playbooks directory
        self._playbooks_dir = Path(__file__).parent.parent.parent / "data" / "playbooks"

        # In-memory cache: playbook_id -> definition dict
        self._cache: Dict[str, Dict] = {}

        # Load built-in playbooks at start
        self.load_builtin_playbooks()

    # ------------------------------------------------------------------ #
    #  Loading
    # ------------------------------------------------------------------ #

    def load_builtin_playbooks(self) -> int:
        """
        Load YAML playbook definitions from ``data/playbooks/``.

        Returns the number of playbooks loaded.
        """
        if not self._playbooks_dir.is_dir():
            logger.debug("[PLAYBOOK] No playbooks directory at %s", self._playbooks_dir)
            return 0

        if not _HAS_YAML:
            logger.warning(
                "[PLAYBOOK] PyYAML is not installed -- cannot load YAML playbooks. "
                "Install with: pip install pyyaml"
            )
            return 0

        count = 0
        for path in sorted(self._playbooks_dir.glob("*.yaml")) + sorted(self._playbooks_dir.glob("*.yml")):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    definition = yaml.safe_load(f)

                if not isinstance(definition, dict):
                    logger.warning("[PLAYBOOK] Skipping %s (not a dict)", path.name)
                    continue

                pid = definition.get("id", path.stem)
                definition["id"] = pid
                definition["source"] = "builtin"
                definition["file"] = str(path)

                # Validate steps
                steps = definition.get("steps", [])
                if not steps:
                    logger.warning("[PLAYBOOK] Skipping %s (no steps)", path.name)
                    continue

                # Parse steps into PlaybookStep objects (validation)
                parsed = [PlaybookStep.from_dict(s) for s in steps]
                definition["_parsed_steps"] = parsed

                self._cache[pid] = definition
                count += 1
                logger.debug("[PLAYBOOK] Loaded: %s (%d steps)", pid, len(parsed))

            except Exception as exc:
                logger.warning("[PLAYBOOK] Failed to load %s: %s", path.name, exc)

        # Also load from DB
        try:
            for pb in self.store.list_playbooks():
                pid = pb.get("id", pb.get("name", ""))
                if pid and pid not in self._cache:
                    steps_data = pb.get("steps_json", [])
                    if isinstance(steps_data, str):
                        steps_data = json.loads(steps_data)
                    self._cache[pid] = {
                        "id": pid,
                        "name": pb.get("name", pid),
                        "description": pb.get("description", ""),
                        "steps": steps_data,
                        "_parsed_steps": [PlaybookStep.from_dict(s) for s in steps_data],
                        "source": "database",
                    }
                    count += 1
        except Exception as exc:
            logger.debug("[PLAYBOOK] DB load error: %s", exc)

        logger.info("[PLAYBOOK] %d playbooks available", len(self._cache))
        return count

    # ------------------------------------------------------------------ #
    #  Accessors
    # ------------------------------------------------------------------ #

    def get_playbook(self, playbook_id: str) -> Optional[Dict]:
        """Get a playbook definition by ID."""
        pb = self._cache.get(playbook_id)
        if pb:
            return {
                "id": pb.get("id", playbook_id),
                "name": pb.get("name", playbook_id),
                "description": pb.get("description", ""),
                "steps": [
                    s.to_dict() if hasattr(s, "to_dict") else s
                    for s in pb.get("_parsed_steps", pb.get("steps", []))
                ],
                "source": pb.get("source", "unknown"),
                "trigger_type": pb.get("trigger_type", "manual"),
            }
        return None

    def list_playbooks(self) -> List[Dict]:
        """List all available playbooks (built-in + database)."""
        results = []
        for pid, pb in self._cache.items():
            results.append({
                "id": pid,
                "name": pb.get("name", pid),
                "category": pb.get("category", "General"),
                "description": pb.get("description", ""),
                "step_count": len(pb.get("_parsed_steps", pb.get("steps", []))),
                "source": pb.get("source", "unknown"),
                "trigger_type": pb.get("trigger_type", "manual"),
            })
        return results

    def list_available(self) -> List[Dict]:
        """Alias for ``list_playbooks`` -- lists all available playbooks."""
        return self.list_playbooks()

    def load_playbook(self, yaml_path: str) -> Dict:
        """Load a single YAML playbook from a file path and register it.

        Args:
            yaml_path: Absolute or relative path to the YAML playbook file.

        Returns:
            Dict with playbook metadata (id, name, step_count) on success,
            or a dict with an ``error`` key on failure.
        """
        if not _HAS_YAML:
            return {"error": "PyYAML is not installed. Install with: pip install pyyaml"}

        path = Path(yaml_path)
        if not path.is_file():
            return {"error": f"Playbook file not found: {yaml_path}"}

        try:
            with open(path, "r", encoding="utf-8") as f:
                definition = yaml.safe_load(f)

            if not isinstance(definition, dict):
                return {"error": f"Invalid playbook format in {path.name} (expected a dict)"}

            pid = definition.get("id", path.stem)
            definition["id"] = pid
            definition["source"] = "file"
            definition["file"] = str(path.resolve())

            steps = definition.get("steps", [])
            if not steps:
                return {"error": f"Playbook {path.name} has no steps"}

            parsed = [PlaybookStep.from_dict(s) for s in steps]
            definition["_parsed_steps"] = parsed

            self._cache[pid] = definition

            logger.info("[PLAYBOOK] Loaded from file: %s (%d steps)", pid, len(parsed))

            return {
                "id": pid,
                "name": definition.get("name", pid),
                "description": definition.get("description", ""),
                "step_count": len(parsed),
                "source": "file",
                "file": str(path.resolve()),
            }

        except Exception as exc:
            logger.error("[PLAYBOOK] Failed to load %s: %s", yaml_path, exc)
            return {"error": f"Failed to load playbook: {exc}"}

    # ------------------------------------------------------------------ #
    #  Execution
    # ------------------------------------------------------------------ #

    def _resolve_playbook(
        self, playbook_id: str, input_data: Any,
    ) -> Tuple[Dict, str, List["PlaybookStep"], Dict]:
        """
        Look up a playbook by ID (exact, case-insensitive, or by name) and
        normalise *input_data* to a dict.

        Returns
        -------
        (pb, resolved_playbook_id, steps, normalised_input_data)

        Raises
        ------
        ValueError
            If the playbook doesn't exist or has no steps.
        """
        # --- FIX: original code had a SyntaxError here (except/elif were
        # mis-indented as if nested inside the `try` body, and `elif` had no
        # matching top-level `if`). This made the entire module fail to
        # import. Corrected below. ---
        if isinstance(input_data, str):
            try:
                input_data = json.loads(input_data) if input_data.strip() else {}
            except json.JSONDecodeError:
                input_data = {}
        elif not isinstance(input_data, dict):
            input_data = {}

        # --- FIX: avoid pointless full-cache scan when playbook_id is
        # already an exact key match; only fall back to case-insensitive /
        # name-based lookup when a direct hit isn't found. ---
        pb = self._cache.get(playbook_id)
        if pb is None:
            for cached_id, cached_pb in self._cache.items():
                if (cached_id.lower() == playbook_id.lower() or
                        cached_pb.get("name", "").lower() == playbook_id.lower()):
                    pb = cached_pb
                    playbook_id = cached_id
                    break

        if pb is None:
            raise ValueError(f"Playbook '{playbook_id}' not found")

        steps: List[PlaybookStep] = pb.get("_parsed_steps", [])
        if not steps:
            raise ValueError(f"Playbook '{playbook_id}' has no steps")

        input_data = self._fill_required_input_params(pb, input_data)

        return pb, playbook_id, steps, input_data

    @staticmethod
    def _fill_required_input_params(pb: Dict, input_data: Dict) -> Dict:
        """
        Ensure every ``required: true`` entry in the playbook's
        ``input_params`` has a value in *input_data*.

        Callers (e.g. the chat API) often don't know a playbook's exact
        parameter names in advance and instead pass generic keys like
        ``query`` / ``user_input`` / ``message``. Without this, a template
        like ``{{alert_text}}`` is left un-interpolated whenever the caller's
        key doesn't happen to match the playbook's declared param name.

        Missing required params are backfilled from the first generic key
        that has a value, in this priority order: ``query``, ``user_input``,
        ``message``. Params that already have a value in *input_data* are
        left untouched.
        """
        required_params = [
            p.get("name") for p in pb.get("input_params", [])
            if isinstance(p, dict) and p.get("required") and p.get("name")
        ]
        if not required_params:
            return input_data

        fallback_value = None
        for generic_key in ("query", "user_input", "message"):
            if input_data.get(generic_key):
                fallback_value = input_data[generic_key]
                break

        if fallback_value is None:
            return input_data

        for name in required_params:
            if not input_data.get(name):
                input_data[name] = fallback_value

        return input_data

    async def start(
        self,
        playbook_id: str,
        input_data: Any,
        case_id: Optional[str] = None,
    ) -> str:
        """
        Start a playbook run in the background and return immediately.

        Mirrors ``AgentLoop.investigate()``: the playbook is resolved and the
        session is created synchronously (so callers get an instant 404 for
        an unknown ``playbook_id``), then the actual step-by-step execution
        runs on a background thread so the HTTP request that triggered it
        doesn't block for the playbook's full duration.

        Returns
        -------
        str
            Session ID. Poll/subscribe to it (e.g. via ``/ws/agent/{id}``)
            for progress.
        """
        pb, playbook_id, steps, input_data = self._resolve_playbook(playbook_id, input_data)

        goal = f"Playbook: {pb.get('name', playbook_id)}"
        session_id = self.store.create_session(
            goal=goal, case_id=case_id, playbook_id=playbook_id,
        )

        def _run():
            asyncio.run(
                self._execute_session(session_id, playbook_id, pb, steps, input_data, case_id)
            )

        threading.Thread(
            target=_run, daemon=True, name=f"playbook-{session_id}",
        ).start()

        logger.info(
            "[PLAYBOOK] Started %s in background (session %s)",
            playbook_id, session_id,
        )
        return session_id

    async def execute(
        self,
        playbook_id: str,
        input_data: Any,
        case_id: Optional[str] = None,
    ) -> str:
        """
        Execute a playbook and block until it finishes (or hits an approval
        checkpoint).

        Use this for callers that already run off the request thread (e.g.
        the ``trigger_playbook`` action, or the LLM's ``run_playbook``
        decision inside ``AgentLoop``'s background thread). For
        HTTP-request-triggered runs, prefer ``start()`` instead so the
        request doesn't block for the playbook's full duration.

        Parameters
        ----------
        playbook_id : str
            ID of the playbook to run.
        input_data : dict
            Initial context variables (e.g. ``{"file_path": "/tmp/mal.exe"}``).
        case_id : str, optional
            Associated case ID for tracking.

        Returns
        -------
        str
            Session ID of the execution.
        """
        pb, playbook_id, steps, input_data = self._resolve_playbook(playbook_id, input_data)

        # Create a session
        goal = f"Playbook: {pb.get('name', playbook_id)}"
        session_id = self.store.create_session(
            goal=goal, case_id=case_id, playbook_id=playbook_id,
        )

        return await self._execute_session(
            session_id, playbook_id, pb, steps, input_data, case_id,
        )

    async def _execute_session(
        self,
        session_id: str,
        playbook_id: str,
        pb: Dict,
        steps: List["PlaybookStep"],
        input_data: Dict,
        case_id: Optional[str],
    ) -> str:
        """Run all steps of an already-resolved playbook for an existing
        session (fresh start, always begins at steps[0])."""

        # Execution context (variables available to steps)
        context: Dict[str, Any] = {
            "session_id": session_id,
            "playbook_id": playbook_id,
            "input": input_data,
            **input_data,
        }

        # Auto-enrich context from IPs if enabled in the playbook
        context = await self._enrich_context_if_needed(pb, context)

        # Build step lookup by name
        step_map: Dict[str, PlaybookStep] = {s.name: s for s in steps}

        logger.info(
            "[PLAYBOOK] Starting %s (session %s, %d steps)",
            playbook_id, session_id, len(steps),
        )

        return await self._run_step_loop(
            session_id, playbook_id, pb, steps, step_map, context,
            steps[0], 0, case_id,
        )

    async def execute_from_step(self, session_id: str, approved: bool) -> str:
        """Resume a playbook session paused at an approval checkpoint.

        Loads the context + pending step persisted (via
        ``AgentStore.update_session_metadata``) right before the pause in
        ``_run_step_loop``, executes (if approved) or skips (if rejected)
        the pending step, then continues the normal loop from there.
        """
        session = self.store.get_session(session_id)
        if session is None:
            raise ValueError(f"Session '{session_id}' not found")

        playbook_id = session.get("playbook_id")
        pb = self._cache.get(playbook_id)
        if pb is None:
            raise ValueError(f"Playbook '{playbook_id}' not found in cache")

        steps: List[PlaybookStep] = pb.get("_parsed_steps", [])
        step_map: Dict[str, PlaybookStep] = {s.name: s for s in steps}

        metadata = session.get("metadata") or {}
        if not isinstance(metadata, dict) or "pending_step_name" not in metadata:
            raise ValueError(
                f"Session '{session_id}' has no pending approval checkpoint to resume"
            )

        context: Dict[str, Any] = metadata.get("context", {})
        step_number: int = metadata.get("step_number", 0)
        pending_step_name: str = metadata["pending_step_name"]
        pending_step = step_map.get(pending_step_name)
        if pending_step is None:
            raise ValueError(
                f"Pending step '{pending_step_name}' no longer exists in "
                f"playbook '{playbook_id}'"
            )

        case_id = metadata.get("case_id")

        if approved:
            params = self._interpolate_params(pending_step.params, context)
            self.agent_loop._notify(session_id, {
                "type": "tool_call", "step": step_number,
                "tool": pending_step.tool, "args": params,
            })
            start = time.time()
            result = await self._run_tool(
                pending_step.tool, params, pending_step.timeout,
            )
            duration_ms = int((time.time() - start) * 1000)
            self.agent_loop._notify(session_id, {
                "type": "tool_result", "step": step_number,
                "tool": pending_step.tool,
                "result_preview": str(result)[:500],
                "duration": duration_ms,
            })

            self.store.add_step(
                session_id=session_id,
                step_number=step_number,
                step_type="tool_call",
                content=pending_step.description or pending_step.name,
                tool_name=pending_step.tool,
                tool_params=json.dumps(params, default=str),
                tool_result=json.dumps(result, default=str)[:10000],
                duration_ms=duration_ms,
            )
            action_status = "error" if isinstance(result, dict) and "error" in result else "success"
            self.store.add_audit_entry(
                session_id=session_id,
                action=pending_step.tool,
                action_type="approval_granted",
                actor="human",
                requires_approval=True,
                before_state=params,
                after_state=result,
                approved_by=metadata.get("approver"),
                status=action_status,
            )
            if self.notification_manager:
                try:
                    self.notification_manager.notify("action_executed", {
                        "tool": pending_step.tool,
                        "session_id": session_id,
                        "status": action_status,
                    })
                except Exception as notify_exc:
                    logger.warning(
                        "[PLAYBOOK] Notification dispatch failed: %s", notify_exc,
                    )

            context[pending_step.name] = result
            context["last_result"] = result
            if isinstance(result, dict):
                for key, val in result.items():
                    context[f"{pending_step.name}_{key}"] = val

            success = not (isinstance(result, dict) and "error" in result)
            next_step_name = pending_step.on_success if success else pending_step.on_failure
        else:
            self.store.add_step(
                session_id=session_id,
                step_number=step_number,
                step_type="approval_rejected",
                content=f"Approval rejected: {pending_step.description or pending_step.name}",
                tool_name=pending_step.tool,
            )
            self.store.add_audit_entry(
                session_id=session_id,
                action=pending_step.tool,
                action_type="approval_rejected",
                actor="human",
                requires_approval=True,
                before_state=self._interpolate_params(pending_step.params, context),
                approved_by=metadata.get("approver"),
                status="rejected",
            )
            next_step_name = pending_step.on_failure

        next_step = self._resolve_next(next_step_name, step_map, steps, step_number)

        self.store.update_session_status(session_id, "active")

        return await self._run_step_loop(
            session_id, playbook_id, pb, steps, step_map, context,
            next_step, step_number, case_id,
        )

    async def _run_step_loop(
        self,
        session_id: str,
        playbook_id: str,
        pb: Dict,
        steps: List["PlaybookStep"],
        step_map: Dict[str, "PlaybookStep"],
        context: Dict[str, Any],
        current_step: Optional["PlaybookStep"],
        step_number: int,
        case_id: Optional[str],
    ) -> str:
        """Run the step loop starting at *current_step* / *step_number* with
        the given *context*. Shared by a fresh ``_execute_session`` start
        (step 0) and ``execute_from_step`` resuming after an approval gate."""
        try:
            while current_step is not None:
                step_number += 1

                # Safety: prevent infinite loops
                if step_number > 200:
                    logger.error("[PLAYBOOK] Step limit (200) reached -- aborting")
                    self.store.update_session_status(
                        session_id, "failed",
                        summary="Aborted: exceeded maximum step count (200)",
                    )
                    return session_id

                # Pure decision/branch step: มี condition แต่ไม่มี tool/action/for_each เลย
                # แปลว่าเป็น branch node ล้วน ๆ (if/then/else) ไม่ใช่ tool ที่มี precondition
                # ต้อง resolve ทันทีจากผลของ condition โดยไม่ตกไป execute เป็น tool call
                if (current_step.condition and not current_step.tool
                        and not current_step.action and not current_step.for_each):
                    decision_result = self.evaluate_condition(current_step.condition, context)
                    next_step_name = (
                        current_step.on_success if decision_result else current_step.on_failure
                    )
                    logger.info(
                        "[PLAYBOOK] Decision step '%s': condition=%s -> next='%s'",
                        current_step.name, decision_result, next_step_name,
                    )
                    self.store.add_step(
                        session_id=session_id,
                        step_number=step_number,
                        step_type="decision",
                        content=(
                            f"{current_step.description or current_step.name}: "
                            f"condition evaluated to {decision_result}"
                        ),
                        tool_name="",
                        tool_params="",
                        tool_result=json.dumps({"decision": decision_result}, default=str),
                        duration_ms=0,
                    )
                    context[current_step.name] = {"decision": decision_result}
                    context["last_result"] = context[current_step.name]
                    current_step = self._resolve_next(
                        next_step_name, step_map, steps, step_number,
                    )
                    continue

                # Evaluate condition (gate สำหรับ step ที่มี tool ควบคู่กับ condition -- ของเดิม)
                if current_step.condition:
                    if not self.evaluate_condition(current_step.condition, context):
                        logger.debug(
                            "[PLAYBOOK] Skipping step '%s' (condition false)",
                            current_step.name,
                        )
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, step_number,
                        )
                        continue

                    # Human approval checkpoint
                if current_step.requires_approval:
                    logger.info(
                        "[PLAYBOOK] Step '%s' requires human approval -- pausing",
                        current_step.name,
                    )
                    self.store.add_step(
                        session_id=session_id,
                        step_number=step_number,
                        step_type="approval_required",
                        content=f"Waiting for approval: {current_step.description or current_step.name}",
                        tool_name=current_step.tool,
                        tool_params=json.dumps(
                            self._interpolate_params(current_step.params, context),
                            default=str,
                        ),
                    )
                    self.store.add_audit_entry(
                        session_id=session_id,
                        action=current_step.tool,
                        action_type="approval_required",
                        actor="system",
                        requires_approval=True,
                        before_state=self._interpolate_params(current_step.params, context),
                        status="pending",
                    )
                    if self.notification_manager:
                        try:
                            self.notification_manager.notify("approval_required", {
                                "tool": current_step.tool,
                                "session_id": session_id,
                                "description": current_step.description or current_step.name,
                            })
                        except Exception as notify_exc:
                            logger.warning(
                                "[PLAYBOOK] Notification dispatch failed: %s", notify_exc,
                            )
                    # Persist context + pending step so execute_from_step can
                    # resume exactly where this run paused.
                    self.store.update_session_metadata(session_id, {
                        "context": context,
                        "pending_step_name": current_step.name,
                        "step_number": step_number,
                        "case_id": case_id,
                    })
                    self.store.update_session_status(session_id, "waiting_approval")
                    self.agent_loop._notify(session_id, {
                        "type": "approval_required",
                        "tool": current_step.tool,
                        "description": current_step.description or current_step.name,
                    })

                    # Execution pauses here. Call execute_from_step(session_id,
                    # approved) to resume -- it reloads the persisted
                    # context/pending step and continues the loop.
                    return session_id

                # Handle action-only steps (no tool call needed)
                if current_step.action and not current_step.tool:
                    action = current_step.action
                    params = self._interpolate_params(current_step.params, context)

                    if action == "final_answer":
                        # Terminal step: record description as final report
                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="final_answer",
                            content=current_step.description or current_step.name,
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result=json.dumps(
                                {"action": "final_answer", "report": current_step.description},
                                default=str,
                            ),
                            duration_ms=0,
                        )
                        context[current_step.name] = {
                            "action": "final_answer",
                            "report": current_step.description,
                        }
                        context["last_result"] = context[current_step.name]
                        # final_answer is terminal — go to next sequential or end
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, step_number,
                        )
                        continue

                    elif action == "trigger_playbook":
                        # Trigger another playbook
                        target_pb = params.get("playbook", "")
                        trigger_input = {k: v for k, v in params.items() if k != "playbook"}
                        trigger_input.update({k: v for k, v in context.items()
                                              if k not in ("session_id", "playbook_id", "input")})

                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="trigger_playbook",
                            content=f"Triggering playbook: {target_pb}",
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result="",
                            duration_ms=0,
                        )

                        try:
                            sub_session = await self.execute(
                                target_pb, trigger_input, case_id=case_id,
                            )
                            context[current_step.name] = {
                                "action": "trigger_playbook",
                                "playbook": target_pb,
                                "sub_session_id": sub_session,
                            }
                        except Exception as exc:
                            logger.warning(
                                "[PLAYBOOK] trigger_playbook '%s' failed: %s",
                                target_pb, exc,
                            )
                            context[current_step.name] = {
                                "action": "trigger_playbook",
                                "playbook": target_pb,
                                "error": str(exc),
                            }
                        context["last_result"] = context[current_step.name]
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, step_number,
                        )
                        continue

                    elif action == "input":
                        # Input step: use existing context data or record prompt
                        prompt = params.get("prompt", current_step.description)
                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="input",
                            content=f"Input: {prompt}",
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result=json.dumps(
                                {"action": "input", "prompt": prompt, "value": prompt},
                                default=str,
                            ),
                            duration_ms=0,
                        )
                        context[current_step.name] = {
                            "action": "input",
                            "value": prompt,
                        }
                        context["last_result"] = context[current_step.name]
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, step_number,
                        )
                        continue

                    else:
                        # Unknown action — log and skip
                        logger.warning(
                            "[PLAYBOOK] Unknown action '%s' in step '%s'",
                            action, current_step.name,
                        )
                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="action",
                            content=f"Action: {action} - {current_step.description}",
                            tool_name="",
                            tool_params=json.dumps(params, default=str),
                            tool_result="",
                            duration_ms=0,
                        )
                        context[current_step.name] = {"action": action}
                        context["last_result"] = context[current_step.name]
                        current_step = self._resolve_next(
                            current_step.on_success, step_map, steps, step_number,
                        )
                        continue

                # Handle for_each iteration
                if current_step.for_each:
                    items = _resolve_var(current_step.for_each, context)
                    if not isinstance(items, list):
                        items = [items] if items else []

                    logger.debug(
                        "[PLAYBOOK] for_each '%s': %d items",
                        current_step.for_each, len(items),
                    )

                    iteration_results = []
                    for i, item in enumerate(items[:50]):  # Cap iterations
                        iter_context = {**context, "item": item, "item_index": i}
                        params = self._interpolate_params(current_step.params, iter_context)

                        self.agent_loop._notify(session_id, {
                            "type": "tool_call", "step": step_number,
                            "tool": current_step.tool, "args": params,
                        })
                        start = time.time()
                        result = await self._run_tool(
                            current_step.tool, params, current_step.timeout,
                        )
                        duration_ms = int((time.time() - start) * 1000)
                        self.agent_loop._notify(session_id, {
                            "type": "tool_result", "step": step_number,
                            "tool": current_step.tool,
                            "result_preview": str(result)[:500],
                            "duration": duration_ms,
                        })

                        iteration_results.append(result)

                        self.store.add_step(
                            session_id=session_id,
                            step_number=step_number,
                            step_type="for_each_iteration",
                            content=f"{current_step.name} (item {i})",
                            tool_name=current_step.tool,
                            tool_params=json.dumps(params, default=str),
                            tool_result=json.dumps(result, default=str)[:10000],
                            duration_ms=duration_ms,
                        )

                    context[f"{current_step.name}_results"] = iteration_results
                    context["last_result"] = iteration_results

                    # Determine success
                    has_error = any("error" in r for r in iteration_results if isinstance(r, dict))
                    next_step_name = current_step.on_failure if has_error else current_step.on_success

                else:
                    # Single execution
                    params = self._interpolate_params(current_step.params, context)

                    self.agent_loop._notify(session_id, {
                        "type": "tool_call", "step": step_number,
                        "tool": current_step.tool, "args": params,
                    })
                    start = time.time()
                    result = await self._run_tool(
                        current_step.tool, params, current_step.timeout,
                    )
                    duration_ms = int((time.time() - start) * 1000)
                    self.agent_loop._notify(session_id, {
                        "type": "tool_result", "step": step_number,
                        "tool": current_step.tool,
                        "result_preview": str(result)[:500],
                        "duration": duration_ms,
                    })

                    # Record step
                    self.store.add_step(
                        session_id=session_id,
                        step_number=step_number,
                        step_type="tool_call",
                        content=current_step.description or current_step.name,
                        tool_name=current_step.tool,
                        tool_params=json.dumps(params, default=str),
                        tool_result=json.dumps(result, default=str)[:10000],
                        duration_ms=duration_ms,
                    )

                    # Store result in context
                    context[current_step.name] = result
                    context["last_result"] = result

                    # Also expose nested result fields
                    if isinstance(result, dict):
                        for key, val in result.items():
                            context[f"{current_step.name}_{key}"] = val

                    # Determine next step
                    success = not (isinstance(result, dict) and "error" in result)
                    next_step_name = (
                        current_step.on_success if success else current_step.on_failure
                    )

                # Resolve the next step
                current_step = self._resolve_next(
                    next_step_name, step_map, steps, step_number,
                )

            # All steps completed
            highest_verdict = _find_highest_verdict(context)
            summary = (
                f"Playbook '{pb.get('name', playbook_id)}' completed "
                f"({step_number} steps executed)"
            )
            if highest_verdict:
                summary += f" — highest verdict: {highest_verdict}"
            self.store.update_session_status(session_id, "completed", summary=summary)
            self.agent_loop._notify(session_id, {"type": "completed", "summary": summary})
            logger.info(
                "[PLAYBOOK] Completed %s (session %s, %d steps)",
                playbook_id, session_id, step_number,
            )

        except Exception as exc:
            logger.error(
                "[PLAYBOOK] Execution error in %s step %d: %s",
                playbook_id, step_number, exc,
            )
            self.store.add_step(
                session_id=session_id,
                step_number=step_number,
                step_type="error",
                content=f"Playbook error: {exc}",
            )
            self.store.update_session_status(
                session_id, "failed", summary=f"Error: {str(exc)[:200]}",
            )
            self.agent_loop._notify(session_id, {"type": "failed", "error": str(exc)[:200]})

        return session_id

    # ------------------------------------------------------------------ #
    #  Condition evaluation
    # ------------------------------------------------------------------ #

    def evaluate_condition(self, condition: str, context: Dict) -> bool:
        """
        Evaluate a step condition against the current context.

        Delegates to ``safe_evaluate_condition`` which uses pattern matching
        instead of eval() for safety.

        Supported syntax:
        - ``verdict == 'MALICIOUS'``
        - ``score > 70``
        - ``score >= 50 and verdict != 'CLEAN'``
        - ``'ransomware' in tags``
        - ``file_type in ('PE', 'ELF')``
        """
        return safe_evaluate_condition(condition, context)

    async def _enrich_context_if_needed(self, pb: Dict, context: Dict) -> Dict:
        """
        If the playbook has `auto_enrich_context: true`, find related IOCs.

        Specifically, if the context only contains an IP address, this function
        will attempt to find related domains and file hashes from VirusTotal
        to allow other playbook steps (like file analysis) to run.
        """
        if not pb.get("auto_enrich_context"):
            return context

        if not self.threat_intel:
            logger.warning("[PLAYBOOK] Skipping enrichment: ThreatIntel not available.")
            return context

        has_ips = bool(context.get("ip_addresses") or context.get("ip_address"))
        has_domains = bool(context.get("domains") or context.get("domain"))
        has_hashes = bool(context.get("file_hashes") or context.get("hash"))

        if not (has_ips and not has_domains and not has_hashes):
            return context

        ips = context.get("ip_addresses") or [context.get("ip_address")]
        ips = [ip for ip in ips if ip]

        if not ips:
            return context

        logger.info(f"[PLAYBOOK] Auto-enriching context for {len(ips)} IP(s)...")

        if "domains" not in context:
            context["domains"] = []
        if "file_hashes" not in context:
            context["file_hashes"] = []

        for ip in ips:
            try:
                logger.debug(f"[PLAYBOOK] Getting raw VT report for IP: {ip}")
                report = await asyncio.wait_for(
                    self.threat_intel.get_raw_virustotal_report(ip, "ipv4"),
                    timeout=15.0,
                )

                if "error" in report or "data" not in report:
                    logger.warning(f"[PLAYBOOK] Enrichment for {ip} failed: {report.get('error', 'No data')}")
                    continue

                relationships = report["data"].get("relationships", {})

                # Extract domains from resolutions
                resolutions = relationships.get("resolutions", {}).get("data", [])
                found_domains = [res["id"] for res in resolutions if res.get("type") == "domain"]
                new_domains = [d for d in found_domains if d not in context["domains"]]
                if new_domains:
                    context["domains"].extend(new_domains)
                    logger.info(f"[PLAYBOOK] Enriched {len(new_domains)} domains for {ip}")

                # Extract hashes from files
                comm_files = relationships.get("communicating_files", {}).get("data", [])
                down_files = relationships.get("downloaded_files", {}).get("data", [])
                found_hashes = [f["id"] for f in comm_files + down_files]
                new_hashes = [h for h in found_hashes if h not in context["file_hashes"]]
                if new_hashes:
                    context["file_hashes"].extend(new_hashes)
                    logger.info(f"[PLAYBOOK] Enriched {len(new_hashes)} file hashes for {ip}")

            except asyncio.TimeoutError:
                logger.warning(
                    f"[PLAYBOOK] Context enrichment timed out for IP: {ip}. Proceeding."
                )
            except Exception as e:
                logger.warning(
                    f"[PLAYBOOK] Context enrichment failed for IP: {ip} (error: {e}). Proceeding."
                )

        return context


    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    async def _run_tool(self, tool_name: str, params: Dict, timeout: int) -> Dict:
        """
        Run a tool via the agent loop with a timeout.

        Returns the tool result dict, or an ``error`` dict on failure/timeout.
        """
        try:
            if hasattr(self.agent_loop, "run_tool"):
                import asyncio
                result = await asyncio.wait_for(
                    self.agent_loop.run_tool(tool_name, params),
                    timeout=timeout,
                )
                return result if isinstance(result, dict) else {"result": result}
            else:
                return {"error": "agent_loop has no run_tool method"}
        except TimeoutError:
            return {"error": f"Tool '{tool_name}' timed out after {timeout}s"}
        except Exception as exc:
            return {"error": f"Tool '{tool_name}' failed: {exc}"}

    def _interpolate_params(self, params: Dict, context: Dict) -> Dict:
        """
        Replace ``{{variable}}`` placeholders in parameter values with
        values from the context.

        Supports:
        - ``{{file_path}}`` -- simple variable
        - ``{{step_name.field}}`` -- nested access
        - ``{{item}}`` -- current for_each item
        """
        result = {}
        for key, value in params.items():
            if isinstance(value, str):
                result[key] = self._interpolate_string(value, context)
            elif isinstance(value, dict):
                result[key] = self._interpolate_params(value, context)
            elif isinstance(value, list):
                result[key] = [
                    self._interpolate_string(v, context) if isinstance(v, str) else v
                    for v in value
                ]
            else:
                result[key] = value
        return result

    @staticmethod
    def _interpolate_string(template: str, context: Dict) -> str:
        """Replace ``{{var}}`` tokens in a string."""

        def _replacer(match):
            var_path = match.group(1).strip()
            resolved = _resolve_var(var_path, context)
            if resolved is not None:
                return str(resolved)
            return match.group(0)  # Leave placeholder as-is

        return re.sub(r"\{\{(.+?)\}\}", _replacer, template)

    @staticmethod
    def _resolve_next(
        next_name: Optional[str],
        step_map: Dict[str, PlaybookStep],
        steps: List[PlaybookStep],
        current_index: int,
    ) -> Optional[PlaybookStep]:
        """
        Resolve the next step to execute.

        If ``next_name`` is given, look it up in ``step_map``.
        Otherwise fall through to the next sequential step.
        ``None`` means the playbook is done.
        """
        if next_name == "__end__" or next_name == "end":
            return None

        if next_name:
            return step_map.get(next_name)

        # Default: next sequential step
        if current_index < len(steps):
            return steps[current_index]

        return None

    # ------------------------------------------------------------------ #
    #  Playbook creation
    # ------------------------------------------------------------------ #

    def register_playbook(
        self,
        name: str,
        description: str,
        steps: List[Dict],
        trigger_type: str = "manual",
    ) -> str:
        """
        Register a new playbook (saved to DB and cache).

        Returns the playbook ID.
        """
        # Validate steps
        parsed = [PlaybookStep.from_dict(s) for s in steps]

        pid = self.store.save_playbook(
            name=name,
            description=description,
            steps=steps,
            trigger_type=trigger_type,
        )

        self._cache[pid] = {
            "id": pid,
            "name": name,
            "description": description,
            "steps": steps,
            "_parsed_steps": parsed,
            "source": "database",
            "trigger_type": trigger_type,
        }

        logger.info("[PLAYBOOK] Registered: %s (%d steps)", name, len(parsed))
        return pid