"""
Integration test: verify PlaybookEngine can invoke real containment tools
(isolate_device / block_ip / quarantine_file) through the real ToolRegistry
and AgentLoop, without mocking the tool dispatch chain.

Covers P0.2: playbook_engine -> agent_loop.run_tool() -> tool_registry.execute_local_tool()
"""

import asyncio
import os
import tempfile
import unittest
from unittest.mock import MagicMock

from src.agent.agent_store import AgentStore
from src.agent.tool_registry import ToolRegistry
from src.agent.agent_loop import AgentLoop
from src.agent.playbook_engine import PlaybookEngine, PlaybookStep


class TestPlaybookContainmentChain(unittest.TestCase):

    def setUp(self):
        """Real ToolRegistry (with default tools registered) + real AgentLoop,
        only agent_store is mocked (persistence is not what this test verifies)."""
        self.tool_registry = ToolRegistry()
        self.tool_registry.register_default_tools({})

        self.agent_store = MagicMock()
        self.agent_store.create_session.return_value = "sess-test-001"

        self.agent_loop = AgentLoop(
            config={},
            tool_registry=self.tool_registry,
            agent_store=self.agent_store,
            llm_analyzer=None,
            mcp_client=None,
        )

        self.engine = PlaybookEngine(self.agent_loop, self.agent_store)

        steps = [
            {
                "name": "isolate_test",
                "tool": "isolate_device",
                "params": {"device_id": "host-01", "isolation_type": "network"},
                "requires_approval": True,
                "description": "Test isolate step",
            }
        ]
        self.engine._cache["test_containment"] = {
            "id": "test_containment",
            "name": "Test Containment",
            "steps": steps,
            "_parsed_steps": [PlaybookStep.from_dict(s) for s in steps],
            "source": "test",
        }

    def test_requires_approval_step_halts_without_error(self):
        session_id = asyncio.run(self.engine.execute("test_containment", {}))

        self.assertEqual(session_id, "sess-test-001")

        status_calls = [c.args for c in self.agent_store.update_session_status.call_args_list]
        self.assertTrue(
            any(call[1] == "waiting_approval" for call in status_calls),
            f"Expected a waiting_approval status update, got: {status_calls}",
        )
        self.assertFalse(
            any(call[1] == "failed" for call in status_calls),
            f"Playbook should not fail on an approval gate, got: {status_calls}",
        )

        add_step_calls = self.agent_store.add_step.call_args_list
        approval_step = [
            c for c in add_step_calls
            if c.kwargs.get("step_type") == "approval_required"
        ]
        self.assertEqual(len(approval_step), 1)
        self.assertEqual(approval_step[0].kwargs.get("tool_name"), "isolate_device")

    def test_isolate_device_executes_via_agent_loop_run_tool(self):
        result = asyncio.run(
            self.agent_loop.run_tool(
                "isolate_device", {"device_id": "host-02", "isolation_type": "network"}
            )
        )
        self.assertNotIn("error", result, f"isolate_device errored: {result}")

    def test_block_ip_executes_via_agent_loop_run_tool(self):
        result = asyncio.run(
            self.agent_loop.run_tool(
                "block_ip", {"ip_address": "203.0.113.5", "reason": "test"}
            )
        )
        self.assertNotIn("error", result, f"block_ip errored: {result}")

    def test_quarantine_file_missing_source_is_handled_gracefully(self):
        result = asyncio.run(
            self.agent_loop.run_tool(
                "quarantine_file", {"file_path": "C:\\nonexistent\\file.exe"}
            )
        )
        self.assertIsInstance(result, dict)


class TestPlaybookPureDecisionStepRouting(unittest.TestCase):
    """Regression coverage for a pure decision/branch step (condition with
    if/then/else but no tool/action/for_each) being routed correctly by
    ``_run_step_loop``, instead of falling through to a tool-call attempt or
    inverting on_success/on_failure."""

    def setUp(self):
        """Real ToolRegistry + real AgentLoop + real AgentStore (temp SQLite
        file), so step routing is asserted against actual persisted DB rows."""
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.agent_store = AgentStore(db_path=self.db_path)

        self.tool_registry = ToolRegistry()
        self.tool_registry.register_default_tools({})

        self.agent_loop = AgentLoop(
            config={},
            tool_registry=self.tool_registry,
            agent_store=self.agent_store,
            llm_analyzer=None,
            mcp_client=None,
        )

        self.engine = PlaybookEngine(self.agent_loop, self.agent_store)

        steps = [
            {
                "name": "evaluate_severity",
                "condition": {
                    "if": "score > 50",
                    "then": "high_severity_path",
                    "else": "low_severity_path",
                },
                "description": "Branch on severity score",
            },
            {
                "name": "high_severity_path",
                "action": "final_answer",
                "description": "Handled as high severity",
                "on_success": "__end__",
            },
            {
                "name": "low_severity_path",
                "action": "final_answer",
                "description": "Handled as low severity",
                "on_success": "__end__",
            },
        ]
        self.engine._cache["test_decision_routing"] = {
            "id": "test_decision_routing",
            "name": "Test Decision Routing",
            "steps": steps,
            "_parsed_steps": [PlaybookStep.from_dict(s) for s in steps],
            "source": "test",
        }

    def tearDown(self):
        try:
            os.remove(self.db_path)
        except OSError:
            pass

    def test_pure_decision_step_true_routes_to_on_success(self):
        session_id = asyncio.run(
            self.engine.execute("test_decision_routing", {"score": 80})
        )

        recorded_steps = self.agent_store.get_steps(session_id)
        step_contents = [s.get("content", "") for s in recorded_steps]

        self.assertTrue(
            any("Handled as high severity" in c for c in step_contents),
            f"Expected the high-severity (on_success) step to execute, got steps: {step_contents}",
        )
        self.assertFalse(
            any("Handled as low severity" in c for c in step_contents),
            f"Should not have taken the low-severity (on_failure) branch, got steps: {step_contents}",
        )

        decision_steps = [s for s in recorded_steps if s.get("step_type") == "decision"]
        self.assertEqual(len(decision_steps), 1)

    def test_pure_decision_step_false_routes_to_on_failure(self):
        session_id = asyncio.run(
            self.engine.execute("test_decision_routing", {"score": 10})
        )

        recorded_steps = self.agent_store.get_steps(session_id)
        step_contents = [s.get("content", "") for s in recorded_steps]

        self.assertTrue(
            any("Handled as low severity" in c for c in step_contents),
            f"Expected the low-severity (on_failure) step to execute, got steps: {step_contents}",
        )
        self.assertFalse(
            any("Handled as high severity" in c for c in step_contents),
            f"Should not have taken the high-severity (on_success) branch, got steps: {step_contents}",
        )

        decision_steps = [s for s in recorded_steps if s.get("step_type") == "decision"]
        self.assertEqual(len(decision_steps), 1)


if __name__ == "__main__":
    unittest.main()