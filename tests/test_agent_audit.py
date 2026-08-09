"""
Integration tests verifying AgentLoop persists audit_log entries via
AgentStore.add_audit_entry -- for every tool call (_act) and for every
human approval decision (_run_loop approval gate).
"""

import asyncio
import unittest
from unittest import mock
from unittest.mock import MagicMock

from src.agent.agent_loop import AgentLoop
from src.agent.agent_state import AgentState
from src.agent.tool_registry import ToolRegistry


class TestAgentAuditLogging(unittest.TestCase):

    def setUp(self):
        self.tool_registry = ToolRegistry()
        self.tool_registry.register_default_tools({})

        self.agent_store = MagicMock()

        self.agent_loop = AgentLoop(
            config={},
            tool_registry=self.tool_registry,
            agent_store=self.agent_store,
            llm_analyzer=None,
            mcp_client=None,
        )

    def test_act_logs_tool_call_audit_entry(self):
        state = AgentState(session_id="sess-1", goal="test", max_steps=10)
        decision = {
            "action": "use_tool",
            "tool": "isolate_device",
            "params": {"device_id": "host-01"},
        }

        result = asyncio.run(self.agent_loop._act(state, decision))

        self.assertNotIn("error", result)
        calls = self.agent_store.add_audit_entry.call_args_list
        self.assertEqual(len(calls), 1)
        kwargs = calls[0].kwargs
        self.assertEqual(kwargs["session_id"], "sess-1")
        self.assertEqual(kwargs["action"], "isolate_device")
        self.assertEqual(kwargs["action_type"], "tool_call")
        self.assertEqual(kwargs["status"], "success")
        self.assertTrue(kwargs["requires_approval"])  # isolate_device is is_dangerous

    def test_act_logs_error_status_on_unknown_tool(self):
        state = AgentState(session_id="sess-2", goal="test", max_steps=10)
        decision = {"action": "use_tool", "tool": "nonexistent_tool", "params": {}}

        result = asyncio.run(self.agent_loop._act(state, decision))

        self.assertIn("error", result)
        kwargs = self.agent_store.add_audit_entry.call_args.kwargs
        self.assertEqual(kwargs["status"], "error")
        self.assertFalse(kwargs["requires_approval"])

    def test_run_loop_logs_approval_and_tool_call_audit_entries(self):
        """Real end-to-end run through _run_loop: a dangerous tool triggers
        the approval gate, gets approved, executes, then the loop ends on
        a final_answer -- verifying both audit entry types get persisted."""
        session_id = "sess-3"
        state = AgentState(session_id=session_id, goal="test goal", max_steps=10)
        self.agent_loop._active_sessions[session_id] = state
        self.agent_loop._approval_events[session_id] = asyncio.Event()
        self.agent_store.create_session.return_value = session_id

        decisions = [
            {"action": "use_tool", "tool": "block_ip", "params": {"ip_address": "203.0.113.5"}},
            {"action": "final_answer", "answer": "done", "verdict": "MALICIOUS"},
        ]

        async def fake_think(_state):
            return decisions.pop(0) if decisions else {
                "action": "final_answer", "answer": "x", "verdict": "UNKNOWN",
            }

        async def auto_approve():
            for _ in range(200):
                if state.pending_approval is not None:
                    await self.agent_loop.approve_action(session_id)
                    return
                await asyncio.sleep(0.01)

        async def drive():
            with mock.patch.object(self.agent_loop, "_think", side_effect=fake_think):
                await asyncio.gather(
                    self.agent_loop._run_loop(session_id),
                    auto_approve(),
                )

        asyncio.run(drive())

        action_types = [
            c.kwargs.get("action_type")
            for c in self.agent_store.add_audit_entry.call_args_list
        ]
        self.assertIn("approval_granted", action_types)
        self.assertIn("tool_call", action_types)


if __name__ == "__main__":
    unittest.main()