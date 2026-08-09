"""
Tests for the audit_log table and AgentStore.add_audit_entry/get_audit_log.
Uses a temp SQLite file so it never touches the real ~/.blue-team-assistant DB.
"""

import json
import os
import tempfile
import unittest

from src.agent.agent_store import AgentStore


class TestAuditLog(unittest.TestCase):

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.store = AgentStore(db_path=self.db_path)
        self.session_id = self.store.create_session(goal="test audit session")

    def tearDown(self):
        try:
            os.remove(self.db_path)
        except OSError:
            pass

    def test_add_and_get_basic_tool_call(self):
        entry_id = self.store.add_audit_entry(
            session_id=self.session_id,
            action="investigate_ioc",
            action_type="tool_call",
            actor="agent",
            after_state={"verdict": "MALICIOUS", "score": 87},
            status="success",
        )
        self.assertTrue(entry_id)

        entries = self.store.get_audit_log(session_id=self.session_id)
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e["action"], "investigate_ioc")
        self.assertEqual(e["action_type"], "tool_call")
        self.assertEqual(e["requires_approval"], 0)
        self.assertEqual(e["after_state"]["verdict"], "MALICIOUS")

    def test_containment_action_with_approval(self):
        self.store.add_audit_entry(
            session_id=self.session_id,
            action="isolate_device",
            action_type="approval_granted",
            actor="agent",
            requires_approval=True,
            approved_by="analyst_01",
            before_state={"device_id": "host-01"},
            after_state={"status": "success", "simulated": True},
            status="success",
        )
        entries = self.store.get_audit_log(session_id=self.session_id)
        e = entries[0]
        self.assertEqual(e["requires_approval"], 1)
        self.assertEqual(e["approved_by"], "analyst_01")
        self.assertEqual(e["before_state"]["device_id"], "host-01")

    def test_get_audit_log_filters_by_session(self):
        other_session = self.store.create_session(goal="other session")
        self.store.add_audit_entry(session_id=self.session_id, action="tool_a")
        self.store.add_audit_entry(session_id=other_session, action="tool_b")

        entries = self.store.get_audit_log(session_id=self.session_id)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["action"], "tool_a")

        all_entries = self.store.get_audit_log()
        self.assertEqual(len(all_entries), 2)

    def test_get_audit_log_newest_first(self):
        self.store.add_audit_entry(session_id=self.session_id, action="first")
        self.store.add_audit_entry(session_id=self.session_id, action="second")

        entries = self.store.get_audit_log(session_id=self.session_id)
        self.assertEqual(entries[0]["action"], "second")
        self.assertEqual(entries[1]["action"], "first")


if __name__ == "__main__":
    unittest.main()