"""Tests for AgentLoop approval tracking with approved_by field."""

from unittest.mock import MagicMock, AsyncMock, patch
import asyncio
import pytest

from src.agent.agent_loop import AgentLoop
from src.agent.agent_state import AgentState, AgentPhase


@pytest.fixture
def mock_agent_loop():
    """Create a minimal AgentLoop for testing."""
    config = {
        'agent': {'max_steps': 50},
        'llm': {'provider': 'ollama', 'model': 'llama3.2:3b'},
    }
    tool_registry = MagicMock()
    agent_store = MagicMock()

    loop = AgentLoop(
        config=config,
        tool_registry=tool_registry,
        agent_store=agent_store,
    )
    return loop


@pytest.fixture
def active_session(mock_agent_loop):
    """Create an active session with pending approval."""
    session_id = "test-session-1"
    state = AgentState(
        session_id=session_id,
        goal="Test investigation",
        max_steps=50,
    )

    # Simulate pending approval
    state.request_approval(
        {"tool": "test_tool", "params": {"key": "value"}},
        "Test requires approval",
    )

    mock_agent_loop._active_sessions[session_id] = state
    mock_agent_loop._approval_events[session_id] = asyncio.Event()

    return session_id, state, mock_agent_loop


class TestApproveAction:
    """Test approve_action() stores approved_by correctly."""

    @pytest.mark.asyncio
    async def test_approve_action_stores_approved_by_field(self, active_session):
        """approve_action should store approved_by in pending_approval dict."""
        session_id, state, loop = active_session

        result = await loop.approve_action(session_id, approved_by="analyst1")

        assert result is True
        assert state.pending_approval is not None
        assert state.pending_approval["approved"] is True
        assert state.pending_approval["approved_by"] == "analyst1"

    @pytest.mark.asyncio
    async def test_approve_action_default_unknown_when_not_provided(self, active_session):
        """approve_action should default to 'unknown' if approved_by not provided."""
        session_id, state, loop = active_session

        result = await loop.approve_action(session_id)

        assert result is True
        assert state.pending_approval["approved"] is True
        assert state.pending_approval["approved_by"] == "unknown"

    @pytest.mark.asyncio
    async def test_approve_action_returns_false_when_no_pending_approval(self, mock_agent_loop):
        """approve_action should return False if no pending approval exists."""
        session_id = "nonexistent-session"

        result = await mock_agent_loop.approve_action(session_id, approved_by="analyst1")

        assert result is False


class TestRejectAction:
    """Test reject_action() stores approved_by correctly."""

    @pytest.mark.asyncio
    async def test_reject_action_stores_approved_by_field(self, active_session):
        """reject_action should store approved_by in pending_approval dict."""
        session_id, state, loop = active_session

        result = await loop.reject_action(session_id, approved_by="analyst2")

        assert result is True
        assert state.pending_approval is not None
        assert state.pending_approval["approved"] is False
        assert state.pending_approval["approved_by"] == "analyst2"

    @pytest.mark.asyncio
    async def test_reject_action_default_unknown_when_not_provided(self, active_session):
        """reject_action should default to 'unknown' if approved_by not provided."""
        session_id, state, loop = active_session

        result = await loop.reject_action(session_id)

        assert result is True
        assert state.pending_approval["approved"] is False
        assert state.pending_approval["approved_by"] == "unknown"

    @pytest.mark.asyncio
    async def test_reject_action_returns_false_when_no_pending_approval(self, mock_agent_loop):
        """reject_action should return False if no pending approval exists."""
        session_id = "nonexistent-session"

        result = await mock_agent_loop.reject_action(session_id, approved_by="analyst2")

        assert result is False


class TestWaitForApproval:
    """Test _wait_for_approval() returns tuple (bool, str)."""

    @pytest.mark.asyncio
    async def test_wait_for_approval_returns_tuple_on_approval(self, active_session):
        """_wait_for_approval should return (True, 'analyst1') when approved."""
        session_id, state, loop = active_session

        # Set up approval in background
        async def set_approval():
            await asyncio.sleep(0.1)
            await loop.approve_action(session_id, approved_by="analyst1")

        task = asyncio.create_task(set_approval())
        approved, approved_by = await loop._wait_for_approval(session_id, state)
        await task

        assert approved is True
        assert approved_by == "analyst1"

    @pytest.mark.asyncio
    async def test_wait_for_approval_returns_tuple_on_rejection(self, active_session):
        """_wait_for_approval should return (False, 'analyst2') when rejected."""
        session_id, state, loop = active_session

        # Set up rejection in background
        async def set_rejection():
            await asyncio.sleep(0.1)
            await loop.reject_action(session_id, approved_by="analyst2")

        task = asyncio.create_task(set_rejection())
        approved, approved_by = await loop._wait_for_approval(session_id, state)
        await task

        assert approved is False
        assert approved_by == "analyst2"

    @pytest.mark.asyncio
    async def test_wait_for_approval_default_unknown_when_not_set(self, active_session):
        """_wait_for_approval should default to 'unknown' if approval dict has no approved_by."""
        session_id, state, loop = active_session

        # Approve without setting approved_by (simulate old code path)
        async def set_approval_no_field():
            await asyncio.sleep(0.1)
            evt = loop._approval_events.get(session_id)
            if evt:
                state.pending_approval["approved"] = True
                # Intentionally don't set approved_by
                evt.set()

        task = asyncio.create_task(set_approval_no_field())
        approved, approved_by = await loop._wait_for_approval(session_id, state)
        await task

        assert approved is True
        assert approved_by == "unknown"

    @pytest.mark.asyncio
    async def test_wait_for_approval_no_event_returns_false_unknown(self, mock_agent_loop):
        """_wait_for_approval should return (False, 'unknown') if no event exists."""
        session_id = "nonexistent-session"
        state = AgentState(session_id=session_id, goal="Test", max_steps=50)

        approved, approved_by = await mock_agent_loop._wait_for_approval(session_id, state)

        assert approved is False
        assert approved_by == "unknown"


class TestAuditEntryIntegration:
    """Test add_audit_entry receives approved_by from approval workflow."""

    @pytest.mark.asyncio
    async def test_audit_entry_receives_approved_by_on_approval(self, active_session):
        """add_audit_entry should be called with approved_by when tool is approved."""
        session_id, state, loop = active_session

        # Mock the store's add_audit_entry
        loop.store.add_audit_entry = MagicMock()

        # Simulate approval flow (mimicking _run_loop approval section)
        async def set_approval():
            await asyncio.sleep(0.1)
            await loop.approve_action(session_id, approved_by="security_analyst")

        task = asyncio.create_task(set_approval())
        approved, approved_by = await loop._wait_for_approval(session_id, state)
        await task

        # Record audit entry as _run_loop would
        loop.store.add_audit_entry(
            session_id=session_id,
            action="dangerous_tool",
            action_type='approval_granted' if approved else 'approval_rejected',
            actor='human',
            requires_approval=True,
            before_state={"key": "value"},
            approved_by=approved_by,
            status='approved' if approved else 'rejected',
        )

        loop.store.add_audit_entry.assert_called_once()
        call_kwargs = loop.store.add_audit_entry.call_args[1]
        assert call_kwargs['approved_by'] == "security_analyst"
        assert call_kwargs['action_type'] == 'approval_granted'

    @pytest.mark.asyncio
    async def test_audit_entry_receives_approved_by_on_rejection(self, active_session):
        """add_audit_entry should be called with approved_by when tool is rejected."""
        session_id, state, loop = active_session

        # Mock the store's add_audit_entry
        loop.store.add_audit_entry = MagicMock()

        # Simulate rejection flow
        async def set_rejection():
            await asyncio.sleep(0.1)
            await loop.reject_action(session_id, approved_by="manager")

        task = asyncio.create_task(set_rejection())
        approved, approved_by = await loop._wait_for_approval(session_id, state)
        await task

        # Record audit entry as _run_loop would
        loop.store.add_audit_entry(
            session_id=session_id,
            action="dangerous_tool",
            action_type='approval_granted' if approved else 'approval_rejected',
            actor='human',
            requires_approval=True,
            before_state={"key": "value"},
            approved_by=approved_by,
            status='approved' if approved else 'rejected',
        )

        loop.store.add_audit_entry.assert_called_once()
        call_kwargs = loop.store.add_audit_entry.call_args[1]
        assert call_kwargs['approved_by'] == "manager"
        assert call_kwargs['action_type'] == 'approval_rejected'
