from pathlib import Path


TEMPLATE = Path("templates/agent_chat.html").read_text(encoding="utf-8")


def _function_source(name: str) -> str:
    marker = f"function {name}("
    start = TEMPLATE.index(marker)
    end = TEMPLATE.find("\n    function ", start + len(marker))
    return TEMPLATE[start:] if end < 0 else TEMPLATE[start:end]


def test_agent_session_state_keeps_goal_context_without_adding_duplicate_bubble():
    handler = _function_source("handleWSMessage")
    session_state = handler.split("case 'session_state':", 1)[1].split("case 'message':", 1)[0]

    assert "if (typeof msg.session.goal === 'string') currentGoal = msg.session.goal" in session_state
    assert "addBubble(msg.session.goal, 'user')" not in session_state


def test_session_state_playbook_branch_still_uses_playbook_renderer():
    handler = _function_source("handleWSMessage")
    session_state = handler.split("case 'session_state':", 1)[1].split("case 'message':", 1)[0]

    assert "if (playbookSessionMode)" in session_state
    assert "renderPlaybookSession(msg.session)" in session_state


def test_load_history_still_renders_user_history_bubbles():
    load_history = _function_source("loadHistory")

    assert "if (m.role === 'user') addBubble(m.content, 'user')" in load_history
