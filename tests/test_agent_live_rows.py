"""Template contract checks for the Agent Chat live tool rows."""

from pathlib import Path


TEMPLATE = Path("templates/agent_chat.html").read_text(encoding="utf-8")


def _function_source(name: str) -> str:
    marker = f"function {name}("
    start = TEMPLATE.index(marker)
    end = TEMPLATE.find("\n    function ", start + len(marker))
    return TEMPLATE[start:] if end < 0 else TEMPLATE[start:end]


def test_agent_live_path_has_one_card_and_never_adds_legacy_tool_cards():
    ensure = _function_source("ensureLiveInvestigationCard")
    handler = _function_source("handleWSMessage")
    assert "liveCardElement = document.createElement('section')" in ensure
    assert "Checking " in ensure
    assert "liveCardTargetChosen" in ensure
    assert "upsertLiveToolRow(msg, 'phase')" in handler
    assert "upsertLiveToolRow(msg, 'result')" in handler
    assert "if (!playbookSessionMode)" in handler
    agent_phase_path = handler.split("if (!playbookSessionMode) {", 1)[1].split("}\n                if (phase ===", 1)[0]
    assert "addPhaseIndicator" not in agent_phase_path
    assert "addToolCall" not in agent_phase_path
    assert "addToolResult" not in agent_phase_path
    assert "showLiveToolIndicator" not in agent_phase_path


def test_rows_upsert_by_session_step_tool_and_allow_step_zero():
    identity = _function_source("liveRowIdentityKey")
    upsert = _function_source("upsertLiveToolRow")
    assert "Number.isInteger(step) && step >= 0" in identity
    assert "JSON.stringify([sid, step, tool])" in identity
    assert "var row = liveToolRows[key]" in upsert
    assert "if (!row)" in upsert
    assert "liveToolRows[key] = row" in upsert


def test_orphan_and_duplicate_result_events_reuse_rows_when_key_is_available():
    identity = _function_source("liveRowIdentityKey")
    upsert = _function_source("upsertLiveToolRow")
    assert "'orphan'" in identity
    assert "liveToolRowCounter++" in identity
    assert "var row = liveToolRows[key]" in upsert
    assert "row.resultSeen = true" in _function_source("updateLiveToolRow")


def test_live_rows_render_all_projected_statuses_without_raw_result_fields():
    update = _function_source("updateLiveToolRow")
    assert "['ok', 'hit', 'error', 'unknown']" in update
    assert "is-ok" in update and "is-hit" in update
    assert "is-error" in update and "is-unknown" in update
    assert "event.summary" in update
    assert "event.duration_ms" in update
    assert "event.result" not in update
    assert "result_preview" not in update
    assert "Show raw output" not in update
    assert "Visible output" not in update


def test_live_row_dom_uses_text_nodes_and_never_inserts_event_data_as_html():
    live_functions = "\n".join(
        _function_source(name)
        for name in (
            "ensureLiveInvestigationCard",
            "liveToolPresentation",
            "createLiveRowField",
            "createLiveToolRow",
            "updateLiveToolRow",
            "upsertLiveToolRow",
            "refreshLiveRowPresentations",
        )
    )
    assert "innerHTML" not in live_functions
    assert "insertAdjacentHTML" not in live_functions
    assert "textContent" in live_functions
    for unsafe in ("event.tool", "toolName", "msg.tool"):
        assert f"setAttribute('title', {unsafe}" not in live_functions
        assert f"setAttribute('aria-label', {unsafe}" not in live_functions
        assert f"setAttribute('data-tool', {unsafe}" not in live_functions
    assert "textContent = presentation.displayName" in _function_source("createLiveToolRow")


def test_live_row_labels_are_localized_and_expansion_is_keyboard_native():
    ensure = _function_source("ensureLiveInvestigationCard")
    create = _function_source("createLiveToolRow")
    assert "evidenceLanguage(null, currentGoal)" in _function_source("liveRowLanguage")
    assert "against threat intel sources" in ensure
    assert r"\u0e01\u0e31\u0e1a\u0e41\u0e2b\u0e25\u0e48\u0e07\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e20\u0e31\u0e22\u0e04\u0e38\u0e01\u0e04\u0e32\u0e21" in ensure
    assert "document.createElement('details')" in create
    assert "document.createElement('summary')" in create
    assert "setAttribute('aria-label'" in create
    assert "What it does" in create and r"\u0e01\u0e32\u0e23\u0e17\u0e33\u0e07\u0e32\u0e19" in create
    assert "No validated input is available." in create
    assert r"\u0e44\u0e21\u0e48\u0e21\u0e35\u0e02\u0e49\u0e2d\u0e21\u0e39\u0e25\u0e17\u0e35\u0e48\u0e1c\u0e48\u0e32\u0e19\u0e01\u0e32\u0e23\u0e15\u0e23\u0e27\u0e08\u0e23\u0e39\u0e1b\u0e41\u0e1a\u0e1a" in create
    assert "liveRowResultFallback('unknown')" in create
    fallback = _function_source("liveRowResultFallback")
    assert "Details not available" in fallback
    assert r"\u0e44\u0e21\u0e48\u0e21\u0e35\u0e23\u0e32\u0e22\u0e25\u0e30\u0e40\u0e2d\u0e35\u0e22\u0e14" in fallback


def test_session_change_resets_only_live_rows_and_preserves_playbook_and_approval_paths():
    switch = _function_source("switchSession")
    handler = _function_source("handleWSMessage")
    approval = _function_source("showApproval")
    respond = _function_source("respondApproval")
    assert "clearLiveToolRows(true)" in switch
    assert "if (playbookSessionMode)" in switch
    assert "renderPlaybookSession(id)" not in switch
    assert "showApproval(msg)" in handler
    assert "'/approve'" in respond
    assert "function showApproval(msg)" in approval
    assert "function respondApproval(approved)" in respond


def test_existing_playbook_rendering_and_approval_modal_remain_separate():
    playbook = _function_source("renderPlaybookSession")
    approval = _function_source("showApproval")
    assert "addToolCall(step.tool_name, null)" in playbook
    assert "approvalOverlay" in approval
    assert "approvalDetail" in approval
    assert "if (playbookSessionMode && msg.params !== undefined)" in approval
