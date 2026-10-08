"""Regression checks for scrolling and collapse behavior of live tool rows."""

from pathlib import Path
import re


TEMPLATE = Path("templates/agent_chat.html").read_text(encoding="utf-8")


def _function_source(name: str) -> str:
    marker = f"function {name}("
    start = TEMPLATE.index(marker)
    end = TEMPLATE.find("\n    function ", start + len(marker))
    return TEMPLATE[start:] if end < 0 else TEMPLATE[start:end]


def test_live_tool_details_start_collapsed_and_are_never_opened_by_code():
    create = _function_source("createLiveToolRow")
    assert "document.createElement('details')" in create
    assert ".open = true" not in create
    assert "setAttribute('open'" not in create
    assert "details.open" in create  # read-only check in the toggle listener
    assert ".agent-live-row:not([open]) > .agent-live-row-body { display: none; }" in TEMPLATE


def test_chat_messages_scroll_and_live_card_does_not_clip_or_lock_height():
    chat_messages = TEMPLATE.split(".chat-messages {", 1)[1].split("}", 1)[0]
    live_card = TEMPLATE.split(".agent-live-card {", 1)[1].split("}", 1)[0]
    assert "overflow-y: auto" in chat_messages
    assert "min-height: 0" in chat_messages
    assert "overflow: hidden" not in live_card
    assert re.search(r"(?<!min-)height\s*:", live_card) is None
    assert "max-height" not in live_card
    assert "flex: 0 0 auto" in live_card
    assert ".agent-live-row:not([open]) > .agent-live-row-body { display: none; }" in TEMPLATE
    assert ".agent-live-row[open] > .agent-live-row-body { display: grid; }" in TEMPLATE


def test_live_row_updates_stick_to_bottom_only_when_reader_was_already_there():
    handler = _function_source("handleWSMessage")
    at_bottom = _function_source("chatIsAtBottom")
    scroll_if_pinned = _function_source("scrollToBottomIfPinned")
    assert "var wasAtBottom = chatIsAtBottom()" in handler
    assert "if (liveRowUpdate) scrollToBottomIfPinned(wasAtBottom)" in handler
    assert "scrollHeight - msgs.clientHeight - msgs.scrollTop <= 32" in at_bottom
    assert "if (!wasPinned) return" in scroll_if_pinned
    assert "msgs.scrollTop = msgs.scrollHeight" in scroll_if_pinned


def test_expanding_a_row_scrolls_nearest_and_preserves_stick_to_bottom():
    create = _function_source("createLiveToolRow")
    assert "summary.addEventListener('click'" in create
    assert "details.addEventListener('toggle'" in create
    assert "details.scrollIntoView({ block: 'nearest', inline: 'nearest' })" in create
    assert "scrollToBottomIfPinned(detailsWasAtBottom)" in create


def test_expanded_description_is_hidden_when_it_repeats_the_header_summary():
    create = _function_source("createLiveToolRow")
    update = _function_source("updateLiveToolRow")
    refresh = _function_source("refreshLiveRowPresentations")
    assert "presentation.description === description.textContent" in create
    assert "presentation.description === row.description.textContent" in update
    assert "presentation.description === row.description.textContent" in refresh


def test_live_card_layout_code_never_inserts_event_values_as_html():
    live_functions = "\n".join(
        _function_source(name)
        for name in (
            "ensureLiveInvestigationCard",
            "createLiveToolRow",
            "updateLiveToolRow",
            "upsertLiveToolRow",
            "chatIsAtBottom",
            "scrollToBottomIfPinned",
        )
    )
    assert "innerHTML" not in live_functions
    assert "insertAdjacentHTML" not in live_functions
    assert "textContent" in live_functions
