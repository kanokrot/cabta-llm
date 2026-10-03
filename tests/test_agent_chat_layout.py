from __future__ import annotations

import re
from pathlib import Path


def test_agent_chat_layout_preserves_required_hooks_and_adds_redesign() -> None:
    template = (Path(__file__).parents[1] / "templates" / "agent_chat.html").read_text(
        encoding="utf-8"
    )

    preserved_ids = [
        "chatMessages",
        "chatInput",
        "sendBtn",
        "typingIndicator",
        "elapsedTime",
        "connectionStatus",
        "agentStatusServers",
        "agentStatusAgent",
        "agentSidebarTabs",
        "agentTabPlaybooks",
        "agentTabTools",
        "agentPanelPlaybooks",
        "agentPanelTools",
        "playbookCountBadge",
        "toolCountBadge",
        "playbooksList",
        "toolsList",
        "toolSearchInput",
        "toolCategoryFilters",
        "toolTotalSummary",
        "toolCountSummaryBreakdown",
        "toolCountBreakdown",
        "composerPlaybooksButton",
        "composerToolsButton",
        "playbookDetailModal",
        "agentSidebarDrawer",
        "exportDropdownWrap",
        "exportHtmlItem",
        "investigationProgress",
        "liveToolIndicator",
    ]
    for element_id in preserved_ids:
        assert template.count(f'id="{element_id}"') == 1

    assert template.count('id="sessionList"') == 1
    assert template.count('id="agentSessionsSidebar"') == 1
    assert template.count('id="sessionViewAllButton"') == 1
    assert 'class="agent-chat-sidebar offcanvas-lg offcanvas-start"' in template
    assert 'onclick="AgentChat.newSession()"' in template
    assert "-- New Session --" not in template
    assert "sessionSelect" not in template
    assert "substring(0, 35)" not in template
    assert ".sub-header { display: none; }" in template
    assert ".main-content { min-height: 0; }" in template
    assert template.count('id="exportDropdownWrap"') == 1
    assert "document.querySelector('.agent-chat-layout')" in template
    assert "var SESSION_PREVIEW_COUNT = 8;" in template
    assert "var SESSION_FETCH_LIMIT = 50;" in template
    assert "fetch('/api/agent/sessions?limit=' + SESSION_FETCH_LIMIT)" in template
    assert "function renderSessionList()" in template
    assert "View all (" in template
    assert "Show less" in template
    assert "setAttribute('aria-expanded', sessionsExpanded ? 'true' : 'false')" in template
    assert re.search(
        r"\.agent-session-list\s*\{[\s\S]*?min-height:\s*0;[\s\S]*?overflow-y:\s*auto;",
        template,
    )
    assert "s.status === 'completed' ? 'done'" not in template
    assert "var status = s.status === 'active' ? 'running' : (s.status && s.status !== 'completed' ? s.status : '');" in template

    starter_prefixes = [
        "Investigate the IOC: ",
        "Analyze the malware file at: ",
        "Analyze the phishing email at: ",
        "Hunt for threats matching: ",
        "Triage the alert: ",
        "Generate detection rules for: ",
    ]
    for prefix in starter_prefixes:
        assert f"AgentChat.quickAction('{prefix}')" in template

    assert 'id="agentEmptyState"' in template
    assert 'class="agent-starter-grid"' in template
    assert 'class="offcanvas offcanvas-end agent-chat-sidebar-drawer"' in template
    assert re.search(
        r'id="agentSidebarDrawer"[\s\S]*?id="agentSidebarTabs"', template
    )
    assert template.count('id="playbookDetailModal"') == 1
    assert "Use this playbook" in template
    assert "playbook-description" not in template
    assert "substring(0, 100)" not in template
    assert "var defaultIconClass = 'bi-journal-code text-accent';" in template
    assert "var iconClass = pbIcons[pb.id] || defaultIconClass;" in template
    assert "if (!iconClass || iconClass.indexOf('bi-') === -1) iconClass = defaultIconClass;" in template
    assert "icon.className = 'bi ' + iconClass + ' me-2';" in template
    assert '<div class="agent-chat-shell">' in template
    assert '<div class="agent-chat-header">' in template
    assert '<div class="card">\n            <div class="card-header' not in template
    assert "function fitChatHeight()" in template
    assert "window.addEventListener('resize'" in template
    assert "fitChatHeight();" in template
    assert "document.fonts.ready.then(fitChatHeight);" in template
    assert template.count("data.has_report === true") == 2
    assert "data.metadata.ioc_investigation_result" not in template
    hero_css = re.search(r"\.agent-empty-state \{([\s\S]*?)\n    \}", template)
    assert hero_css
    assert "justify-content: flex-start;" in hero_css.group(1)
    assert "margin-block: auto;" in hero_css.group(1)
    assert "justify-content: center;" not in hero_css.group(1)

    card_header_start = template.index('<div class="agent-chat-header">')
    next_block_start = template.index('<div id="investigationProgress"', card_header_start)
    card_header = template[card_header_start:next_block_start]
    assert card_header.count("<div") == card_header.count("</div>")
