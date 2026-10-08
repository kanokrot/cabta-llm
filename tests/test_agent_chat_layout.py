from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest


def test_agent_chat_inline_script_passes_node_check(tmp_path: Path) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not available in PATH")

    template = (Path(__file__).parents[1] / "templates" / "agent_chat.html").read_text(
        encoding="utf-8"
    )
    scripts = re.findall(r"<script(?:\s[^>]*)?>([\s\S]*?)</script>", template, re.IGNORECASE)
    script = max(scripts, key=len)
    script = re.sub(r"\{\{[\s\S]*?\}\}", "0", script)
    script = re.sub(r"\{%[\s\S]*?%\}", "", script)
    script_path = tmp_path / "agent-chat-inline.js"
    script_path.write_text(script, encoding="utf-8")

    result = subprocess.run(
        [node, "--check", str(script_path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


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
    assert template.count('id="exportDropdownBtn"') == 1
    assert template.count('id="exportHtmlItem"') == 1
    assert template.count('id="exportChatModal"') == 1
    assert 'data-bs-toggle="modal" data-bs-target="#exportChatModal"' in template
    assert "Export chat" in template
    assert "JSON" in template
    assert "HTML report" in template
    assert "PDF" in template
    assert "Coming soon" in template
    assert "Available after an investigation report is generated for this session." in template
    assert "Exports include only what you can see with your role." in template
    assert "Download JSON" in template
    assert "Download HTML report" in template
    assert "summary.textContent = 'Session: '" in template
    assert "exportChatSessionSummary.innerHTML" not in template
    assert "function setExportHtmlAvailability(available)" in template
    assert "function downloadSelectedExport()" in template
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
    assert "var status = s.status === 'active' ? 'running' : (s.status || '');" in template

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
    assert "flex-wrap: wrap;" in template
    assert "border-radius: 999px;" in template
    assert "color-mix(in srgb, var(--color-warning) 14%, var(--bg-secondary))" in template
    assert "agent-status-item:has(.agent-status-warning)" in template
    assert "#exportDropdownBtn" in template
    assert "height: 32px;" in template
    assert "border-style: dashed;" in template
    assert "content: '>';" in template
    assert '<div class="card">\n            <div class="card-header' not in template
    assert "function fitChatHeight()" in template
    assert "window.addEventListener('resize'" in template
    assert "fitChatHeight();" in template
    assert "document.fonts.ready.then(fitChatHeight);" in template
    assert template.count("data.has_report === true") == 2
    assert "data.metadata.ioc_investigation_result" not in template
    assert "function addBubble(text, type, trustedHtml = false, verdictOverride = null, verdictSource = null)" in template
    assert "else addBubble(m.content, 'agent', false, m.verdict, m.verdict_source);" in template
    assert "renderEvidenceCard(m.evidence, m.verdict_source)" in template
    assert "var restoredAgentHistory = (msg.session.history || []).filter" in template
    assert "function normalizeVerdict(value)" in template
    assert r"\b(malicious|zararli|kotu|infected|trojan|ransomware|backdoor)\b" not in template
    assert r"\b(suspicious|supheli|potentially|anomal|risk)\b" not in template
    assert r"\b(clean|temiz|benign|safe|legitimate|harmless)\b" not in template
    assert "detectVerdict(verdict) || 'info'" in template
    assert "if (trustedHtml) div.innerHTML = text || '';" in template
    assert "else div.textContent = text || '';" in template
    hero_css = re.search(r"\.agent-empty-state \{([\s\S]*?)\n    \}", template)
    assert hero_css
    assert "justify-content: flex-start;" in hero_css.group(1)
    assert "margin-block: auto;" in hero_css.group(1)
    assert "justify-content: center;" not in hero_css.group(1)

    card_header_start = template.index('<div class="agent-chat-header">')
    next_block_start = template.index('<div id="investigationProgress"', card_header_start)
    card_header = template[card_header_start:next_block_start]
    assert card_header.count("<div") == card_header.count("</div>")


def test_incident_responder_playbook_mode_is_guarded_and_uses_scoped_endpoints() -> None:
    template = (Path(__file__).parents[1] / "templates" / "agent_chat.html").read_text(
        encoding="utf-8"
    )

    assert "request.state.user.get('role') == 'Incident Responder'" in template
    assert "request.query_params.get('session')" in template
    assert "if (playbookSessionMode) {" in template
    assert "if (playbookSessionMode) return;" in template
    assert "loadPlaybookSession(sessionId);" in template
    assert "fetch('/api/playbooks/sessions/' + encodeURIComponent(id))" in template
    assert "'/api/playbooks/sessions/' : '/api/agent/sessions/'" in template
    assert "JSON.stringify(msg.params, null, 2)" in template
    assert "playbookSessionMode ? null : msg.args" in template
    assert "playbookSessionMode ? '' : (msg.result" in template
    send_start = template.index("function send()")
    send_end = template.index("// ===== Bubble Rendering", send_start)
    send_function = template[send_start:send_end]
    assert "if (playbookSessionMode) return;" in send_function

    init = re.search(r"function init\(\)\s*\{([\s\S]*?)\n    \}", template)
    assert init
    mode_exit = init.group(0).index("if (playbookSessionMode)")
    for generic_loader in ("loadSessions();", "loadTools();", "loadPlaybooks();", "checkOllamaHealth();"):
        assert init.group(0).index(generic_loader) > mode_exit
    assert "playbook-session-mode #agentSessionsSidebar" in template
    assert "playbook-session-mode #agentSidebarDrawer" in template
    assert "disabled aria-label=\"Read-only playbook session\"" in template
    assert "playbookSessionMode ? '/api/playbooks/sessions/'" in template

    guarded_endpoints = {
        "/api/agent/tools": r"function loadTools\(\)\s*\{\s*if \(playbookSessionMode\) return;[\s\S]*?fetch\('/api/agent/tools'\)",
        "/api/agent/sessions?limit=": r"function loadSessions\(\)\s*\{\s*if \(playbookSessionMode\) return;[\s\S]*?fetch\('/api/agent/sessions\?limit=",
        "/api/mcp/servers": r"function refreshMCPStatus\(\)\s*\{\s*if \(playbookSessionMode\) return;[\s\S]*?fetch\('/api/mcp/servers'\)",
        "/api/config/ollama-health": r"function checkOllamaHealth\(\)\s*\{\s*if \(playbookSessionMode\) return;[\s\S]*?fetch\('/api/config/ollama-health'\)",
    }
    for endpoint, pattern in guarded_endpoints.items():
        assert endpoint in template
        assert re.search(pattern, template)
    for endpoint in ("/api/agent/investigate", "/api/chat"):
        assert endpoint in send_function
        assert send_function.index("if (playbookSessionMode) return;") < send_function.index(endpoint)


def test_approval_description_uses_text_content_with_reason_and_generic_fallbacks() -> None:
    template = (Path(__file__).parents[1] / "templates" / "agent_chat.html").read_text(
        encoding="utf-8"
    )
    approval = re.search(r"function showApproval\(msg\)\s*\{([\s\S]*?)\n    \}", template)

    assert approval
    source = approval.group(1)
    assert "typeof msg.description === 'string' && msg.description.trim()" in source
    assert "typeof msg.reason === 'string' && msg.reason.trim() ? msg.reason : 'Approval required'" in source
    assert "toolName.innerHTML = toolIdentityHtml(msg.tool || msg.action || 'Action');" in source
    assert "description.textContent = approvalDescription;" in source
    assert "params.textContent = JSON.stringify(msg.params, null, 2) || '';" in source
    assert source.count("innerHTML") == 1
    assert "msg.content" not in source
    assert "description.innerHTML" not in source
    assert "detail.innerHTML" not in source
