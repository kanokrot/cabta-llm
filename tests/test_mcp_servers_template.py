"""Markup contracts used by the MCP servers page JavaScript."""

import re
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.app import _register_page_routes
from src.web.auth import get_current_user


def _admin_user():
    return {
        "id": 1,
        "email": "admin@example.test",
        "username": "admin",
        "role": "admin",
        "is_active": 1,
    }


def test_mcp_template_keeps_javascript_dom_contracts():
    from pathlib import Path

    template = Path("templates/mcp_servers.html").read_text(encoding="utf-8")
    required_ids = (
        "categoryFilters", "serversList", "connectedCount", "toolsAvailableCount",
        "needAttentionCount", "checkAllBtn", "addServerModal", "serverName",
        "serverDescription", "serverCommand", "serverArgs", "serverUrl",
        "serverToken", "serverEnv", "addServerBtn", "toolsModal", "toolsModalBody",
        "toolDetailsModal", "toolDetailsModalBody", "installInfoModal", "installInfoBody",
    )
    for element_id in required_ids:
        assert f'id="{element_id}"' in template

    for css_class in (
        "category-pill", "server-row", "server-connect-btn", "server-disconnect-btn",
        "server-check-btn", "server-tools-btn", "server-delete-btn",
        "server-install-info-btn", "server-row-header", "server-expanded-tools",
        "server-expand-icon", "server-action", "tools-grid", "toggleInlineTools",
    ):
        assert css_class in template

    assert 'data-category="{{ cat.key | e }}"' in template
    assert 'data-server-row="true"' in template
    assert 'data-server-name="{{ srv.name | e }}"' in template
    assert 'id="status-{{ srv.name | e }}"' in template
    assert 'id="spinner-{{ srv.name | e }}"' in template
    assert "function toolIdentity(t)" in template
    assert "function toolIconSvg(iconKey)" in template
    assert "function shortSummary(summary)" in template
    assert "function createToolChip(t, serverName)" in template
    assert "function showToolDetails(t, serverName)" in template
    assert 'fetch(\'/api/mcp/servers/\' + encodeURIComponent(serverName) + \'/tools\')' in template

    stats_and_filters = template.split('<div class="summary-cards"', 1)[1].split(
        '<div class="server-list"', 1
    )[0]
    assert "Installable" not in stats_and_filters
    assert "Planned" not in stats_and_filters
    assert "status-filter-btn" not in template
    assert not re.search(r"querySelectorAll\(['\"]td['\"]\)\s*\[\s*[0-9]+\s*\]", template)


def test_mcp_servers_page_renders_nine_rows_and_category_counts():
    server_categories = {
        "osint_tools": "recon",
        "free_osint_tools": "recon",
        "network_tools": "recon",
        "remote_tools": "recon",
        "malwoverview_tools": "malware",
        "remnux_tools": "malware",
        "forensics_tools": "forensics",
        "threat_intel_tools": "intel",
        "vulnerability-tools": "vuln",
    }
    app = FastAPI()
    app.state.agent_store = SimpleNamespace(list_mcp_connections=lambda: [])
    app.state.config = {
        "mcp_servers": [
            {"name": name, "category": category, "status": "connected"}
            for name, category in server_categories.items()
        ]
    }
    app.state.mcp_client = SimpleNamespace(
        get_connection_status=lambda: {
            name: {"connected": True, "tool_count": 2}
            for name in server_categories
        }
    )
    app.dependency_overrides[get_current_user] = _admin_user
    _register_page_routes(app)

    with TestClient(app) as client:
        response = client.get("/mcp/servers")

    assert response.status_code == 200
    assert response.text.count('<article class="server-row" data-server-row="true"') == 9
    filter_markup = response.text.split('id="categoryFilters"', 1)[1].split("</div>", 1)[0]
    counts = {
        category: int(count)
        for category, count in re.findall(
            r'data-category="(recon|malware|forensics|intel|vuln)"[^>]*>[\s\S]*?'
            r'<span class="pill-count">(\d+)</span>',
            filter_markup,
        )
    }
    assert counts == {"recon": 4, "malware": 2, "forensics": 1, "intel": 1, "vuln": 1}
