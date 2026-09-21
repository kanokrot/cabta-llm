"""
Author: Ugur Ates
MCP Server management routes.
"""

import asyncio
import importlib.util
import logging
import os
import re
import sqlite3
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ...agent.mcp_tool_classification import (
    SERVER_CATEGORIES,
    decorate_mcp_tool,
)
from ..auth import get_current_user, require_role
from ..visibility import is_tool_allowed, serialize_tool_definition

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Category metadata ──────────────────────────────────────────────────────
CATEGORY_META: Dict[str, Dict[str, str]] = {
    'analysis': {
        'label': 'Analysis',
        'icon': 'bi-search',
        'description': 'Malware and file analysis tools',
    },
    'reverse_engineering': {
        'label': 'Reverse Engineering',
        'icon': 'bi-cpu',
        'description': 'Binary file analysis and reverse engineering',
    },
    'sandbox': {
        'label': 'Sandbox',
        'icon': 'bi-box-seam',
        'description': 'Running malware in an isolated environment',
    },
    'threat_intel': {
        'label': 'Threat Intelligence',
        'icon': 'bi-globe2',
        'description': 'IOC querying and threat intelligence resources',
    },
    'detection': {
        'label': 'Detection Engineering',
        'icon': 'bi-shield-exclamation',
        'description': 'Detection rule creation and management',
    },
    'siem': {
        'label': 'SIEM',
        'icon': 'bi-bar-chart-line',
        'description': 'Security information and event management',
    },
    'edr': {
        'label': 'EDR / XDR',
        'icon': 'bi-pc-display',
        'description': 'Endpoint detection and response',
    },
    'forensics': {
        'label': 'Forensics',
        'icon': 'bi-fingerprint',
        'description': 'Digital forensics and incident response',
    },
    'network': {
        'label': 'Network Security',
        'icon': 'bi-diagram-3',
        'description': 'Network traffic analysis and IDS/IPS',
    },
    'vulnerability': {
        'label': 'Vulnerability',
        'icon': 'bi-bug',
        'description': 'Vulnerability scanning and assessment',
    },
    'osint': {
        'label': 'OSINT',
        'icon': 'bi-binoculars',
        'description': 'Open-source intelligence gathering',
    },
    'cloud': {
        'label': 'Cloud Security',
        'icon': 'bi-cloud-check',
        'description': 'Cloud environment security auditing',
    },
    'utility': {
        'label': 'Utility',
        'icon': 'bi-wrench-adjustable',
        'description': 'General-purpose MCP utility servers',
    },
}


class MCPServerAdd(BaseModel):
    name: str
    transport: str  # stdio, sse, http
    command: Optional[str] = None
    args: Optional[List[str]] = None
    url: Optional[str] = None
    env: Optional[Dict[str, str]] = None
    token: Optional[str] = None
    description: str = ""


def _get_category_meta() -> Dict[str, Dict[str, str]]:
    """Return category metadata dict."""
    return CATEGORY_META


def _is_sensitive_key(key: Any) -> bool:
    value = str(key).casefold()
    return any(marker in value for marker in (
        "token", "secret", "password", "credential", "private_key", "private-key",
        "api_key", "api-key", "access_key", "access-key", "bearer", "auth",
    ))


def _redact_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    return re.sub(
        r"(?i)(token|secret|password|api[_-]?key|access[_-]?key|bearer)(\s*[=:]\s*|\s+)[^\s,;]+",
        r"\1\2[REDACTED]",
        text,
    )


def _safe_env(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key): str(item)
        for key, item in value.items()
        if not _is_sensitive_key(key)
    }


def _safe_args(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    result = []
    redact_next = False
    for item in value:
        text = str(item)
        if "=" in text and _is_sensitive_key(text.split("=", 1)[0].lstrip("-")):
            result.append(text.split("=", 1)[0] + "=[REDACTED]")
            continue
        if redact_next:
            result.append("[REDACTED]")
            redact_next = False
            continue
        if _is_sensitive_key(text.lstrip("-")):
            result.append(text)
            redact_next = True
            continue
        result.append(text)
    return result


def _safe_url(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value:
        return None
    parsed = urlsplit(value)
    # Drop query/fragment credentials and userinfo while preserving the
    # endpoint an administrator needs to identify.
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def _safe_live_status(value: Any) -> dict:
    if not isinstance(value, dict):
        return {}
    result = {
        key: value[key]
        for key in ("connected", "transport", "tool_count", "tools")
        if key in value
    }
    if "description" in value:
        result["description"] = _redact_text(value["description"])
    return result


def _decode_config(entry: dict) -> dict:
    config = entry.get("config_json", entry)
    if isinstance(config, str):
        try:
            config = __import__("json").loads(config)
        except (TypeError, ValueError):
            config = {}
    return config if isinstance(config, dict) else {}


def _server_category(entry: dict) -> str:
    return str(entry.get("category") or SERVER_CATEGORIES.get(entry.get("name", ""), "utility"))


def _sanitize_server(entry: dict, role: str) -> dict:
    name = str(entry.get("name", ""))
    status = entry.get("status") or "planned"
    if role != "admin":
        live_status = entry.get("live_status")
        if not isinstance(live_status, dict):
            live_status = {}
        live_tools = live_status.get("tools", [])
        tool_count = len(live_tools) if isinstance(live_tools, (list, tuple)) else 0
        if not tool_count:
            tool_count = live_status.get("tool_count", 0)
        if not isinstance(tool_count, int) or isinstance(tool_count, bool) or tool_count < 0:
            tool_count = 0
        return {
            "name": name,
            "category": _server_category(entry),
            "status": str(status),
            "tool_count": tool_count,
        }

    config = _decode_config(entry)
    output = {
        "name": name,
        "category": _server_category({**config, **entry}),
        "transport": entry.get("transport") or config.get("transport", "stdio"),
        "command": _redact_text(entry.get("command") or config.get("command")),
        "args": _safe_args(entry.get("args") if entry.get("args") is not None else config.get("args")),
        "url": _safe_url(entry.get("url") or config.get("url")),
        "env": _safe_env(entry.get("env") if entry.get("env") is not None else config.get("env")),
        "description": _redact_text(entry.get("description") or config.get("description", "")),
        "source": entry.get("source", "config"),
        "status": str(status),
    }
    if entry.get("last_connected") is not None:
        output["last_connected"] = entry["last_connected"]
    if entry.get("live_status") is not None:
        output["live_status"] = _safe_live_status(entry["live_status"])
    return {key: value for key, value in output.items() if value is not None}


def _record_mcp_audit(user: dict, action: str, server_name: str, status: str) -> None:
    """Write only the fixed audit fields; never serialize request/config data."""
    try:
        db_path = Path(os.getenv("AUTH_DB_PATH", "src/db/auth.db"))
        migration_path = Path(__file__).resolve().parents[2] / "db" / "migrations" / "009_add_mcp_audit.py"
        spec = importlib.util.spec_from_file_location("mcp_audit_migration", migration_path)
        migration = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(migration)
        migration.migrate(str(db_path))
        with sqlite3.connect(str(db_path)) as connection:
            connection.execute(
                "INSERT INTO mcp_management_audit "
                "(actor_user_id, actor_role, action, server_name, status) "
                "VALUES (?, ?, ?, ?, ?)",
                (int(user["id"]), str(user["role"]), action, server_name, str(status)),
            )
            connection.commit()
    except Exception as exc:
        # A failed audit write must be visible to operators but must not turn a
        # completed MCP operation into a misleading API failure.
        logger.error("[MCP] Failed to write management audit for %s: %s", action, exc)


@router.get('/categories')
async def list_categories(current_user: dict = Depends(get_current_user)):
    """Return all MCP server category metadata."""
    del current_user
    return {"categories": CATEGORY_META}


@router.get('/servers')
async def list_servers(
    request: Request,
    current_user: dict = Depends(require_role(["Incident Responder", "Threat Hunter", "admin"])),
):
    """List all configured MCP servers.

    Merges pre-configured servers from config.yaml with any servers
    stored in the database, so users see all available servers and
    their connection status.
    """
    store = request.app.state.agent_store
    db_servers = store.list_mcp_connections() if store else []

    # Build a lookup of DB servers by name for quick merging
    db_lookup = {s['name']: s for s in db_servers}

    # Load pre-configured servers from config.yaml
    config = getattr(request.app.state, 'config', None) or {}
    config_servers = config.get('mcp_servers', []) if isinstance(config, dict) else []

    merged: List[dict] = []
    seen_names: set = set()

    # Pre-configured servers first (canonical order)
    for cfg in config_servers:
        name = cfg.get('name', '')
        if not name:
            continue
        entry = dict(cfg)
        # Overlay any DB-side data (e.g. user-modified fields)
        if name in db_lookup:
            db_entry = db_lookup[name]
            entry.update({k: v for k, v in db_entry.items() if v is not None})
        entry.setdefault('source', 'config')
        entry.setdefault('status', 'planned')
        merged.append(entry)
        seen_names.add(name)

    # Append any DB-only servers not in the config
    for s in db_servers:
        if s['name'] not in seen_names:
            s.setdefault('source', 'user')
            s.setdefault('status', 'requires_install')
            merged.append(s)

    # Add live status if MCP client is available
    if hasattr(request.app.state, 'mcp_client') and request.app.state.mcp_client:
        live_status = request.app.state.mcp_client.get_connection_status()
        for s in merged:
            s['live_status'] = live_status.get(s['name'], {})

    return {"servers": [_sanitize_server(entry, current_user["role"]) for entry in merged]}


@router.post('/servers')
async def add_server(
    request: Request,
    body: MCPServerAdd,
    current_user: dict = Depends(require_role("admin")),
):
    """Add a new MCP server configuration."""
    store = request.app.state.agent_store
    if store is None:
        raise HTTPException(503, "Agent store not initialized")
    server_id = store.save_mcp_connection(body.name, body.transport, body.model_dump())
    _record_mcp_audit(current_user, "add_server", body.name, "success")
    return {"id": server_id, "name": body.name}


@router.delete('/servers/{server_name}')
async def remove_server(
    request: Request,
    server_name: str,
    current_user: dict = Depends(require_role("admin")),
):
    """Remove an MCP server configuration."""
    store = request.app.state.agent_store
    if store is None:
        raise HTTPException(503, "Agent store not initialized")
    store.delete_mcp_connection(server_name)
    _record_mcp_audit(current_user, "delete_server", server_name, "success")
    return {"status": "deleted"}


@router.post('/servers/{server_name}/connect')
async def connect_server(
    request: Request,
    server_name: str,
    current_user: dict = Depends(require_role("admin")),
):
    """Connect to an MCP server."""
    if not hasattr(request.app.state, 'mcp_client') or not request.app.state.mcp_client:
        _record_mcp_audit(current_user, "connect", server_name, "failed")
        raise HTTPException(503, "MCP client not available")
    mcp_client = request.app.state.mcp_client
    store = request.app.state.agent_store

    # Look up server config from BOTH config.yaml and DB
    config = None

    # 1) Check config.yaml first (pre-configured servers)
    app_config = getattr(request.app.state, 'config', None) or {}
    config_servers = app_config.get('mcp_servers', []) if isinstance(app_config, dict) else []
    for s in config_servers:
        if s.get('name') == server_name:
            config = dict(s)
            break

    # 2) Fall back to DB
    if not config and store:
        for s in store.list_mcp_connections():
            if s['name'] == server_name:
                config = s
                break

    if not config:
        _record_mcp_audit(current_user, "connect", server_name, "not_found")
        raise HTTPException(404, "Server configuration not found")
    try:
        from src.agent.mcp_client import MCPServerConfig
        import json as _json
        cfg_data = config.get('config_json', config)
        if isinstance(cfg_data, str):
            cfg_data = _json.loads(cfg_data)
        if isinstance(cfg_data, dict):
            cfg_data.setdefault('name', server_name)
            cfg_data.setdefault('transport', config.get('transport', 'stdio'))
        server_cfg = MCPServerConfig.from_dict(cfg_data)
        success = await mcp_client.connect(server_cfg)
        if success:
            # Register MCP tools into the ToolRegistry so the LLM can see them
            tool_registry = getattr(request.app.state, 'tool_registry', None)
            if tool_registry:
                try:
                    tools = await mcp_client.list_tools(server_name)
                    if tools:
                        tool_registry.register_mcp_tools(server_name, tools)
                except Exception:
                    pass  # Non-critical - tools still callable via MCP direct
            _record_mcp_audit(current_user, "connect", server_name, "success")
            return {"status": "connected", "name": server_name}
        else:
            _record_mcp_audit(current_user, "connect", server_name, "failed")
            raise HTTPException(500, "Connection failed - check server logs")
    except HTTPException:
        raise
    except Exception as e:
        _record_mcp_audit(current_user, "connect", server_name, "failed")
        raise HTTPException(500, "Connection failed - check server logs")


@router.post('/servers/{server_name}/disconnect')
async def disconnect_server(
    request: Request,
    server_name: str,
    current_user: dict = Depends(require_role("admin")),
):
    """Disconnect from an MCP server."""
    if not hasattr(request.app.state, 'mcp_client') or not request.app.state.mcp_client:
        _record_mcp_audit(current_user, "disconnect", server_name, "failed")
        raise HTTPException(503, "MCP client not available")
    mcp_client = request.app.state.mcp_client
    try:
        await mcp_client.disconnect(server_name)
        # Remove MCP tools from ToolRegistry
        tool_registry = getattr(request.app.state, 'tool_registry', None)
        if tool_registry:
            tool_registry.unregister_server(server_name)
        _record_mcp_audit(current_user, "disconnect", server_name, "success")
        return {"status": "disconnected", "name": server_name}
    except Exception as e:
        _record_mcp_audit(current_user, "disconnect", server_name, "failed")
        raise HTTPException(500, "Disconnect failed - check server logs")


@router.get('/servers/{server_name}/tools')
async def list_server_tools(
    request: Request,
    server_name: str,
    current_user: dict = Depends(require_role(["Threat Hunter", "admin"])),
):
    """List tools available from an MCP server."""
    if not hasattr(request.app.state, 'mcp_client') or not request.app.state.mcp_client:
        raise HTTPException(503, "MCP client not available")
    mcp_client = request.app.state.mcp_client
    tools = await mcp_client.list_tools(server_name)
    visible = []
    for raw_tool in tools:
        decorated = decorate_mcp_tool(server_name, raw_tool)
        decorated["name"] = f"{server_name}.{decorated['name']}"
        decorated["source"] = server_name
        if not is_tool_allowed(current_user["role"], decorated):
            continue
        serialized = serialize_tool_definition(decorated, current_user["role"])
        if serialized is not None:
            visible.append(serialized)
    return {"tools": visible}


@router.post('/servers/{server_name}/check')
async def check_server_availability(
    request: Request,
    server_name: str,
    current_user: dict = Depends(require_role("admin")),
):
    """Check if an MCP server's command exists on PATH (stdio)
    or if its URL is reachable (http/sse).

    Returns a JSON object with:
      - available (bool)
      - message (str) - human-readable status
      - detail (str) - technical detail
    """
    # Find server config
    app_config = getattr(request.app.state, 'config', None) or {}
    config_servers = app_config.get('mcp_servers', []) if isinstance(app_config, dict) else []
    server_cfg = None

    for s in config_servers:
        if s.get('name') == server_name:
            server_cfg = s
            break

    # Also check DB
    if not server_cfg:
        store = request.app.state.agent_store
        if store:
            for s in store.list_mcp_connections():
                if s['name'] == server_name:
                    server_cfg = s
                    break

    if not server_cfg:
        _record_mcp_audit(current_user, "check", server_name, "not_found")
        raise HTTPException(404, f"Server '{server_name}' not found")

    effective_cfg = {**_decode_config(server_cfg), **server_cfg}
    transport = (effective_cfg.get('transport') or 'stdio').lower()

    try:
        result = (
            await _check_stdio_server(effective_cfg)
            if transport == 'stdio'
            else await _check_http_server(effective_cfg)
        )
        _record_mcp_audit(
            current_user, "check", server_name,
            "available" if result.get("available") else "unavailable",
        )
        return result
    except Exception:
        _record_mcp_audit(current_user, "check", server_name, "failed")
        raise


async def _check_stdio_server(cfg: dict) -> dict:
    """Check if a stdio server's command binary exists on PATH."""
    command = cfg.get('command', '')
    if not command:
        return {
            "available": False,
            "message": "No command defined",
            "detail": "stdio server has no 'command' field",
        }

    # For npx/uvx commands, check the launcher itself
    base_cmd = command.split()[0] if ' ' in command else command
    found_path = shutil.which(base_cmd)

    if found_path:
        return {
            "available": True,
            "message": f"Command found: {base_cmd}",
            "detail": f"Resolved to: {found_path}",
        }
    else:
        install_cmd = _redact_text(cfg.get('install_command', '')) or ''
        install_hint = f" -- Install: {install_cmd}" if install_cmd else ""
        return {
            "available": False,
            "message": f"Command not found: {base_cmd}{install_hint}",
            "detail": f"'{base_cmd}' is not on PATH",
        }


async def _check_http_server(cfg: dict) -> dict:
    """Check if an HTTP/SSE server URL is reachable."""
    import urllib.request
    import urllib.error

    url = cfg.get('url', '')
    if not url:
        return {
            "available": False,
            "message": "No URL defined",
            "detail": "http/sse server has no 'url' field",
        }

    parsed_url = urlsplit(str(url))
    safe_url = urlunsplit((parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", ""))

    try:
        loop = asyncio.get_event_loop()

        def _probe():
            req = urllib.request.Request(url, method='HEAD')
            req.add_header('User-Agent', 'BlueTeamAssistant/2.0')
            try:
                resp = urllib.request.urlopen(req, timeout=5)
                return resp.status
            except urllib.error.HTTPError as he:
                # Even a 4xx/5xx means the server is reachable
                return he.code
            except Exception:
                raise

        status_code = await loop.run_in_executor(None, _probe)
        return {
            "available": True,
            "message": f"Server reachable (HTTP {status_code})",
            "detail": f"URL: {safe_url} responded with status {status_code}",
        }
    except Exception as e:
        install_cmd = cfg.get('install_command', '')
        install_hint = f" -- Install: {install_cmd}" if install_cmd else ""
        return {
            "available": False,
            "message": f"Server unreachable{install_hint}",
            "detail": f"URL: {safe_url} -- Error: {type(e).__name__}",
        }
