"""
Author: Ugur Ates
Configuration and health check endpoints.
"""

import logging
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..auth import require_role
from ..health_probes import get_detailed_health
from ..settings_registry import primary_config_key, registered_config_keys, settings_sources

logger = logging.getLogger(__name__)
router = APIRouter()
_START_TIME = datetime.now(timezone.utc)


def _resolve_config_path() -> Path:
    """Return the configured YAML path, falling back to the project config."""
    project_root = Path(__file__).parent.parent.parent.parent
    return Path(os.environ.get('BTA_CONFIG') or project_root / 'config.yaml')


@router.get('/health')
async def health(
    _admin_user: dict = Depends(require_role("admin")),
):
    """Health check endpoint."""
    return {
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': '2.0.0',
    }


@router.get('/health/detailed')
async def detailed_health(
    request: Request,
    refresh: bool = False,
    _admin_user: dict = Depends(require_role("admin")),
):
    """Return the cached, read-only dependency health report."""
    return await get_detailed_health(request.app, refresh=refresh, started_at=_START_TIME)


@router.get('/info')
async def info(
    _admin_user: dict = Depends(require_role("admin")),
):
    """System information."""
    config_path = _resolve_config_path().resolve()
    from ...utils.config import load_config

    loaded_config = load_config(str(config_path))
    data_dir = loaded_config.get('data_dir')
    if not data_dir:
        data_dir = (loaded_config.get('cache') or {}).get('db_dir')
    if not data_dir:
        db_path = Path(os.getenv('AUTH_DB_PATH', 'src/db/auth.db')).expanduser()
        data_dir = db_path.parent
    data_path = Path(data_dir).expanduser()
    if not data_path.is_absolute():
        data_path = data_path.resolve()
    return {
        'app': 'Blue Team Assistant',
        'version': '2.0.0',
        'python': sys.version,
        'platform': platform.platform(),
        'config_path': str(config_path),
        'data_dir': str(data_path.resolve()),
    }


@router.get('/tools')
async def tool_status(
    _admin_user: dict = Depends(require_role("admin")),
):
    """Check status of external analysis tools."""
    tools = {}

    # Check yara
    try:
        import yara
        tools['yara'] = {'available': True, 'version': yara.YARA_VERSION}
    except ImportError:
        tools['yara'] = {'available': False}

    # Check pefile
    try:
        import pefile
        tools['pefile'] = {'available': True}
    except ImportError:
        tools['pefile'] = {'available': False}

    # Check oletools
    try:
        import oletools
        tools['oletools'] = {'available': True}
    except ImportError:
        tools['oletools'] = {'available': False}

    # Check ssdeep
    try:
        import ssdeep
        tools['ssdeep'] = {'available': True}
    except ImportError:
        tools['ssdeep'] = {'available': False}

    return {'tools': tools}


@router.get('/settings')
async def get_settings(
    request: Request,
    _admin_user: dict = Depends(require_role("admin")),
):
    """Return current application settings."""
    import json

    config_file = _resolve_config_path()

    config = {}
    try:
        import yaml
        if config_file.is_file():
            with open(config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f) or {}
    except ImportError:
        pass
    except Exception:
        pass

    # Mask API keys for security
    safe_config = dict(config)
    if 'api_keys' in safe_config:
        masked = {}
        for k, v in safe_config['api_keys'].items():
            if v and isinstance(v, str) and len(v) > 8:
                masked[k] = v[:4] + '*' * (len(v) - 8) + v[-4:]
            else:
                masked[k] = v
        safe_config['api_keys'] = masked

    return safe_config


@router.get('/settings/sources')
async def get_settings_sources(
    _admin_user: dict = Depends(require_role("admin")),
):
    """Return the registry and masked status for configured intelligence keys."""
    import yaml

    config_file = _resolve_config_path()
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f) or {}
    except FileNotFoundError:
        config = {}
    except Exception:
        config = {}

    api_keys = config.get('api_keys', {}) if isinstance(config, dict) else {}
    if not isinstance(api_keys, dict):
        api_keys = {}

    return {'sources': settings_sources(api_keys)}


@router.post('/settings')
async def save_settings(
    request: Request,
    _admin_user: dict = Depends(require_role("admin")),
):
    """Save application settings to config.yaml."""
    config_file = _resolve_config_path()

    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail='Invalid JSON body') from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail='Settings body must be an object')

    # Load existing config to preserve keys that aren't being updated
    existing = {}
    try:
        import yaml
        if config_file.is_file():
            with open(config_file, 'r', encoding='utf-8') as f:
                existing = yaml.safe_load(f) or {}
    except ImportError:
        return {'error': 'PyYAML not installed'}, 500
    except Exception:
        pass

    # Merge sections
    for key in ('llm', 'agent', 'sandbox', 'mcp_servers'):
        if key in body:
            if not isinstance(body[key], dict):
                raise HTTPException(status_code=400, detail=f'{key} must be an object')
            existing[key] = body[key]

    # Anthropic is an LLM credential stored beside API keys at runtime, but it
    # is not an intelligence-source registry entry.
    anthropic_key = body.get('anthropic_api_key')
    if anthropic_key is not None:
        if not isinstance(anthropic_key, str):
            raise HTTPException(status_code=400, detail='anthropic_api_key must be a string')
        if anthropic_key and '*' not in anthropic_key:
            existing.setdefault('api_keys', {})['anthropic'] = anthropic_key

    if 'analysis' in body:
        analysis = body['analysis']
        if not isinstance(analysis, dict) or any(
            key not in {'enable_llm', 'enable_rag'} or not isinstance(value, bool)
            for key, value in analysis.items()
        ):
            raise HTTPException(status_code=400, detail='analysis accepts only boolean enable_llm and enable_rag')
        existing.setdefault('analysis', {}).update(analysis)

    # Handle API keys - only update keys that are actually provided (not masked)
    if 'api_keys' in body:
        if not isinstance(body['api_keys'], dict):
            raise HTTPException(status_code=400, detail='api_keys must be an object')
        allowed_keys = registered_config_keys()
        unknown = set(body['api_keys']) - allowed_keys
        if unknown:
            raise HTTPException(status_code=400, detail='Unknown API key name')
        if 'api_keys' not in existing:
            existing['api_keys'] = {}
        for k, v in body['api_keys'].items():
            if not isinstance(v, str):
                raise HTTPException(status_code=400, detail='API key values must be strings')
            if v and '*' not in v:
                existing['api_keys'][primary_config_key(k)] = v

    if 'clear_api_keys' in body:
        clear_ids = body['clear_api_keys']
        sources = {entry['id']: entry for entry in settings_sources()}
        if not isinstance(clear_ids, list) or any(
            not isinstance(source_id, str) or source_id not in sources for source_id in clear_ids
        ):
            raise HTTPException(status_code=400, detail='clear_api_keys must contain registered source ids')
        api_keys = existing.setdefault('api_keys', {})
        for source_id in clear_ids:
            for config_key in sources[source_id]['config_keys']:
                api_keys.pop(config_key, None)

    try:
        import yaml
        config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(existing, f, default_flow_style=False, allow_unicode=True)
        logger.info("[CONFIG] Settings saved to %s", config_file)
        return {'status': 'saved', 'message': 'Settings written to config.yaml; restart to apply.'}
    except Exception as exc:
        logger.error("[CONFIG] Failed to save settings: %s", exc)
        return {'error': str(exc)}


@router.get('/ollama-models')
async def list_ollama_models(
    endpoint: str = Query(default='http://localhost:11434'),
    _admin_user: dict = Depends(require_role("admin")),
):
    """Proxy endpoint to list locally available Ollama models.

    Calls Ollama ``/api/tags`` and returns the model list so the frontend
    settings page can offer a dropdown selector without CORS issues.
    """
    base = endpoint.rstrip('/')
    try:
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f'{base}/api/tags') as resp:
                if resp.status != 200:
                    return {'models': [], 'error': f'Ollama returned HTTP {resp.status}'}
                data = await resp.json()
                return {'models': data.get('models', [])}
    except Exception as exc:
        logger.warning("[CONFIG] Failed to list Ollama models at %s: %s", base, exc)
        return {'models': [], 'error': str(exc)}


async def _check_ollama_health(
    endpoint: str = 'http://localhost:11434',
) -> dict:
    """Check if Ollama is running and the configured model is available.

    Returns connectivity status, running model, and available models
    so the frontend can show a clear diagnostic message.
    """
    base = endpoint.rstrip('/')
    result = {
        'ollama_running': False,
        'endpoint': base,
        'configured_model': '',
        'model_available': False,
        'available_models': [],
        'error': None,
    }

    # Read configured model from config
    try:
        import yaml
        config_file = _resolve_config_path()
        if config_file.is_file():
            with open(config_file, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f) or {}
            result['configured_model'] = cfg.get('llm', {}).get('model', 'llama3.2:3b')
        else:
            result['configured_model'] = 'llama3.2'
    except Exception:
        result['configured_model'] = 'llama3.2'

    # Check Ollama connectivity
    try:
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f'{base}/api/tags') as resp:
                if resp.status == 200:
                    result['ollama_running'] = True
                    data = await resp.json()
                    models = data.get('models', [])
                    result['available_models'] = [
                        m.get('name', '') for m in models
                    ]
                    # Check if configured model is available
                    configured = result['configured_model']
                    for m in models:
                        name = m.get('name', '')
                        # Match with or without :tag suffix
                        if name == configured or name.startswith(configured.split(':')[0]):
                            result['model_available'] = True
                            break
                else:
                    result['error'] = f'Ollama returned HTTP {resp.status}'
    except Exception as exc:
        result['error'] = f'Cannot connect to Ollama: {exc}'

    return result


@router.get('/ollama-health')
async def ollama_health(
    endpoint: str = Query(default='http://localhost:11434'),
    _admin_user: dict = Depends(require_role("admin")),
):
    """Check Ollama health using the requested endpoint."""
    return await _check_ollama_health(endpoint)


@router.get('/system-status')
async def system_status(
    _admin_user: dict = Depends(require_role("admin")),
):
    """Aggregate system status for the dashboard health widget."""
    uptime_seconds = (datetime.now(timezone.utc) - _START_TIME).total_seconds()

    tools_resp = await tool_status()
    tools = tools_resp['tools']
    tools_available = sum(1 for t in tools.values() if t.get('available'))

    ollama_resp = await _check_ollama_health()

    return {
        'status': 'healthy',
        'version': '2.0.0',
        'uptime_seconds': uptime_seconds,
        'tools_available': tools_available,
        'tools_total': len(tools),
        'ollama_running': ollama_resp.get('ollama_running', False),
        'ollama_model': ollama_resp.get('configured_model', ''),
    }
