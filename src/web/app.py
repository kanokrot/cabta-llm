"""
Author: Ugur Ates
FastAPI Application Factory - Blue Team Assistant Web Dashboard.

Usage::

    uvicorn src.web.app:create_app --factory --host 0.0.0.0 --port 8080
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from .routes import analysis, dashboard, reports, config_api, cases, tickets
from .routes import agent as agent_routes
from .routes import chat as chat_routes
from .routes import playbooks as playbook_routes
from .routes import mcp_management as mcp_routes
from . import websocket
from .analysis_manager import AnalysisManager
from .case_store import CaseStore
from src.integrations.ticketing import initialize_database as initialize_ticketing_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent.parent
CONFIG_FILE = PROJECT_ROOT / 'config.yaml'


def _load_config() -> dict:
    """Load configuration from config.yaml (or return sensible defaults)."""
    try:
        import yaml
        if CONFIG_FILE.is_file():
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f) or {}
            logger.info("[WEB] Configuration loaded from %s", CONFIG_FILE)
            return cfg
    except ImportError:
        logger.debug("[WEB] PyYAML not installed -- using default config")
    except Exception as exc:
        logger.warning("[WEB] Failed to load config.yaml: %s", exc)

    return {
        'llm': {
            'provider': 'ollama',
            'ollama_endpoint': 'http://localhost:11434',
            'ollama_model': 'llama3.1:8b',
        },
        'agent': {'max_steps': 50},
        'api_keys': {},
    }


TEMPLATES_DIR = PROJECT_ROOT / 'templates'
STATIC_DIR = PROJECT_ROOT / 'static'


class NoCacheStaticMiddleware(BaseHTTPMiddleware):
    """Prevent browser caching of static JS/CSS during development."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        if request.url.path.startswith('/static/'):
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        return response


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Application lifespan: auto-connect MCP servers on startup."""
    await _auto_connect_mcp_servers(app)
    yield
    # Cleanup: disconnect MCP servers on shutdown
    mcp_client = getattr(app.state, 'mcp_client', None)
    if mcp_client:
        try:
            await mcp_client.disconnect_all()
            logger.info("[WEB] Disconnected all MCP servers during shutdown")
        except Exception as exc:
            logger.warning("[WEB] Error disconnecting MCP servers on shutdown: %s", exc)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    app = FastAPI(
        title='Blue Team Assistant',
        description='SOC Analysis Toolkit - Web Dashboard',
        version='2.0.0',
        docs_url='/api/docs',
        redoc_url='/api/redoc',
        lifespan=_lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=['*'],
        allow_credentials=True,
        allow_methods=['*'],
        allow_headers=['*'],
    )

    # Prevent static file caching
    app.add_middleware(NoCacheStaticMiddleware)

    # Static files
    if STATIC_DIR.exists():
        app.mount('/static', StaticFiles(directory=str(STATIC_DIR)), name='static')

    # Shared state
    app.state.analysis_manager = AnalysisManager()
    app.state.case_store = CaseStore()
    app.state.templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    # Agent components (lazy-initialized; set to None so routes can check availability)
    app.state.agent_store = None
    app.state.agent_loop = None
    app.state.mcp_client = None
    app.state.playbook_engine = None
    app.state.tool_registry = None

    # Load configuration
    config = _load_config()
    app.state.config = config

    # Initialize Ticketing Database
    try:
        initialize_ticketing_db()
    except Exception as e:
        logger.critical(f"[WEB] Failed to initialize ticketing database: {e}")

    try:
        from src.agent.agent_store import AgentStore
        app.state.agent_store = AgentStore()
        logger.info("[WEB] AgentStore initialized")
    except Exception as exc:
        logger.warning(f"[WEB] AgentStore not available: {exc}")

    # Tool instances (used by ToolRegistry)
    app.state.ioc_investigator = None
    app.state.malware_analyzer = None
    app.state.email_analyzer = None
    app.state.correlation_engine = None
    app.state.investigation_memory = None
    app.state.sandbox_orchestrator = None

    try:
        from src.agent.tool_registry import ToolRegistry
        app.state.tool_registry = ToolRegistry()

        # Instantiate real tool classes
        ioc_inv = None
        mal_ana = None
        email_ana = None

        try:
            from src.tools.ioc_investigator import IOCInvestigator
            ioc_inv = IOCInvestigator(config)
            app.state.ioc_investigator = ioc_inv
            logger.info("[WEB] IOCInvestigator initialized")
        except Exception as e:
            logger.warning(f"[WEB] IOCInvestigator not available: {e}")

        try:
            from src.tools.malware_analyzer import MalwareAnalyzer
            mal_ana = MalwareAnalyzer(config)
            app.state.malware_analyzer = mal_ana
            logger.info("[WEB] MalwareAnalyzer initialized")
        except Exception as e:
            logger.warning(f"[WEB] MalwareAnalyzer not available: {e}")

        try:
            from src.tools.email_analyzer import EmailAnalyzer
            email_ana = EmailAnalyzer(config)
            app.state.email_analyzer = email_ana
            logger.info("[WEB] EmailAnalyzer initialized")
        except Exception as e:
            logger.warning(f"[WEB] EmailAnalyzer not available: {e}")

        # Wire cross-tool references
        if email_ana and ioc_inv:
            email_ana.ioc_investigator = ioc_inv
        if email_ana and mal_ana:
            email_ana.file_analyzer = mal_ana
        if mal_ana and ioc_inv:
            mal_ana.ioc_investigator = ioc_inv

        # Register all tools (with full instances where available)
        try:
            app.state.tool_registry.register_default_tools(
                config,
                ioc_investigator=ioc_inv,
                malware_analyzer=mal_ana,
                email_analyzer=email_ana,
            )
        except Exception as reg_exc:
            logger.warning(f"[WEB] Default tool registration partial: {reg_exc}")

        logger.info("[WEB] ToolRegistry initialized with %d tools", len(app.state.tool_registry.list_tools()))
    except Exception as exc:
        logger.warning(f"[WEB] ToolRegistry not available: {exc}")

    # Correlation Engine
    try:
        from src.agent.correlation import CorrelationEngine
        app.state.correlation_engine = CorrelationEngine()
        logger.info("[WEB] CorrelationEngine initialized")
    except Exception as exc:
        logger.warning(f"[WEB] CorrelationEngine not available: {exc}")

    # Investigation Memory
    try:
        from src.agent.memory import InvestigationMemory
        app.state.investigation_memory = InvestigationMemory()
        logger.info("[WEB] InvestigationMemory initialized")
    except Exception as exc:
        logger.warning(f"[WEB] InvestigationMemory not available: {exc}")

    # Sandbox Orchestrator
    try:
        from src.agent.sandbox_orchestrator import SandboxOrchestrator
        app.state.sandbox_orchestrator = SandboxOrchestrator(config)
        logger.info("[WEB] SandboxOrchestrator initialized")
    except Exception as exc:
        logger.warning(f"[WEB] SandboxOrchestrator not available: {exc}")

    # MCP Client Manager
    try:
        from src.agent.mcp_client import MCPClientManager
        app.state.mcp_client = MCPClientManager(agent_store=app.state.agent_store)
        logger.info("[WEB] MCPClientManager initialized")
    except Exception as exc:
        logger.warning(f"[WEB] MCPClientManager not available: {exc}")

    # LLM Analyzer
    app.state.llm_analyzer = None
    try:
        from src.integrations.llm_analyzer import LLMAnalyzer
        app.state.llm_analyzer = LLMAnalyzer(config)
        logger.info("[WEB] LLMAnalyzer initialized")
    except Exception as exc:
        logger.warning(f"[WEB] LLMAnalyzer not available: {exc}")

    # Notification Manager
    app.state.notification_manager = None
    try:
        from src.integrations.notifications import NotificationManager
        app.state.notification_manager = NotificationManager(config)
        logger.info("[WEB] NotificationManager initialized")
    except Exception as exc:
        logger.warning(f"[WEB] NotificationManager not available: {exc}")

    # Agent Loop
    try:
        from src.agent.agent_loop import AgentLoop
        app.state.agent_loop = AgentLoop(
            config=config,
            tool_registry=app.state.tool_registry or ToolRegistry(),
            agent_store=app.state.agent_store,
            mcp_client=app.state.mcp_client,
            llm_analyzer=app.state.llm_analyzer,
            notification_manager=app.state.notification_manager,
        )
        logger.info("[WEB] AgentLoop initialized")
    except Exception as exc:
        logger.warning(f"[WEB] AgentLoop not available: {exc}")

    # Playbook Engine
    try:
        from src.agent.playbook_engine import PlaybookEngine
        app.state.playbook_engine = PlaybookEngine(
            agent_loop=app.state.agent_loop,
            agent_store=app.state.agent_store,
            notification_manager=app.state.notification_manager,
        )
        # Wire playbook engine back into agent loop so LLM can trigger playbooks
        if app.state.agent_loop is not None:
            app.state.agent_loop._playbook_engine = app.state.playbook_engine
        logger.info("[WEB] PlaybookEngine initialized")
    except Exception as exc:
        logger.warning(f"[WEB] PlaybookEngine not available: {exc}")

    # Register routers
    app.include_router(dashboard.router, prefix='/api/dashboard', tags=['Dashboard'])
    app.include_router(analysis.router, prefix='/api/analysis', tags=['Analysis'])
    app.include_router(reports.router, prefix='/api/reports', tags=['Reports'])
    app.include_router(config_api.router, prefix='/api/config', tags=['Config'])
    app.include_router(cases.router, prefix='/api/cases', tags=['Cases'])
    app.include_router(agent_routes.router, prefix='/api/agent', tags=['Agent'])
    app.include_router(chat_routes.router, prefix='/api/chat', tags=['Chat'])
    app.include_router(playbook_routes.router, prefix='/api/playbooks', tags=['Playbooks'])
    app.include_router(mcp_routes.router, prefix='/api/mcp', tags=['MCP'])
    app.include_router(tickets.router, prefix='/api', tags=['Tickets'])
    app.include_router(websocket.router)

    # Page routes (HTML templates)
    _register_page_routes(app)

    logger.info("[WEB] Blue Team Assistant Web Dashboard initialized")
    return app


async def _auto_connect_mcp_servers(app: FastAPI) -> None:
    """Connect to MCP servers from config.yaml and AgentStore on startup."""
    mcp_client = getattr(app.state, 'mcp_client', None)
    if not mcp_client:
        return

    tool_registry = getattr(app.state, 'tool_registry', None)
    config = getattr(app.state, 'config', None) or {}
    mcp_servers = config.get('mcp_servers', []) if isinstance(config, dict) else []

    servers_to_connect = []
    seen_names = set()

    # 1. Collect from config.yaml (auto_connect: true or all config servers)
    for srv in mcp_servers:
        if isinstance(srv, dict) and srv.get('name'):
            if srv.get('auto_connect', True):
                servers_to_connect.append(srv)
                seen_names.add(srv['name'])

    # 2. Collect saved servers from AgentStore Database
    agent_store = getattr(app.state, 'agent_store', None)
    if agent_store and hasattr(agent_store, 'list_mcp_connections'):
        try:
            db_servers = agent_store.list_mcp_connections()
            for db_srv in db_servers:
                name = db_srv.get('name')
                if name and name not in seen_names:
                    cfg_dict = db_srv.get('config_json') or db_srv
                    if isinstance(cfg_dict, dict) and 'name' in cfg_dict:
                        servers_to_connect.append(cfg_dict)
                        seen_names.add(name)
        except Exception as db_exc:
            logger.warning("[WEB] Failed to fetch MCP connections from store: %s", db_exc)

    if not servers_to_connect:
        logger.info("[WEB] No MCP servers found to auto-connect")
        return

    logger.info("[WEB] Auto-connecting to %d MCP server(s)...", len(servers_to_connect))

    for srv_cfg in servers_to_connect:
        try:
            from src.agent.mcp_client import MCPServerConfig
            mcp_cfg = MCPServerConfig.from_dict(srv_cfg)
            success = await mcp_client.connect(mcp_cfg)
            if success:
                logger.info("[WEB] Connected to MCP server: %s", mcp_cfg.name)
                # Register MCP tools into the ToolRegistry so the LLM can see them
                if tool_registry:
                    try:
                        tools = await mcp_client.list_tools(mcp_cfg.name)
                        if tools:
                            tool_registry.register_mcp_tools(mcp_cfg.name, tools)
                            logger.info(
                                "[WEB] Registered %d MCP tools from %s into ToolRegistry",
                                len(tools), mcp_cfg.name
                            )
                    except Exception as te:
                        logger.warning(
                            "[WEB] Failed to register MCP tools for %s: %s",
                            mcp_cfg.name, te
                        )
            else:
                logger.warning("[WEB] Failed to connect to MCP server: %s", mcp_cfg.name)
        except Exception as exc:
            logger.warning(
                "[WEB] MCP auto-connect error for %s: %s",
                srv_cfg.get('name', '?'), exc
            )


def _register_page_routes(app: FastAPI) -> None:
    """Register HTML page routes for the dashboard."""
    from fastapi import Request
    from fastapi.responses import HTMLResponse

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    @app.get('/', response_class=HTMLResponse, include_in_schema=False)
    async def index(request: Request):
        return templates.TemplateResponse(request, 'agent_chat.html', {})

    @app.get('/dashboard', response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_page(request: Request):
        stats = app.state.analysis_manager.get_stats()
        recent = app.state.analysis_manager.list_jobs(limit=10)
        return templates.TemplateResponse(request, 'dashboard.html', {
            'stats': stats, 'recent_jobs': recent,
        })

    @app.get('/analysis/ioc', response_class=HTMLResponse, include_in_schema=False)
    async def ioc_page(request: Request):
        return templates.TemplateResponse(request, 'analysis_ioc.html', {})

    @app.get('/analysis/file', response_class=HTMLResponse, include_in_schema=False)
    async def file_page(request: Request):
        return templates.TemplateResponse(request, 'analysis_file.html', {})

    @app.get('/analysis/email', response_class=HTMLResponse, include_in_schema=False)
    async def email_page(request: Request):
        return templates.TemplateResponse(request, 'analysis_email.html', {})

    @app.get('/history', response_class=HTMLResponse, include_in_schema=False)
    async def history_page(request: Request):
        raw_jobs = app.state.analysis_manager.list_jobs(limit=100)
        # Normalize field names for templates
        jobs = []
        for j in raw_jobs:
            params = j.get('params') or {}
            if isinstance(params, str):
                import json as _json
                try:
                    params = _json.loads(params)
                except Exception:
                    params = {}
            j['type'] = j.get('analysis_type', '')
            j['target'] = params.get('value', params.get('filename', j.get('id', '')))
            jobs.append(j)
        return templates.TemplateResponse(request, 'history.html', {
            'jobs': jobs,
        })

    @app.get('/cases', response_class=HTMLResponse, include_in_schema=False)
    async def cases_page(request: Request):
        case_list = app.state.case_store.list_cases(limit=100)
        return templates.TemplateResponse(request, 'cases.html', {
            'cases': case_list,
        })

    @app.get('/cases/{case_id}', response_class=HTMLResponse, include_in_schema=False)
    async def case_detail_page(request: Request, case_id: str):
        case = app.state.case_store.get_case(case_id)
        if not case:
            return HTMLResponse('<h3>Case not found</h3>', status_code=404)
        return templates.TemplateResponse(request, 'case_detail.html', {
            'case': case,
        })

    @app.get('/tickets', response_class=HTMLResponse, include_in_schema=False)
    async def tickets_page(request: Request):
        from src.integrations.ticketing import get_all_tickets
        import json as _json
        try:
            raw_tickets = get_all_tickets()
        except Exception as e:
            logger.warning(f"[WEB] Failed to load tickets: {e}")
            raw_tickets = []
        tickets = []
        for t in raw_tickets:
            t = dict(t)
            recs = t.get('recommendations')
            if isinstance(recs, str):
                try:
                    t['recommendations'] = _json.loads(recs)
                except Exception:
                    t['recommendations'] = []
            tickets.append(t)
        return templates.TemplateResponse(request, 'tickets.html', {
            'tickets': tickets,
        })
    @app.get('/report/{job_id}', response_class=HTMLResponse, include_in_schema=False)
    async def report_page(request: Request, job_id: str):
        job = app.state.analysis_manager.get_job(job_id)
        if not job:
            return HTMLResponse('<h3>Report not found</h3>', status_code=404)
        return templates.TemplateResponse(request, 'report_view.html', {
            'job': job,
        })

    # ----- Agent pages -----

    @app.get('/agent/chat', response_class=HTMLResponse, include_in_schema=False)
    async def agent_chat_page(request: Request):
        return templates.TemplateResponse(request, 'agent_chat.html', {})

    @app.get('/agent/investigations', response_class=HTMLResponse, include_in_schema=False)
    async def agent_investigations_page(request: Request):
        sessions = []
        stats = {"total": 0, "active": 0, "completed": 0, "failed": 0}
        if app.state.agent_store:
            sessions = app.state.agent_store.list_sessions(limit=100)
            stats = app.state.agent_store.get_agent_stats()
        return templates.TemplateResponse(request, 'agent_investigations.html', {
            'sessions': sessions, 'stats': stats,
        })

    @app.get('/agent/playbooks', response_class=HTMLResponse, include_in_schema=False)
    async def agent_playbooks_page(request: Request):
        playbooks = []
        if app.state.playbook_engine:
            playbooks = app.state.playbook_engine.list_playbooks()
        elif app.state.agent_store:
            playbooks = app.state.agent_store.list_playbooks()
        return templates.TemplateResponse(request, 'playbooks.html', {
            'playbooks': playbooks,
        })

    @app.get('/mcp/servers', response_class=HTMLResponse, include_in_schema=False)
    async def mcp_servers_page(request: Request):
        db_servers = []
        if app.state.agent_store:
            db_servers = app.state.agent_store.list_mcp_connections()

        # Merge config.yaml servers with DB servers
        db_lookup = {s['name']: s for s in db_servers}
        config_obj = getattr(app.state, 'config', None) or {}
        config_servers = config_obj.get('mcp_servers', []) if isinstance(config_obj, dict) else []

        merged = []
        seen_names = set()
        for cfg in config_servers:
            name = cfg.get('name', '')
            if not name:
                continue
            entry = dict(cfg)
            if name in db_lookup:
                db_entry = db_lookup[name]
                entry.update({k: v for k, v in db_entry.items() if v is not None})
            entry.setdefault('source', 'config')
            entry.setdefault('status', 'planned')
            merged.append(entry)
            seen_names.add(name)
        for s in db_servers:
            if s['name'] not in seen_names:
                s.setdefault('source', 'user')
                s.setdefault('status', 'requires_install')
                merged.append(s)

        # Add live status if MCP client is available
        if hasattr(app.state, 'mcp_client') and app.state.mcp_client:
            try:
                live_status = app.state.mcp_client.get_connection_status()
                for s in merged:
                    s['live_status'] = live_status.get(s['name'], {})
            except Exception:
                pass

        # Category metadata for grouping/filtering
        from src.web.routes.mcp_management import CATEGORY_META
        categories = CATEGORY_META

        # Collect unique categories present in the server list
        active_categories = []
        seen_cats = set()
        for s in merged:
            cat = s.get('category', 'other')
            if cat not in seen_cats:
                seen_cats.add(cat)
                meta = categories.get(cat, {'label': cat.replace('_', ' ').title(), 'icon': 'bi-server'})
                active_categories.append({'key': cat, **meta})

        return templates.TemplateResponse(request, 'mcp_servers.html', {
            'servers': merged,
            'categories': categories,
            'active_categories': active_categories,
        })

    @app.get('/settings', response_class=HTMLResponse, include_in_schema=False)
    async def settings_page(request: Request):
        return templates.TemplateResponse(request, 'settings.html', {})
