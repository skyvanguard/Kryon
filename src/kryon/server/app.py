"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from kryon.server.auth import configure_auth
from kryon.server.config import ServerConfig
from kryon.server.logging_config import get_logger, setup_logging
from kryon.server.middleware.audit import AuditMiddleware
from kryon.server.middleware.error_handler import global_exception_handler
from kryon.server.middleware.rate_limit import RateLimitMiddleware
from kryon.server.middleware.request_id import RequestIdMiddleware
from kryon.server.middleware.security_headers import SecurityHeadersMiddleware
from kryon.server.routes import agents, clients, engagements, evaluations, health, knowledge, reports, runs, scans, usage
from kryon.server.routes import admin as admin_routes
from kryon.server.routes import audit as audit_routes
from kryon.server.routes import auth_routes
from kryon.server.sessions import SessionManager

logger = get_logger(__name__)


def create_app(config: ServerConfig | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    if config is None:
        config = ServerConfig()

    setup_logging(debug=config.debug)

    # Configure JWT auth
    from kryon.server.auth.jwt_auth import configure_jwt
    configure_jwt(config.jwt_secret, config.jwt_access_ttl_minutes)

    session_manager = SessionManager(max_concurrent_runs=config.max_concurrent_runs)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup
        configure_auth(config.api_keys)
        runs.set_session_manager(session_manager)
        # Resume active engagements from DB
        try:
            from kryon.server.routes.engagements import _get_manager
            await _get_manager().resume_active_engagements()
        except Exception:
            logger.warning("Failed to resume engagements", exc_info=True)
        yield
        # Shutdown — cancel active engagement tasks
        try:
            from kryon.server.routes.engagements import _manager
            if _manager:
                for task in _manager._active_tasks.values():
                    task.cancel()
        except Exception:
            logger.warning("Error during shutdown cleanup", exc_info=True)

    app = FastAPI(
        title="KRYON API",
        description="Autonomous Cybersecurity Intelligence Platform API",
        version="1.0.0",
        lifespan=lifespan,
    )

    # Global exception handler
    app.add_exception_handler(Exception, global_exception_handler)

    # Middleware (order matters — outermost first, added last)
    # RequestId must be outermost to tag all requests
    app.add_middleware(RequestIdMiddleware)

    # Audit logging (after request ID so it's available)
    app.add_middleware(AuditMiddleware)

    # Security headers
    app.add_middleware(SecurityHeadersMiddleware, https_enabled=config.https_enabled)

    # Rate limiting
    app.add_middleware(RateLimitMiddleware, rpm=config.rate_limit_rpm)

    # CORS
    origins = config.cors_origins if not config.debug else ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount routes
    app.include_router(health.router, prefix="/api")
    app.include_router(auth_routes.router, prefix="/api")
    app.include_router(agents.router, prefix="/api")
    app.include_router(runs.router, prefix="/api")
    app.include_router(usage.router, prefix="/api")
    app.include_router(reports.router, prefix="/api")
    app.include_router(clients.router, prefix="/api")
    app.include_router(evaluations.router, prefix="/api")
    app.include_router(scans.router, prefix="/api")
    app.include_router(knowledge.router, prefix="/api")
    app.include_router(engagements.router, prefix="/api")
    app.include_router(audit_routes.router, prefix="/api")
    app.include_router(admin_routes.router, prefix="/api")

    # Serve dashboard static files if the build directory exists
    dashboard_build = Path(__file__).resolve().parent.parent.parent.parent / "dashboard" / "build"
    if dashboard_build.is_dir():
        from fastapi.staticfiles import StaticFiles

        app.mount("/", StaticFiles(directory=str(dashboard_build), html=True), name="dashboard")

    return app
