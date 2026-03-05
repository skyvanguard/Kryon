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
from kryon.server.routes import (
    admin as admin_routes,
    agents,
    appsec,
    assets,
    attack_paths,
    audit as audit_routes,
    auth_routes,
    billing,
    clients,
    compliance,
    engagements,
    evaluations,
    findings,
    health,
    integrations,
    knowledge,
    notifications,
    onboarding,
    remediation,
    report_settings,
    reports,
    risk,
    runs,
    scans,
    scope,
    tenants,
    usage,
    validation,
    vm_integration,
)
from kryon.server.sessions import SessionManager

logger = get_logger(__name__)


def create_app(config: ServerConfig | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    if config is None:
        config = ServerConfig()

    setup_logging(debug=config.debug)

    # Disable OpenAI tracing — not needed for server and blocks in Docker
    # (container cannot resolve api.openai.com for trace uploads)
    from kryon.sdk.agents import set_tracing_disabled

    set_tracing_disabled(True)

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
            from kryon.server.deps import get_engagement_manager

            await get_engagement_manager().resume_active_engagements()
        except Exception:
            logger.warning("Failed to resume engagements", exc_info=True)
        # Restore scheduled jobs from DB
        try:
            from kryon.server.scheduler import ScanScheduler

            _scheduler = ScanScheduler()
            restored = await _scheduler.restore_from_db()
            if restored:
                logger.info("Restored %d scheduled scan jobs", restored)
        except Exception:
            logger.warning("Failed to restore scheduled jobs", exc_info=True)
        # Start knowledge auto-updater if enabled
        if config.auto_update_enabled:
            try:
                from kryon.knowledge.auto_updater import get_auto_updater

                updater = get_auto_updater()
                schedule_type = "daily" if config.auto_update_interval_hours >= 24 else "hourly"
                updater.start(
                    schedule_type=schedule_type,
                    sources=config.auto_update_sources or None,
                )
            except Exception:
                logger.warning("Failed to start knowledge auto-updater", exc_info=True)
        yield
        # Shutdown — stop auto-updater
        if config.auto_update_enabled:
            try:
                from kryon.knowledge.auto_updater import get_auto_updater

                get_auto_updater().stop()
            except Exception:
                logger.warning("Error stopping auto-updater", exc_info=True)
        # Shutdown — cancel active engagement tasks
        try:
            from kryon.server.deps import get_engagement_manager

            get_engagement_manager().cancel_all_tasks()
        except Exception:
            logger.warning("Error during shutdown cleanup", exc_info=True)

    app = FastAPI(
        title="KRYON API",
        description="Autonomous Cybersecurity Intelligence Platform API",
        version="1.0.0",
        lifespan=lifespan,
        contact={
            "name": "KRYON Security",
            "url": "https://github.com/skyvanguard/Kryon",
        },
        license_info={
            "name": "MIT",
            "url": "https://opensource.org/licenses/MIT",
        },
        openapi_tags=[
            {"name": "health", "description": "Health checks and system status"},
            {"name": "auth", "description": "Authentication and session management"},
            {"name": "agents", "description": "Security agent listing and details"},
            {"name": "runs", "description": "Agent execution and run management"},
            {"name": "sessions", "description": "Conversational session management"},
            {"name": "engagements", "description": "Multi-day autonomous pentesting engagements"},
            {"name": "scans", "description": "Automated security scanning"},
            {"name": "clients", "description": "Client/organization management"},
            {"name": "knowledge", "description": "RAG knowledge base queries and management"},
            {"name": "reports", "description": "Security report generation"},
            {"name": "evaluations", "description": "Agent evaluation and benchmarking"},
            {"name": "usage", "description": "API usage statistics and cost tracking"},
            {"name": "audit", "description": "Audit log access (admin)"},
            {"name": "admin", "description": "System administration (admin)"},
            {"name": "appsec", "description": "Application security scanning (SAST/DAST/SCA)"},
            {"name": "validation", "description": "Offensive validation and BAS"},
            {"name": "compliance", "description": "Compliance framework assessment"},
            {"name": "assets", "description": "Asset inventory management"},
            {"name": "notifications", "description": "Multi-channel notification management"},
            {"name": "remediation", "description": "Remediation workflow and SLA enforcement"},
            {"name": "risk", "description": "Business risk scoring and impact analysis"},
            {"name": "attack_paths", "description": "Attack path visualization and kill chains"},
            {"name": "report_settings", "description": "Report branding and template configuration"},
            {"name": "onboarding", "description": "Customer onboarding wizard"},
            {"name": "billing", "description": "License validation and usage metering"},
            {"name": "vm-integration", "description": "VM scanner import (Qualys, Tenable, Rapid7, nmap, nuclei)"},
        ],
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

    # CORS — never use wildcard with credentials, even in debug
    origins = config.cors_origins
    if config.debug:
        # Add common dev origins but don't use wildcard
        dev_origins = {"http://localhost:3000", "http://localhost:5173", "http://localhost:8700"}
        origins = list(set(origins) | dev_origins)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount routes
    app.include_router(health.router, prefix="/api/v1")
    app.include_router(auth_routes.router, prefix="/api/v1")
    app.include_router(agents.router, prefix="/api/v1")
    app.include_router(runs.router, prefix="/api/v1")
    app.include_router(usage.router, prefix="/api/v1")
    app.include_router(reports.router, prefix="/api/v1")
    app.include_router(clients.router, prefix="/api/v1")
    app.include_router(evaluations.router, prefix="/api/v1")
    app.include_router(findings.router, prefix="/api/v1")
    app.include_router(scans.router, prefix="/api/v1")
    app.include_router(knowledge.router, prefix="/api/v1")
    app.include_router(engagements.router, prefix="/api/v1")
    app.include_router(scope.router, prefix="/api/v1")
    app.include_router(integrations.router, prefix="/api/v1")
    app.include_router(tenants.router, prefix="/api/v1")
    app.include_router(audit_routes.router, prefix="/api/v1")
    app.include_router(admin_routes.router, prefix="/api/v1")
    app.include_router(appsec.router, prefix="/api/v1")
    app.include_router(validation.router, prefix="/api/v1")
    app.include_router(compliance.router, prefix="/api/v1")
    app.include_router(assets.router, prefix="/api/v1")
    app.include_router(notifications.router, prefix="/api/v1")
    app.include_router(remediation.router, prefix="/api/v1")
    app.include_router(risk.router, prefix="/api/v1")
    app.include_router(attack_paths.router, prefix="/api/v1")
    app.include_router(report_settings.router, prefix="/api/v1")
    app.include_router(onboarding.router, prefix="/api/v1")
    app.include_router(billing.router, prefix="/api/v1")
    app.include_router(vm_integration.router, prefix="/api/v1")

    # Serve dashboard static files if the build directory exists
    dashboard_build = Path(__file__).resolve().parent.parent.parent.parent / "dashboard" / "build"
    if dashboard_build.is_dir():
        from fastapi.staticfiles import StaticFiles

        app.mount("/", StaticFiles(directory=str(dashboard_build), html=True), name="dashboard")

    return app
