"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from kryon.server.auth import configure_auth
from kryon.server.config import ServerConfig
from kryon.server.routes import agents, health, runs, usage
from kryon.server.sessions import SessionManager


def create_app(config: ServerConfig | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    if config is None:
        config = ServerConfig()

    session_manager = SessionManager(max_concurrent_runs=config.max_concurrent_runs)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup
        configure_auth(config.api_keys)
        runs.set_session_manager(session_manager)
        yield
        # Shutdown — nothing to clean up for now

    app = FastAPI(
        title="KRYON API",
        description="Autonomous Cybersecurity Intelligence Platform API",
        version="1.0.0",
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount routes
    app.include_router(health.router, prefix="/api")
    app.include_router(agents.router, prefix="/api")
    app.include_router(runs.router, prefix="/api")
    app.include_router(usage.router, prefix="/api")

    # Serve dashboard static files if the build directory exists
    dashboard_build = Path(__file__).resolve().parent.parent.parent.parent / "dashboard" / "build"
    if dashboard_build.is_dir():
        from fastapi.staticfiles import StaticFiles

        app.mount("/", StaticFiles(directory=str(dashboard_build), html=True), name="dashboard")

    return app
