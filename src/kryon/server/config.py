"""Server configuration."""

import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ServerConfig:
    """Configuration for the KRYON API server."""

    host: str = "0.0.0.0"
    port: int = 8700
    api_keys: list[str] = field(default_factory=list)
    reload: bool = False
    max_concurrent_runs: int = 10
    cors_origins: list[str] = field(default_factory=lambda: ["http://localhost:5173", "http://localhost:8700"])
    debug: bool = False
    rate_limit_rpm: int = 60

    # Auth (Phase 2)
    jwt_secret: str = ""
    auth_enabled: bool = False
    jwt_access_ttl_minutes: int = 60

    # TLS (Phase 3)
    ssl_certfile: str = ""
    ssl_keyfile: str = ""
    https_enabled: bool = False

    # Knowledge auto-updater
    auto_update_enabled: bool = True
    auto_update_interval_hours: int = 24
    auto_update_sources: list[str] = field(default_factory=list)

    def __post_init__(self):
        # Allow env var override for API key
        env_key = os.getenv("KRYON_API_KEY", "")
        if env_key and env_key not in self.api_keys:
            self.api_keys.append(env_key)

        # Allow env var override for JWT secret
        if not self.jwt_secret:
            self.jwt_secret = os.getenv("KRYON_JWT_SECRET", "")

        # Allow env var override for rate limit
        env_rate = os.getenv("KRYON_RATE_LIMIT", "")
        if env_rate.isdigit():
            self.rate_limit_rpm = int(env_rate)

        # Allow env var override for CORS origins. The setup wizard writes
        # KRYON_CORS_ORIGINS to .env, but nothing read it — origins silently
        # stayed at the localhost default, so the operator couldn't actually
        # restrict (or widen) cross-origin access. Comma-separated list.
        env_cors = os.getenv("KRYON_CORS_ORIGINS", "")
        if env_cors.strip():
            self.cors_origins = [o.strip() for o in env_cors.split(",") if o.strip()]

        # Allow env var override for debug
        env_debug = os.getenv("KRYON_DEBUG", "").lower()
        if env_debug in ("true", "1", "yes"):
            self.debug = True

        # Allow env var override for auto-updater
        env_auto_update = os.getenv("KRYON_AUTO_UPDATE", "").lower()
        if env_auto_update in ("false", "0", "no"):
            self.auto_update_enabled = False
        elif env_auto_update in ("true", "1", "yes"):
            self.auto_update_enabled = True

        if self.auth_enabled and not self.jwt_secret:
            raise ValueError(
                "auth_enabled=True but jwt_secret is empty. Set KRYON_JWT_SECRET or run the setup wizard: kryon --setup"
            )
        if self.host == "0.0.0.0" and self.debug:
            logger.warning(
                "Server bound to 0.0.0.0 with debug=True — this exposes the debug server to the network. "
                "Use 127.0.0.1 for local development."
            )
