"""Server configuration."""

import logging
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
    cors_origins: list[str] = field(
        default_factory=lambda: ["http://localhost:5173", "http://localhost:8700"]
    )
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

    def __post_init__(self):
        if self.auth_enabled and not self.jwt_secret:
            raise ValueError(
                "auth_enabled=True but jwt_secret is empty. "
                "Set KRYON_JWT_SECRET or run the setup wizard: kryon --setup"
            )
