"""Server configuration."""

from dataclasses import dataclass, field


@dataclass
class ServerConfig:
    """Configuration for the KRYON API server."""

    host: str = "0.0.0.0"
    port: int = 8700
    api_keys: list[str] = field(default_factory=list)
    reload: bool = False
    max_concurrent_runs: int = 10
    cors_origins: list[str] = field(default_factory=lambda: ["*"])
