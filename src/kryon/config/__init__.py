"""Centralized Kryon configuration.

Single source of truth for the core runtime config. Historically defaults
(model name, temperature, timeouts, paths) were duplicated across 100+ call
sites with ``os.getenv(..., "<default>")`` — divergent defaults caused subtle
drift. ``KryonSettings`` reads the environment ONCE with typed, documented
defaults; new code should read from it instead of re-deriving defaults.

    from kryon.config import settings
    model = settings().model
"""

from kryon.config.settings import KryonSettings, settings

__all__ = ["KryonSettings", "settings"]
