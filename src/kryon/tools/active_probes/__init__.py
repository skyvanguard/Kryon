"""F114 — Active Probes. Closes the "half-feature" gap on F103
(open redirect) and F106 (SSRF) by performing controlled,
operator-gated active probing.

Two double-gates apply to every probe in this module:
  1. `fire=True` argument on the config dataclass.
  2. `KRYON_<MODULE>_FIRE` environment variable set to "true".

Both must be present, otherwise the probe is a dry-run (constructs
payloads + reports them but sends no traffic). This mirrors the
banca-safety contract documented in CLAUDE.md for F87/F88/F90."""

from kryon.tools.active_probes.open_redirect_active import (
    OpenRedirectActiveConfig,
    OpenRedirectActiveResult,
    ActiveProbeAttempt,
    probe_open_redirect_active,
)
from kryon.tools.active_probes.ssrf_active import (
    SsrfActiveConfig,
    SsrfActiveResult,
    SsrfProbeAttempt,
    probe_ssrf_active,
)

__all__ = [
    "OpenRedirectActiveConfig",
    "OpenRedirectActiveResult",
    "ActiveProbeAttempt",
    "probe_open_redirect_active",
    "SsrfActiveConfig",
    "SsrfActiveResult",
    "SsrfProbeAttempt",
    "probe_ssrf_active",
]
