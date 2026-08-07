"""F115 — Out-of-Band probing infrastructure.

Two pieces:

  * **F115.A — Payload generator (pure)**. Given an operator-supplied
    callback domain, produces correlated payloads for SSRF / XXE /
    log4j / blind XSS. No network calls. Always available.

  * **F115.B — interactsh-client wrapper**. Wraps ProjectDiscovery's
    `interactsh-client` binary in batch mode: start session, wait,
    poll for interactions, stop. Soft-fails when binary absent.

Banca-safety: payload generation is pure (no network). The interactsh
wrapper REFUSES to use the default public oast.* servers unless the
operator explicitly opts in via `allow_public_server=True`. Default
banca workflow: operator runs a self-hosted interactsh server in
their lab + supplies the domain to Kryon."""

from kryon.tools.oob.interactsh import (
    Interaction,
    InteractshConfig,
    InteractshResult,
    is_interactsh_available,
    run_interactsh_batch,
)
from kryon.tools.oob.payloads import (
    OOB_PAYLOAD_KINDS,
    OobPayload,
    correlate_payload_with_interactions,
    correlation_id,
    generate_oob_payloads,
)

__all__ = [
    "OobPayload",
    "OOB_PAYLOAD_KINDS",
    "correlation_id",
    "correlate_payload_with_interactions",
    "generate_oob_payloads",
    "Interaction",
    "InteractshConfig",
    "InteractshResult",
    "is_interactsh_available",
    "run_interactsh_batch",
]
