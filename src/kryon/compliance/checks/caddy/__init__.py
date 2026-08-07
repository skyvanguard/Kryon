"""Caddy web-server hardening check modules — each registers via
`register_check` on import. Audited via the Caddyfile over SSH. Explicit
submodule imports trigger side-effect registration."""

from kryon.compliance.checks.caddy import (  # noqa: F401 — side-effect
    c_caddy_1_1_admin_exposure,
    c_caddy_1_2_auto_https,
    c_caddy_1_3_tls_protocols,
    c_caddy_2_1_file_browse,
)
