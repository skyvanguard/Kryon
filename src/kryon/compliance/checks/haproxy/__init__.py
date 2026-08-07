"""HAProxy hardening check modules — each registers via `register_check` on
import. Audited via the config tree over SSH. Explicit submodule imports
trigger side-effect registration."""

from kryon.compliance.checks.haproxy import (  # noqa: F401 — side-effect
    c_hap_1_1_weak_tls,
    c_hap_1_2_stats_auth,
    c_hap_1_3_logging,
    c_hap_2_1_admin_socket,
)
