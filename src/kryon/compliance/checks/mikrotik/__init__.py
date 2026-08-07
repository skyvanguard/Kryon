"""MikroTik RouterOS hardening check modules — each registers via
`register_check` on import. Audited via the RouterOS CLI over SSH. Explicit
submodule imports so importing the package triggers side-effect registration."""

from kryon.compliance.checks.mikrotik import (  # noqa: F401 — side-effect
    c_mtk_1_1_insecure_services,
    c_mtk_1_2_ssh_strong_crypto,
    c_mtk_1_3_bandwidth_server,
    c_mtk_2_1_ntp_client,
    c_mtk_2_2_snmp_community,
    c_mtk_2_3_remote_logging,
)
