"""Cisco IOS / IOS-XE hardening check modules (CIS Cisco Benchmark subset) —
each registers via `register_check` on import. Audited via `show running-config`
over SSH. Explicit submodule imports trigger side-effect registration."""

from kryon.compliance.checks.cisco import (  # noqa: F401 — side-effect
    c_ios_1_1_vty_ssh,
    c_ios_1_2_enable_secret,
    c_ios_1_3_password_encryption,
    c_ios_2_1_snmp_community,
    c_ios_2_2_http_server,
)
