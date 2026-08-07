"""Xen (XCP-ng / XenServer / Citrix Hypervisor) hardening check modules — each
registers via `register_check` on import. Audited via SSH on dom0 using the
`xe` CLI + Linux config. Explicit submodule imports so importing the package
triggers side-effect registration."""

from kryon.compliance.checks.xen import (  # noqa: F401 — side-effect
    c_xen_1_1_ssh_keyonly,
    c_xen_1_2_time_sync,
    c_xen_1_3_remote_syslog,
    c_xen_2_1_version,
    c_xen_2_2_patches,
)
