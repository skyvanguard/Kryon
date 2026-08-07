"""Microsoft Hyper-V hardening check modules (CIS Hyper-V Benchmark subset) —
each registers via `register_check` on import. Audited via WinRM + PowerShell
(same transport as the Windows Server audit; set ctx.transport = "winrm").
Explicit submodule imports so importing the package triggers registration."""

from kryon.compliance.checks.hyperv import (  # noqa: F401 — side-effect
    c_hv_1_1_mac_spoofing,
    c_hv_1_2_automatic_stop,
    c_hv_1_3_admins_group,
    c_hv_2_1_secure_boot,
    c_hv_2_2_guest_file_copy,
    c_hv_2_3_production_checkpoints,
    c_hv_2_4_automatic_checkpoints,
    c_hv_3_1_migration_auth,
    c_hv_3_2_nested_virt,
)
