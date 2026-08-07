"""F199 — Windows Server + endpoint compliance checks via WinRM.

Each submodule registers a check on import (side-effect). Run all via
`run_compliance_audit(framework="windows")` after the runner's auto
`_import_all_checks()` pass. CheckContext.transport="winrm" routes
the commands through `run_winrm_cmd` (F36).
"""

from kryon.compliance.checks.windows import (  # noqa: F401 — side-effect imports
    c_win_1_1_smbv1,
    c_win_1_2_lsa_protection,
    c_win_1_3_dc_print_spooler,
    c_win_2_1_defender,
    c_win_2_2_firewall_domain,
    c_win_2_3_bitlocker,
    c_win_2_4_llmnr,
    c_win_2_5_wsus_internet,
    c_win_3_1_gpo_refresh,
    c_win_3_2_laps,
    c_win_3_3_audit_policy,
    c_win_3_4_rdp_nla,
    c_win_3_5_uac,
    c_win_4_1_remote_registry,
    c_win_4_2_edr_detection,
)
