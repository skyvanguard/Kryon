"""VMware ESXi / vSphere check modules — each registers via `register_check`
on import. Explicit submodule imports so importing the package (or any single
submodule) triggers the side-effect registration. CIS ESXi Benchmark subset,
read via `esxcli` over SSH (operator enables SSH for the engagement)."""

from kryon.compliance.checks.vmware import (  # noqa: F401 — side-effect
    c_esx_1_1_shell_timeout,
    c_esx_1_2_mob_disabled,
    c_esx_1_3_dcui_timeout,
    c_esx_1_4_shell_service_timeout,
    c_esx_2_1_account_lockout,
    c_esx_2_2_account_unlock_time,
    c_esx_2_3_login_banner,
    c_esx_3_1_ntp,
    c_esx_3_2_remote_syslog,
    c_esx_3_3_ntp_firewall,
    c_esx_4_1_firewall,
    c_esx_4_2_snmp,
    c_esx_4_3_vswitch_security,
    c_esx_5_1_password_complexity,
    c_esx_5_2_password_history,
    c_esx_6_1_weak_tls,
    c_esx_6_2_vib_acceptance,
)
