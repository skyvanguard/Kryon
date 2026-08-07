"""Proxmox VE check modules — each registers via `register_check` on import.

Explicitly import every submodule so `from kryon.compliance.checks import
proxmox` triggers their side-effect `register_check` calls. Without this,
the package was empty and callers that only imported `proxmox` (instead
of the runner's `_import_all_checks`) saw zero registered controls.
"""

from kryon.compliance.checks.proxmox import (  # noqa: F401 — side-effect
    c_pve_1_1_web_ssl_cert,
    c_pve_1_2_unauth_api,
    c_pve_2_1_ssh_hardening,
    c_pve_2_2_fail2ban,
    c_pve_2_3_ssh_ciphers,
    c_pve_2_4_kernel_sysctl,
    c_pve_3_1_2fa_enforced,
    c_pve_3_2_api_token_hygiene,
    c_pve_3_3_named_users,
    c_pve_4_1_firewall_enabled,
    c_pve_4_2_firewall_logging,
    c_pve_5_1_version_currency,
    c_pve_5_2_repo_hygiene,
    c_pve_5_3_unattended_upgrades,
    c_pve_6_1_cluster_quorum,
    c_pve_7_1_time_sync,
    c_pve_8_1_backup_jobs,
)
