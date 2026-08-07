"""FortiGate (FortiOS) check modules — each registers via `register_check` on import.

Explicitly import every submodule so `from kryon.compliance.checks import
fortigate` triggers their side-effect `register_check` calls (otherwise
the package is empty and engage's auto-invoke path sees zero FGT controls).
"""

from kryon.compliance.checks.fortigate import (  # noqa: F401 — side-effect
    c_fgt_1_1_default_creds,
    c_fgt_1_2_admin_https_only,
    c_fgt_1_3_trusthost,
    c_fgt_1_4_2fa_enforced,
    c_fgt_1_5_admin_idle_timeout,
    c_fgt_1_6_super_admin_count,
    c_fgt_1_7_admin_gui_tls,
    c_fgt_1_8_password_policy,
    c_fgt_1_9_maintainer,
    c_fgt_2_1_iface_allowaccess,
    c_fgt_2_2_snmp_community,
    c_fgt_2_3_ntp_auth,
    c_fgt_2_4_dns_servers,
    c_fgt_2_5_strong_crypto,
    c_fgt_3_1_sslvpn_tls_min,
    c_fgt_3_2_sslvpn_mfa,
    c_fgt_3_3_sslvpn_portal_exposure,
    c_fgt_3_4_sslvpn_policy_source,
    c_fgt_3_5_sslvpn_timeouts,
    c_fgt_4_1_syslog_upstream,
    c_fgt_4_2_log_storage,
    c_fgt_4_3_log_retention,
    c_fgt_5_1_fortios_version_currency,
    c_fgt_5_2_fortiguard_licenses,
    c_fgt_5_3_known_cve_exposure,
    c_fgt_6_1_allow_all_policies,
    c_fgt_6_2_policy_logging,
    c_fgt_6_3_policy_utm_profiles,
)
