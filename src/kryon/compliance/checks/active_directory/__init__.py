"""AD/LDAP check modules — each registers via `register_check` on import.

Explicit submodule imports trigger the side-effect `register_check` calls
when the package is imported (without them the package is empty and the
auto-invoke dispatch in engage sees zero AD controls)."""

from kryon.compliance.checks.active_directory import (  # noqa: F401 — side-effect
    c_ad_1_1_ldap_signing,
    c_ad_1_2_ldaps_cert,
    c_ad_1_3_anon_bind,
    c_ad_2_1_kerberoastable,
    c_ad_2_2_krbtgt_rotation,
    c_ad_3_1_domain_admins,
    c_ad_3_2_password_policy,
    c_ad_4_1_smb_signing,
    c_ad_5_1_audit_policy,
)
