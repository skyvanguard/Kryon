"""Linux OS baseline check modules (CIS Distribution-Independent Linux subset)
— each registers via `register_check` on import. Audited via SSH (sshd -T,
/etc/passwd, /etc/shadow, stat). Explicit submodule imports trigger
side-effect registration."""

from kryon.compliance.checks.linux import (  # noqa: F401 — side-effect
    c_lnx_1_1_root_login,
    c_lnx_1_2_empty_passwords_ssh,
    c_lnx_2_1_shadow_empty_password,
    c_lnx_2_2_uid0,
    c_lnx_2_3_shadow_perms,
)
