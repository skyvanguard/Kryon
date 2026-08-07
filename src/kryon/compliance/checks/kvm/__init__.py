"""KVM / libvirt / QEMU host hardening check modules — each registers via
`register_check` on import. Explicit submodule imports so importing the
package (or any single submodule) triggers side-effect registration. Read via
config files + `stat` over SSH on the libvirt host."""

from kryon.compliance.checks.kvm import (  # noqa: F401 — side-effect
    c_kvm_1_1_libvirtd_tcp_auth,
    c_kvm_1_2_socket_perms,
    c_kvm_1_3_audit_logging,
    c_kvm_1_4_tls_key_perms,
    c_kvm_1_5_tls_verify,
    c_kvm_2_1_svirt,
    c_kvm_2_2_vnc_exposure,
    c_kvm_2_3_spice_exposure,
    c_kvm_3_1_qemu_nonroot,
    c_kvm_3_2_image_perms,
    c_kvm_3_3_seccomp,
    c_kvm_3_4_clear_capabilities,
    c_kvm_3_5_namespaces,
    c_kvm_3_6_device_acl,
)
