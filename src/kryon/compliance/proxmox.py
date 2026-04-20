"""Proxmox VE compliance framework metadata.

Target: banking audits (ASOBAN demo). Checks run over SSH against a
Proxmox VE 7.x / 8.x node and flag misconfigurations that expose the
hypervisor or cluster to compromise.

The actual check modules live in `kryon.compliance.checks.proxmox.*` and
self-register on import.
"""

from __future__ import annotations

from dataclasses import dataclass


FRAMEWORK_ID = "proxmox-ve"
FRAMEWORK_NAME = "Proxmox VE hardening (banking profile)"
FRAMEWORK_VERSION = "1.0"

# Section numbers loosely align with CIS Proxmox Benchmark + banking
# add-ons (web UI SSL, API token hygiene, 2FA).
SECTIONS = {
    "1": "Web UI / API surface",
    "2": "SSH access",
    "3": "Cluster authentication",
    "4": "Firewall & network",
    "5": "Patch currency",
}


@dataclass(frozen=True)
class ProxmoxContext:
    """Extra hints a Proxmox check can use.

    The generic `compliance.CheckContext` already carries host / ssh_*;
    this just documents Proxmox-specific knobs a demo harness can pass
    through env vars.
    """

    web_ui_port: int = 8006
    cluster_name: str = ""
    expected_realms: tuple[str, ...] = ("pve", "pam")
