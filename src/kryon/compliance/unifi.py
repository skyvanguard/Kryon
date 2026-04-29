"""Unifi (Ubiquiti Network Controller) compliance framework metadata.

Target: corporate WiFi + small/medium enterprise audits. Checks run over SSH
against a UDM / UDM-Pro / Cloud Key (Linux underneath) or a self-hosted
controller. Configuration is dumped from MongoDB (`mongo --port 27117 ace`)
exposed locally on the controller.

Out-of-scope (NOT covered by deterministic checks):
  - Active WiFi capture (handshake / PMKID / deauth) — requires monitor-mode
    radio attached to the operator host, NOT to the Kryon container.
  - WPA passphrase cracking — offline only, separate workflow.

The actual check modules live in `kryon.compliance.checks.unifi.*` and
self-register on import.
"""

from __future__ import annotations

from dataclasses import dataclass


FRAMEWORK_ID = "unifi"
FRAMEWORK_NAME = "Unifi (Ubiquiti) controller + WiFi configuration audit"
FRAMEWORK_VERSION = "1.0"

# Sections loosely align with CIS Wireless Network Benchmark + Unifi
# operational best practices.
SECTIONS = {
    "1": "Controller (admin surface / exposure / firmware / 2FA / backup)",
    "2": "SSIDs (WPA mode / passphrase strength / WPS / open networks)",
    "3": "Segmentation (VLAN tagging / guest isolation / RADIUS hygiene)",
    "4": "Logging & firmware (syslog upstream / AP firmware currency)",
}


@dataclass(frozen=True)
class UnifiContext:
    """Extra hints a Unifi check can use.

    The generic `compliance.CheckContext` already carries host / ssh_*;
    this documents Unifi-specific knobs.
    """

    controller_https_port: int = 8443
    mongo_port: int = 27117
    mongo_db: str = "ace"
    site_name: str = "default"
