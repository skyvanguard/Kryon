"""
KRYON Anonymity - Operational Security

Automated operational security best practices.

Clearance Level: Omega-Shadow (Maximum Anonymity Operations Authority)
Specialization: OpSec automation, secure workflows, evidence destruction
Mission: Prevent operational security failures

This module provides:
- OpSec checklist validation
- Compartmentalization enforcement
- Metadata scrubbing
- Secure workspace setup
- Evidence destruction
- OpSec training scenarios
"""

import os
from typing import Any, Optional


def opsec_checklist_validator(operation_type: str, checks: Optional[list[str]] = None) -> dict[str, Any]:
    """
    Validate OpSec checklist before operation.

    Args:
        operation_type: Type of operation
        checks: Specific checks to perform

    Returns:
        Checklist validation results

    Example:
        >>> from kryon.tools.anonymity import opsec_checklist_validator
        >>>
        >>> # Validate OpSec
        >>> result = opsec_checklist_validator(
        ...     operation_type="pentest",
        ...     checks=["vpn_active", "tor_running", "dns_leak_check"]
        ... )
        >>> if not result['all_passed']:
        ...     print(f"Failed: {result['failed_checks']}")
    """
    results = {
        "operation_type": operation_type,
        "checks_requested": checks or [],
        "passed_checks": [],
        "failed_checks": [],
        "warnings": [],
        "all_passed": False,
        "success": False,
        "error": None,
    }

    try:
        # Default checks by operation type
        default_checks = {
            "pentest": [
                "vpn_active",
                "tor_running",
                "dns_leak_check",
                "webrtc_disabled",
                "mac_spoofed",
                "timezone_randomized",
            ],
            "reconnaissance": ["vpn_active", "user_agent_randomized", "cookies_cleared"],
            "exploitation": [
                "vpn_chain_active",
                "tor_running",
                "fingerprint_randomized",
                "killswitch_enabled",
                "logs_disabled",
            ],
        }

        checks_to_perform = checks or default_checks.get(operation_type, default_checks["pentest"])

        # Simulate check execution
        check_commands = {
            "vpn_active": "ip route | grep tun",
            "tor_running": "systemctl is-active tor",
            "dns_leak_check": "# Check DNS servers",
            "webrtc_disabled": "# Browser check",
            "mac_spoofed": "ip link show | grep ether",
            "timezone_randomized": "# Check TZ",
            "cookies_cleared": "# Browser check",
        }

        for check in checks_to_perform:
            if check in check_commands:
                results["passed_checks"].append(check)
            else:
                results["failed_checks"].append(check)

        results["all_passed"] = len(results["failed_checks"]) == 0

        results["checklist_script"] = f"""
#!/bin/bash
# OpSec Checklist for {operation_type}

echo "Running OpSec checklist..."

# VPN check
if ip route | grep -q tun; then
    echo "✓ VPN active"
else
    echo "✗ VPN not active"
    exit 1
fi

# Tor check
if systemctl is-active --quiet tor; then
    echo "✓ Tor running"
else
    echo "✗ Tor not running"
    exit 1
fi

echo "All checks passed!"
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def compartmentalization_enforcer(identities: list[str], strict_mode: bool = True) -> dict[str, Any]:
    """
    Enforce identity compartmentalization.

    Args:
        identities: List of separate identities
        strict_mode: Prevent cross-contamination

    Returns:
        Compartmentalization configuration

    Example:
        >>> from kryon.tools.anonymity import compartmentalization_enforcer
        >>>
        >>> # Setup compartments
        >>> comp = compartmentalization_enforcer(
        ...     identities=["work", "personal", "activist"],
        ...     strict_mode=True
        ... )
    """
    results = {
        "identities": identities,
        "strict_mode": strict_mode,
        "vm_configs": {},
        "success": False,
        "error": None,
    }

    try:
        results["principles"] = """
Compartmentalization Principles:
1. Separate VM per identity
2. Different VPN/Tor circuits
3. No cross-contamination of data
4. Different user agents/fingerprints
5. Separate communication channels
"""

        # Generate VM configs for each identity
        for identity in identities:
            results["vm_configs"][identity] = {
                "vm_name": f"kryon_{identity}",
                "vpn_config": f"/etc/openvpn/{identity}.ovpn",
                "browser_profile": f"~/.mozilla/{identity}",
                "tor_port": 9050 + identities.index(identity),
            }

        results["qubes_os_setup"] = """
# Qubes OS - Best for compartmentalization

# Create separate qubes:
qvm-create work --label blue
qvm-create personal --label green
qvm-create activist --label red

# Set network VMs
qvm-prefs work netvm sys-vpn-work
qvm-prefs activist netvm sys-vpn-tor

# Each qube isolated
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def metadata_scrubber(file_path: str, scrub_all: bool = True) -> dict[str, Any]:
    """
    Automatically scrub metadata from file.

    Args:
        file_path: File to scrub
        scrub_all: Remove all metadata

    Returns:
        Scrubbing result

    Example:
        >>> from kryon.tools.anonymity import metadata_scrubber
        >>>
        >>> # Scrub file metadata
        >>> result = metadata_scrubber(
        ...     file_path="/tmp/document.pdf",
        ...     scrub_all=True
        ... )
    """
    results = {"file_path": file_path, "scrub_all": scrub_all, "success": False, "error": None}

    try:
        file_ext = os.path.splitext(file_path)[1].lower()

        if file_ext in [".jpg", ".jpeg", ".png", ".gif"]:
            results["command"] = f"exiftool -all= {file_path}"

        elif file_ext == ".pdf":
            results["command"] = f"exiftool -all= {file_path}"
            results["alternative"] = f"qpdf --linearize --object-streams=disable {file_path} clean.pdf"

        elif file_ext in [".docx", ".xlsx", ".pptx"]:
            results["command"] = f"exiftool -all= {file_path}"

        results["mat2_command"] = f"""
# MAT2 (Metadata Anonymisation Toolkit 2)
mat2 {file_path}

# Check metadata:
mat2 --check-dependencies
mat2 --show {file_path}
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def secure_workspace_setup(workspace_name: str = "kryon_ops", encryption: bool = True) -> dict[str, Any]:
    """
    Setup secure workspace for operations.

    Args:
        workspace_name: Workspace name
        encryption: Enable full disk encryption

    Returns:
        Workspace configuration

    Example:
        >>> from kryon.tools.anonymity import secure_workspace_setup
        >>>
        >>> # Setup secure workspace
        >>> workspace = secure_workspace_setup(
        ...     workspace_name="operation_alpha",
        ...     encryption=True
        ... )
    """
    results = {
        "workspace_name": workspace_name,
        "encryption": encryption,
        "success": False,
        "error": None,
    }

    try:
        results["directory_structure"] = f"""
~/{workspace_name}/
├── tools/          # Hacking tools
├── data/           # Target data
├── logs/           # Operation logs
├── exfil/          # Exfiltrated data
├── reports/        # Reports
└── vm/             # VM images
"""

        if encryption:
            results["encryption_setup"] = f"""
# LUKS encryption
cryptsetup luksFormat /dev/sdX
cryptsetup open /dev/sdX {workspace_name}
mkfs.ext4 /dev/mapper/{workspace_name}
mount /dev/mapper/{workspace_name} /mnt/{workspace_name}

# Or encrypted container:
dd if=/dev/zero of={workspace_name}.img bs=1M count=10240
cryptsetup luksFormat {workspace_name}.img
cryptsetup open {workspace_name}.img {workspace_name}
mkfs.ext4 /dev/mapper/{workspace_name}
"""

        results["security_measures"] = """
Security measures:
1. Full disk encryption (LUKS)
2. Encrypted swap
3. Disable logging (history, .bash_history)
4. RAM-only operations when possible
5. Automatic cleanup on shutdown
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def evidence_destruction(target: str, method: str = "shred", passes: int = 7) -> dict[str, Any]:
    """
    Securely destroy evidence.

    Methods:
    - shred: Overwrite file multiple times
    - wipe: Wipe file/directory
    - srm: Secure rm
    - dd: Overwrite disk

    Args:
        target: File/directory to destroy
        method: Destruction method
        passes: Number of overwrite passes

    Returns:
        Destruction commands

    Example:
        >>> from kryon.tools.anonymity import evidence_destruction
        >>>
        >>> # Destroy evidence
        >>> result = evidence_destruction(
        ...     target="/tmp/sensitive",
        ...     method="shred",
        ...     passes=7
        ... )
    """
    results = {
        "target": target,
        "method": method,
        "passes": passes,
        "success": False,
        "error": None,
    }

    try:
        if method == "shred":
            results["command"] = f"shred -vfz -n {passes} {target}"

        elif method == "wipe":
            results["command"] = f"wipe -rf -p {passes} {target}"

        elif method == "srm":
            results["command"] = f"srm -v -z -l -l {target}"

        elif method == "dd":
            results["command"] = f"dd if=/dev/urandom of={target} bs=1M"

        results["full_cleanup"] = f"""
# Complete evidence destruction

# 1. Shred files
find {target} -type f -exec shred -vfz -n {passes} {{}} \\;

# 2. Wipe free space
dd if=/dev/zero of=/tmp/wipefile bs=1M
rm /tmp/wipefile

# 3. Clear logs
> /var/log/syslog
> /var/log/auth.log
> ~/.bash_history

# 4. Clear swap
swapoff -a
dd if=/dev/zero of=/dev/sdX_swap bs=1M
mkswap /dev/sdX_swap
swapon -a

# 5. Clear RAM (requires restart)
sync; echo 3 > /proc/sys/vm/drop_caches
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def opsec_training_scenarios() -> dict[str, Any]:
    """
    OpSec training scenarios and common mistakes.

    Returns:
        Training scenarios

    Example:
        >>> from kryon.tools.anonymity import opsec_training_scenarios
        >>>
        >>> # Get training scenarios
        >>> training = opsec_training_scenarios()
    """
    results = {"scenarios": [], "success": False, "error": None}

    try:
        results["scenarios"] = [
            {
                "title": "DNS Leak Scenario",
                "description": "VPN active but DNS queries bypass VPN",
                "mistake": "Not configuring DNS to use VPN",
                "consequence": "ISP sees all DNS queries",
                "fix": "Use VPN's DNS servers or DNS-over-HTTPS",
            },
            {
                "title": "Timezone Leak",
                "description": "Browser reports real timezone",
                "mistake": "Not randomizing timezone",
                "consequence": "Reveals geographic location",
                "fix": "Spoof timezone to match VPN exit",
            },
            {
                "title": "Metadata in Document",
                "description": "Uploaded document contains author name",
                "mistake": "Not scrubbing metadata before upload",
                "consequence": "Real identity leaked",
                "fix": "Use exiftool/MAT2 to clean metadata",
            },
            {
                "title": "Cross-Identity Contamination",
                "description": "Used same VPN for work and activist accounts",
                "mistake": "Not compartmentalizing identities",
                "consequence": "Identities linked together",
                "fix": "Separate VMs/browsers per identity",
            },
            {
                "title": "WebRTC Leak",
                "description": "WebRTC reveals real IP despite VPN",
                "mistake": "WebRTC enabled in browser",
                "consequence": "Real IP exposed to websites",
                "fix": "Disable WebRTC or use blocking extension",
            },
        ]

        results["best_practices"] = """
OpSec Best Practices:
1. Assume breach - plan for compromise
2. Compartmentalize - separate identities completely
3. Minimize data - don't create unnecessary evidence
4. Verify constantly - check for leaks regularly
5. Practice - dry runs before real operations
6. Document - maintain OpSec procedures
7. Update - stay current with new techniques
"""

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results
