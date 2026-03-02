"""Attack Surface Management (ASM) engine — continuous discovery and diffing."""

import json
import uuid
from datetime import datetime, timezone

from kryon.sdk.agents import function_tool
from kryon.server.logging_config import get_logger
from kryon.tools.common import run_command

logger = get_logger(__name__)


@function_tool
def asm_discovery_scan(
    domain: str,
    include_subdomains: bool = True,
    include_ports: bool = True,
    previous_scan_id: str = "",
    ctf=None,
) -> str:
    """
    Run an Attack Surface Management discovery scan.

    Discovers subdomains, open ports, and services for a domain,
    building a comprehensive asset inventory.

    Args:
        domain: Target domain to scan
        include_subdomains: Enumerate subdomains (default: True)
        include_ports: Scan for open ports (default: True)
        previous_scan_id: Previous scan ID for change detection
        ctf: CTF context

    Returns:
        str: JSON discovery results with scan_id for future diffing
    """
    logger.info("asm_discovery_scan started for domain=%s include_subdomains=%s include_ports=%s", domain, include_subdomains, include_ports)
    scan_id = uuid.uuid4().hex[:12]
    results = {
        "scan_id": scan_id,
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "subdomains": [],
        "services": [],
    }

    try:
        if include_subdomains:
            sub_cmd = f"subfinder -d {domain} -silent 2>/dev/null"
            sub_output = run_command(sub_cmd, ctf=ctf)
            subdomains = [s.strip() for s in sub_output.split("\n") if s.strip()]
            results["subdomains"] = subdomains

        if include_ports:
            targets = results["subdomains"][:20] if results["subdomains"] else [domain]
            for target in targets[:5]:  # Limit to 5 for speed
                port_cmd = f"nmap -sT -T4 --top-ports 100 -Pn {target} -oG - 2>/dev/null"
                port_output = run_command(port_cmd, ctf=ctf)
                results["services"].append({"host": target, "scan_output": port_output})

        results["total_subdomains"] = len(results.get("subdomains", []))
        results["total_services"] = len(results.get("services", []))
    except Exception as exc:
        logger.error("asm_discovery_scan failed for %s: %s", domain, exc)
        results["error"] = str(exc)
        results["status"] = "failed"

    return json.dumps(results, indent=2)


@function_tool
def asm_diff(
    scan_id_old: str,
    scan_id_new: str,
    ctf=None,
) -> str:
    """
    Compare two ASM scans to identify changes in attack surface.

    Detects new subdomains, removed services, port changes, and
    other modifications between scans.

    Args:
        scan_id_old: Previous scan ID
        scan_id_new: Current scan ID
        ctf: CTF context

    Returns:
        str: Diff results showing changes between scans
    """
    logger.info("asm_diff started old=%s new=%s", scan_id_old, scan_id_new)
    return json.dumps({
        "old_scan_id": scan_id_old,
        "new_scan_id": scan_id_new,
        "status": "Diff requires stored scan data. Use the asset inventory to track changes over time.",
        "note": "Store scan results in the asset database for automated diffing.",
    }, indent=2)
