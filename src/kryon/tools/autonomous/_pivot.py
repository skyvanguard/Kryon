"""Network pivot / lateral-movement helpers.

Extraído de ``orchestrator.py`` (era 1612 líneas → split en módulos).
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


def _check_lateral_movement(host_ip: str, results: dict, *, run_cmd: Callable[[str], str] | None = None) -> list[dict]:
    """Enumerate lateral-movement opportunities from a compromised host.

    Rewritten: every old probe called a non-existent tool function
    (capture_traffic.get_network_interfaces, filesystem.search_files,
    netstat.get_routing_table, remote_execution.enumerate_smb_shares,
    pth_attacks.dump_credentials, docker_bench.check_docker_access,
    kube_hunter.check_kubernetes_access — NONE exist), so the broad except
    swallowed the first AttributeError and it always returned []. Now it runs
    real read-only commands over ``run_cmd`` (the pivot SSH executor,
    injectable) and parses their output with the correct RFC1918 helpers.

    ``run_cmd`` is REQUIRED to reach the host — without a post-exploit shell
    threaded in, this returns [] rather than pretending. Guarded on prior shell
    access. Covers routed/multi-homed private networks, SSH private keys, and
    docker access (the probes doable over a plain shell)."""
    opportunities: list[dict] = []

    if not any(e.get("shell_obtained") for e in results.get("exploitation_path", [])):
        return opportunities
    if run_cmd is None:
        return opportunities

    def _probe(label: str, command: str) -> str:
        try:
            return run_cmd(command) or ""
        except Exception:  # noqa: BLE001 — one probe failing must not abort the rest
            logger.debug("lateral-movement: '%s' probe failed", label, exc_info=True)
            return ""

    # Routed / multi-homed private networks → pivot candidates.
    net_out = _probe("routes", "ip route 2>/dev/null; ip -o -4 addr show 2>/dev/null")
    for network in _networks_from_text(net_out):
        if network != f"{host_ip}/32":
            opportunities.append(
                {
                    "type": "routed_network",
                    "target_network": network,
                    "pivot_method": "socks_proxy",
                    "confidence": 0.85,
                }
            )

    # SSH private keys → key-based pivot to other hosts.
    keys_out = _probe(
        "ssh-keys",
        "find /home /root -maxdepth 3 \\( -name id_rsa -o -name id_ed25519 -o -name '*.pem' \\) 2>/dev/null",
    )
    for path in (ln.strip() for ln in keys_out.splitlines() if ln.strip()):
        opportunities.append(
            {
                "type": "ssh_key_found",
                "key_path": path,
                "pivot_method": "ssh_key_authentication",
                "confidence": 0.8,
            }
        )

    # Docker access → container pivot / escape.
    docker_out = _probe("docker", "docker ps --format '{{.Names}}' 2>/dev/null")
    containers = [ln.strip() for ln in docker_out.splitlines() if ln.strip()]
    if containers:
        opportunities.append(
            {
                "type": "docker_access",
                "containers": containers,
                "pivot_method": "container_escape",
                "confidence": 0.7,
            }
        )

    return opportunities


_CIDR_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b")
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# Read-only enumeration commands run over the pivot's shell. Each self-degrades
# (2>/dev/null / `||`) so a missing tool yields empty output, not an error.
_INTERNAL_ENUM_COMMANDS: tuple[tuple[str, str], ...] = (
    ("routes", "ip route 2>/dev/null || netstat -rn 2>/dev/null"),
    ("addrs", "ip -o -4 addr show 2>/dev/null"),
    ("neighbors", "ip neigh 2>/dev/null || arp -a 2>/dev/null"),
    ("hosts", "cat /etc/hosts 2>/dev/null"),
    ("dhcp", "cat /var/lib/dhcp/dhclient.leases 2>/dev/null || cat /var/lib/dhclient/dhclient.leases 2>/dev/null"),
    ("docker", "docker network inspect $(docker network ls -q) 2>/dev/null"),
)
_WINDOWS_ENUM_COMMANDS: tuple[tuple[str, str], ...] = (
    ("routes", "route print"),
    ("neighbors", "arp -a"),
    ("hosts", "type C:\\Windows\\System32\\drivers\\etc\\hosts"),
)


def _as_private_network(value: str) -> str | None:
    """Normalize a CIDR to its private canonical form, or None.

    Uses ``ipaddress.is_private`` (correct RFC1918) instead of the old string
    prefix that wrongly treated all of 172.0.0.0/8 as private — only
    172.16.0.0/12 is."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    return str(net) if net.is_private else None


def _private_24_from_ip(ip: str) -> str | None:
    """Collapse a bare IPv4 to its /24, only if that IP is private. Used where
    just a host address is known (ARP, /etc/hosts, DHCP routers)."""
    ip = (ip or "").strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4 or not addr.is_private:
        return None
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def _networks_from_text(text: str) -> list[str]:
    """Extract private network CIDRs from arbitrary command output.

    Explicit CIDR tokens (ip route, addr, docker Subnet) are kept when private;
    bare IPs (arp, /etc/hosts, dhcp) collapse to their private /24. Order-
    preserving and de-duplicated."""
    out: list[str] = []
    seen: set[str] = set()

    def _add(net: str | None) -> None:
        if net and net not in seen:
            seen.add(net)
            out.append(net)

    text = text or ""
    for cidr in _CIDR_RE.findall(text):
        _add(_as_private_network(cidr))
    for ip in _IPV4_RE.findall(text):
        _add(_private_24_from_ip(ip))
    return out


def _default_pivot_runner(host_ip: str, credentials: dict) -> Callable[[str], str]:
    """Build the real remote-command executor from the pivot credentials.

    Prefers password auth (the sshpass tool) when a password is present, else an
    ssh key. Returns "" when no usable credential exists, so discovery degrades
    to the /24 fallback instead of raising."""
    user = credentials.get("username") or credentials.get("user") or "root"
    password = credentials.get("password") or ""
    key = credentials.get("ssh_key") or credentials.get("ssh_key_path") or ""
    port = int(credentials.get("port", 22) or 22)

    def _run(command: str) -> str:
        if password:
            from kryon.tools.command_and_control.sshpass import run_ssh_command_with_credentials

            return run_ssh_command_with_credentials._raw_fn(
                host=host_ip, username=user, password=password, command=command, port=port
            )
        if key:
            from kryon.tools.common import run_command

            return run_command(
                f"ssh -i {key} -o StrictHostKeyChecking=no -o BatchMode=yes -p {port} {user}@{host_ip} '{command}'"
            )
        return ""

    return _run


def _discover_internal_networks(
    host_ip: str, credentials: dict, *, run_cmd: Callable[[str], str] | None = None
) -> list[str]:
    """Discover internal network CIDRs reachable from a compromised pivot.

    Runs read-only enumeration commands over the pivot's shell (routing table,
    interfaces, ARP/neighbors, /etc/hosts, DHCP leases, docker nets) and parses
    their output for PRIVATE networks. ``run_cmd`` is the only impure dependency
    (the SSH executor); inject a fake in tests. Falls back to the pivot's own
    /24 when nothing is found.

    NOTE: acting on the returned networks (pivoting into them) may exceed the
    original engagement scope — that authorization check is the caller's."""
    run = run_cmd or _default_pivot_runner(host_ip, credentials)
    is_windows = str(credentials.get("platform", "")).lower() == "windows"
    commands = _WINDOWS_ENUM_COMMANDS if is_windows else _INTERNAL_ENUM_COMMANDS

    found: list[str] = []
    seen: set[str] = set()

    def _add(net: str | None) -> None:
        if net and net not in seen:
            seen.add(net)
            found.append(net)

    for label, command in commands:
        try:
            output = run(command) or ""
        except Exception:  # noqa: BLE001 — one failed command must not abort discovery
            logger.debug("internal-net discovery: '%s' command failed", label, exc_info=True)
            continue
        for net in _networks_from_text(output):
            _add(net)

    found.sort()

    if not found:
        # Fallback: the pivot's own /24 (works for a private pivot; for a public
        # pivot IP, derive the dotted-quad /24 as a last resort).
        _add(_private_24_from_ip(host_ip))
        if not found:
            octets = host_ip.split(".")
            if len(octets) == 4 and all(o.isdigit() for o in octets):
                found.append(f"{octets[0]}.{octets[1]}.{octets[2]}.0/24")

    return found


_NMAP_HOST_RE = re.compile(r"Nmap scan report for (?:.*\()?(\d{1,3}(?:\.\d{1,3}){3})")
_NMAP_PORT_RE = re.compile(r"^\s*(\d+)/tcp\s+open\s+(\S+)?")


def _parse_nmap_hosts(text: str) -> list[dict]:
    """Parse nmap normal output into ``[{ip, ports}]`` for hosts with open ports."""
    hosts: list[dict] = []
    current: dict | None = None
    for line in (text or "").splitlines():
        m = _NMAP_HOST_RE.search(line)
        if m:
            current = {"ip": m.group(1), "ports": []}
            hosts.append(current)
            continue
        if current is not None:
            pm = _NMAP_PORT_RE.match(line)
            if pm:
                current["ports"].append({"port": int(pm.group(1)), "service": pm.group(2) or ""})
    return [h for h in hosts if h["ports"]]


def _default_proxied_scanner(network: str, socks_proxy: str) -> str:
    from kryon.tools.common import run_command

    # -sT (TCP connect) is the only scan type that works through a SOCKS proxy;
    # -Pn because ICMP host-discovery won't traverse it. proxychains routes it.
    return run_command(f"proxychains4 -q nmap -sT -Pn -T3 --open {network}")


def _enumerate_through_pivot(
    network: str, socks_proxy: str, *, scanner: Callable[[str, str], str] | None = None
) -> list[dict]:
    """Enumerate live hosts in ``network`` through the SOCKS proxy.

    Was a ``return []`` stub. Runs nmap wrapped in proxychains (the default
    ``scanner``); inject a fake in tests. Returns ``[{ip, ports}]`` for hosts
    with at least one open port."""
    scan = scanner or _default_proxied_scanner
    try:
        output = scan(network, socks_proxy) or ""
    except Exception:  # noqa: BLE001 — a scan failure must not crash the pivot
        logger.debug("pivot enumeration failed for %s", network, exc_info=True)
        return []
    return _parse_nmap_hosts(output)


def _autonomous_compromise_through_pivot(
    target_ip: str, socks_proxy: str, *, solver: Callable[[str], dict] | None = None
) -> dict[str, Any]:
    """Attempt autonomous compromise of a host reached through the pivot.

    Was a ``{success: False}`` stub. Delegates to the real
    ``autonomous_ctf_solver`` (a genuine end-to-end compromise attempt);
    ``solver`` is injectable for tests. NOTE: routing every sub-tool through the
    tunnel relies on the operator's proxychains config set up with the pivot."""

    def _default_solver(ip: str) -> dict:
        # Lazy import breaks the cycle: orchestrator.py imports FROM _pivot, and the
        # default solver reaches BACK to the autonomous_ctf_solver entry point there.
        from kryon.tools.autonomous.orchestrator import autonomous_ctf_solver

        return autonomous_ctf_solver._raw_fn(target_ip=ip, max_time_hours=1)

    run_solver = solver or _default_solver
    try:
        result = run_solver(target_ip) or {}
    except Exception as e:  # noqa: BLE001 — surface, don't crash the pivot loop
        logger.debug("pivot compromise of %s failed", target_ip, exc_info=True)
        return {"success": False, "access_level": "none", "error": str(e)}
    return {
        "success": bool(result.get("success")),
        "access_level": result.get("privilege_level", "none"),
        "services_exploited": result.get("services_exploited", []),
    }


def _check_objective_achieved(objective: str, results: dict) -> bool:
    """
    Check if a specific mission objective has been achieved.

    Validates objective completion based on operation results and gathered evidence.

    Args:
        objective: Objective name (initial_access, privilege_escalation, find_flags, etc.)
        results: Current operation results dictionary

    Returns:
        True if objective is achieved, False otherwise
    """
    objective = objective.lower()

    try:
        # Initial Access objective
        if objective == "initial_access":
            # Check if any service has been successfully exploited
            if results.get("services_exploited") and len(results["services_exploited"]) > 0:
                return True

            # Check if any exploitation was successful
            for step in results.get("exploitation_path", []):
                if step.get("phase") == "exploitation" and step.get("status") == "success":
                    return True

            # Check if we have shell access
            if any(step.get("shell_obtained") for step in results.get("exploitation_path", [])):
                return True

        # Privilege Escalation objective
        elif objective == "privilege_escalation":
            # Check privilege level
            privilege_level = results.get("privilege_level", "none")

            if privilege_level in ["root", "system", "administrator"]:
                return True

            # Check if privesc phase was successful
            for step in results.get("exploitation_path", []):
                if step.get("phase") == "privilege_escalation" and step.get("status") == "success":
                    return True

        # Find Flags objective
        elif objective == "find_flags":
            # Check if any flags were found
            if results.get("flags_found") and len(results["flags_found"]) > 0:
                # Filter out empty flags
                valid_flags = [f for f in results["flags_found"] if f.get("value")]
                return len(valid_flags) > 0

        # Lateral Movement objective
        elif objective == "lateral_movement":
            # Check if lateral movement opportunities were identified
            for step in results.get("exploitation_path", []):
                if step.get("phase") == "lateral_movement":
                    return True

            # Check if any pivoting was successful
            if results.get("pivoted_hosts"):
                return len(results["pivoted_hosts"]) > 0

        # Data Exfiltration objective
        elif objective == "data_exfiltration":
            # Check if any data was exfiltrated
            if results.get("data_exfiltrated"):
                return True

            for step in results.get("exploitation_path", []):
                if step.get("phase") == "exfiltration" and step.get("status") == "success":
                    return True

        # Reconnaissance objective
        elif objective == "reconnaissance":
            # Check if recon was performed
            for step in results.get("exploitation_path", []):
                if step.get("phase") == "reconnaissance" and step.get("status") == "completed":
                    return True

            # Check if services were detected
            if results.get("services_detected") and len(results["services_detected"]) > 0:
                return True

        # Vulnerability Assessment objective
        elif objective == "vulnerability_assessment":
            # Check if vulnerabilities were found
            for step in results.get("exploitation_path", []):
                if step.get("vulnerabilities_found", 0) > 0:
                    return True

        # Persistence objective
        elif objective == "persistence":
            # Check if persistence mechanisms were established
            for step in results.get("exploitation_path", []):
                if step.get("phase") == "persistence" and step.get("status") == "success":
                    return True

            if results.get("persistence_established"):
                return True

        # Credentials Gathering objective
        elif objective == "credentials_gathering":
            # Check if credentials were discovered
            for step in results.get("exploitation_path", []):
                if step.get("phase") == "intelligence" and step.get("status") == "credentials_discovered":
                    return True

            if results.get("credentials_found") and len(results["credentials_found"]) > 0:
                return True

        # Network Mapping objective
        elif objective == "network_mapping":
            # Check if internal networks were discovered
            if results.get("internal_networks") and len(results["internal_networks"]) > 0:
                return True

            for step in results.get("exploitation_path", []):
                if "network_mapping" in step.get("phase", ""):
                    return True

        # Domain Compromise objective
        elif objective == "domain_compromise":
            # Check if domain admin access was achieved
            if results.get("privilege_level") in ["domain_admin", "enterprise_admin"]:
                return True

            if results.get("domain_compromised"):
                return True

        # Defense Evasion objective
        elif objective == "defense_evasion":
            # Check if defenses were successfully evaded
            defenses_bypassed = []
            for step in results.get("exploitation_path", []):
                if step.get("defenses_bypassed"):
                    defenses_bypassed.extend(step["defenses_bypassed"])

            return len(defenses_bypassed) > 0

    except Exception:
        # If there's an error checking, assume objective not achieved
        pass

    return False
