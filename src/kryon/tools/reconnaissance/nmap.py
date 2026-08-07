"""
Nmap - Network Mapper
======================

Nmap is the industry-standard network scanner for port discovery,
service detection, OS fingerprinting, and security auditing.

PERFORMANCE: Results are cached with 4-hour TTL to avoid redundant
port scans and improve response times by 10-30x for repeated scans.

THROTTLING (F195 — POC-safe defaults for production targets):
Three env vars override aggressive defaults when scanning live infra:

  KRYON_NMAP_TIMING            — replaces hardcoded -T4 in full-port path.
                                 Valid: T0..T5. Banca-safe: T2.
  KRYON_NMAP_MIN_RATE          — replaces hardcoded --min-rate 1000.
                                 Banca-safe: 50.
  KRYON_NMAP_MAX_PARALLELISM   — adds --max-parallelism if not present.
                                 Banca-safe: 10.

Caller-supplied flags (LLM/operator via args=) always win — env vars
only kick in when the corresponding flag is absent from args.
"""

import os
import re

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command  # pylint: disable=E0401

# Regex to match an IPv4 address or hostname
_IP_RE = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"  # IPv4
    r"|"
    r"\b([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z]{2,})+)\b"  # hostname
)


def _is_full_port_scan(ports_str: str, flags_str: str) -> bool:
    """Check if this is a full port scan (all 65535 ports)."""
    if "-p-" in flags_str or "-p 1-65535" in flags_str:
        return True
    if ports_str:
        p = ports_str.strip().replace(" ", "")
        if p in ("1-65535", "0-65535", "-"):
            return True
    return False


def _apply_throttle_env(flags: str) -> str:
    """Layer KRYON_NMAP_* env overrides onto already-built nmap flags.

    Caller-supplied flags win — env vars only fill missing slots.
    """
    timing = os.getenv("KRYON_NMAP_TIMING", "").strip()
    if timing and "-T" not in flags:
        if not timing.startswith("-T"):
            timing = f"-T{timing.lstrip('T')}"
        flags += f" {timing}"

    min_rate = os.getenv("KRYON_NMAP_MIN_RATE", "").strip()
    if min_rate and "--min-rate" not in flags:
        flags += f" --min-rate {min_rate}"

    max_par = os.getenv("KRYON_NMAP_MAX_PARALLELISM", "").strip()
    if max_par and "--max-parallelism" not in flags:
        flags += f" --max-parallelism {max_par}"

    return flags


@function_tool(strict_mode=False)
@cache_scan_result(scan_type="port_scan", ttl=14400)  # Cache for 4 hours
def nmap(
    target: str = "",
    host: str = "",
    ip: str = "",
    args: str = "",
    flags: str = "",
    arguments: str = "",
    ports: str = "",
    services: bool = False,
    os_detection: bool = False,
    script: str = "",
    version: bool = False,
    sudo: bool = False,
    scan_type: str = "",
    address: str = "",
    ctf=None,
) -> str:
    """Scan a target IP/hostname for open ports and services.

    IMPORTANT: The 'target' parameter is REQUIRED.

    Args:
        target: IP address or hostname to scan (REQUIRED). Example: "10.10.10.5"
        host: Alias for target.
        ip: Alias for target.
        address: Alias for target.
        args: Nmap flags as a single string. Example: "-sV -sC -T4"
        flags: Alias for args.
        arguments: Full nmap command args including target. Example: "-sV -sC 10.10.10.5"
        ports: Ports to scan. Example: "80,443,8080" or "1-1000"
        services: If True, adds -sV for version detection.
        os_detection: If True, adds -O for OS fingerprinting.
        version: Alias for services (adds -sV).
        script: Nmap script to run (e.g. "default", "vuln"). Adds --script.
        sudo: Ignored (runs as current user).
        scan_type: Ignored (use args for scan type flags).

    Returns:
        Port scan results including open ports, services, versions.

    Examples:
        nmap(target="10.10.10.5", args="-sV -sC -T4")
        nmap(target="192.168.1.1", ports="80,443", services=True)
        nmap(arguments="-sV -sC 10.10.10.5")
    """
    # Merge target aliases: host/ip/address → target
    if not target and host:
        target = host
    if not target and ip:
        target = ip
    if not target and address:
        target = address

    # Merge flag aliases: flags → args, version → services, script → args
    if flags and not args:
        args = flags
    if version:
        services = True
    if not args:
        args = "-sV -sC"
    if script and script != "default":
        if "--script" not in args:
            args += f" --script {script}"
    elif script == "default":
        if "-sC" not in args:
            args += " -sC"

    # Handle the 'arguments' alias: model often sends everything in one string
    if arguments and not target:
        parts = arguments.strip().split()
        extracted_target = ""
        flag_parts = []
        i = 0
        while i < len(parts):
            part = parts[i]
            if part.startswith("-"):
                flag_parts.append(part)
                if i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                    if re.match(r"^-[poPsSdDegiIkm]$|^--", part):
                        i += 1
                        flag_parts.append(parts[i])
            else:
                extracted_target = part
            i += 1
        if extracted_target:
            target = extracted_target
            args = " ".join(flag_parts) if flag_parts else "-sV -sC"
        else:
            command = f"nmap {arguments}"
            return run_command(command, ctf=ctf)

    # Last resort: try to find target in any string parameter
    if not target:
        for key in ("target", "host", "ip", "address"):
            val = locals().get(key, "")
            if val and isinstance(val, str):
                target = val.strip()
                break
        if not target:
            for val in (args, flags, arguments, ports, script, scan_type):
                if isinstance(val, str) and val:
                    match = _IP_RE.search(val)
                    if match:
                        target = match.group(0)
                        break

    if not target:
        return (
            "Error: target is required. You must provide the IP or hostname.\n"
            'Correct usage: nmap(target="10.10.10.5", args="-sV -sC -T4")\n'
            "The parameter name MUST be 'target'. Example:\n"
            '  nmap(target="10.64.189.65", args="-sV -sC")'
        )

    from kryon.validation.target_guard import placeholder_reason

    _ph = placeholder_reason(target)
    if _ph:
        return _ph

    nmap_flags = args
    if ports:
        nmap_flags += f" -p {ports}"
    if services and "-sV" not in nmap_flags:
        nmap_flags += " -sV"
    if os_detection and "-O" not in nmap_flags:
        nmap_flags += " -O"

    # STARVATION FIX (UNIVERSAL — every nmap variant, not just -p-). A model-issued slow nmap
    # (-p-, or 1-1000 -sV -O, etc.) over VPN used to run up to ~the reflective runner's 900s chunk
    # budget, consuming the whole turn so the deterministic chain-planner autoexec (which only
    # fires between chunks) never got control (the run died at turn 2). Bound EVERY scan: hand
    # nmap a self-bounding --host-timeout + --max-retries 1 (it aborts a slow host instead of
    # hanging) and cap the subprocess at KRYON_NMAP_FULL_TIMEOUT_S (default 240s). Tunable up for
    # thorough offline scans; a redundant model scan can no longer starve the loop.
    try:
        full_timeout = int(os.getenv("KRYON_NMAP_FULL_TIMEOUT_S") or 240)
    except ValueError:
        full_timeout = 240
    if "--host-timeout" not in nmap_flags:
        nmap_flags += f" --host-timeout {max(60, full_timeout - 30)}s"
    if "--max-retries" not in nmap_flags:
        nmap_flags += " --max-retries 1"

    is_full = _is_full_port_scan(ports, nmap_flags)
    if is_full:
        # Default aggressive flags for full-port scans over VPN. F195: env
        # overrides take precedence via _apply_throttle_env below.
        if "-T" not in nmap_flags and not os.getenv("KRYON_NMAP_TIMING"):
            nmap_flags += " -T4"
        if "--min-rate" not in nmap_flags and not os.getenv("KRYON_NMAP_MIN_RATE"):
            nmap_flags += " --min-rate 1000"
        nmap_flags = _apply_throttle_env(nmap_flags)
        # For full port scans, skip version detection first (too slow)
        # Do a fast SYN scan to find open ports, then detailed scan
        if "-sV" in nmap_flags:
            # Phase 1: Fast port discovery without version detection
            fast_flags = nmap_flags.replace("-sV", "").replace("-sC", "").strip()
            fast_flags = re.sub(r"\s+", " ", fast_flags)
            fast_cmd = f"nmap {fast_flags} {target}"
            fast_result = run_command(fast_cmd, ctf=ctf, timeout=full_timeout)

            # Extract open ports from fast scan
            open_ports = re.findall(r"(\d+)/tcp\s+open", fast_result)
            if open_ports:
                # Phase 2: Detailed scan only on the open ports (fast, bounded too).
                port_list = ",".join(open_ports)
                detail_flags = _apply_throttle_env("-sV -sC")
                detail_cmd = f"nmap {detail_flags} -p {port_list} {target}"
                return run_command(detail_cmd, ctf=ctf, timeout=min(full_timeout, 180))
            else:
                return fast_result  # No open ports found

    nmap_flags = _apply_throttle_env(nmap_flags)
    command = f"nmap {nmap_flags} {target}"
    # Bounded too (the --host-timeout above self-limits; this caps the subprocess as a backstop).
    return run_command(command, ctf=ctf, timeout=full_timeout)
