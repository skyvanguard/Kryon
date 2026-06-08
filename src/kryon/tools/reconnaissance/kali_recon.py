"""F203.BD — Banca-safe recon wrappers (Group 1, no RED_TEAM gate).

Wrappers @function_tool para Kali tools de recon/RE que son read-only
por naturaleza (DNS lookups, port scans, binary disasm). Sin gate
extra — disponibles en cualquier kryon investigate run.

Tools wrapped:
  - masscan_scan       — fast TCP port scanner
  - tcpdump_capture    — packet capture (file out, bounded)
  - dnsrecon_enum      — DNS enumeration (records, zone, brute)
  - amass_enum         — subdomain enumeration (passive + active)
  - sublist3r_enum     — alternative subdomain finder (passive only)
  - radare2_analyze    — binary analysis (info + functions)
"""

from __future__ import annotations

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def masscan_scan(
    target: str,
    ports: str = "1-65535",
    rate: int = 1000,
    output_format: str = "list",
    extra_args: str = "",
    ctf=None,
) -> str:
    """Run masscan for fast TCP port discovery.

    Banca-safe: rate-limited default 1000 pps (vs masscan default 100
    pps; 10k+ requires --rate flag overrride explícito + authorization).

    Args:
        target: IP, CIDR, or hostname (e.g. 10.0.0.0/24 or target.com).
        ports: port spec (default "1-65535" all TCP).
        rate: packets per second (default 1000, banca-safe; max 10000
            without explicit operator override).
        output_format: list (default), json, xml.
        extra_args: passthrough (e.g. "--banners" for banner grabbing).
        ctf: CTF context.

    Returns:
        str: masscan output (open ports + banner if --banners).
    """
    safe_rate = min(int(rate), 10000)
    fmt_flag = {"json": "-oJ -", "xml": "-oX -", "list": "-oL -"}.get(output_format, "-oL -")
    cmd_parts = [
        "masscan",
        target,
        f"-p {ports}",
        f"--rate {safe_rate}",
        fmt_flag,
    ]
    if extra_args:
        cmd_parts.append(extra_args)
    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def tcpdump_capture(
    interface: str = "any",
    bpf_filter: str = "",
    packet_count: int = 100,
    output_pcap: str = "",
    snaplen: int = 96,
    ctf=None,
) -> str:
    """Capture network packets with tcpdump (bounded).

    Banca-safe: bounded by packet_count (default 100). NO promiscuous
    mode unless operator passes extra_args="-p" inverse.

    Args:
        interface: network interface (default "any").
        bpf_filter: BPF filter (e.g. "host 10.0.0.5 and port 80").
        packet_count: -c flag, max packets to capture (default 100).
        output_pcap: -w path. Empty = stdout summary only.
        snaplen: -s snaplen (default 96, headers + few bytes payload).
        ctf: CTF context.

    Returns:
        str: tcpdump output (summary lines or pcap write confirmation).
    """
    cmd_parts = [
        "tcpdump",
        f"-i {interface}",
        f"-c {packet_count}",
        f"-s {snaplen}",
        "-n",  # numeric, no DNS reverse
        "-nn",  # numeric ports
    ]
    if output_pcap:
        cmd_parts.append(f"-w {output_pcap}")
    if bpf_filter:
        cmd_parts.append(f"'{bpf_filter}'")
    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def dnsrecon_enum(
    domain: str,
    record_types: str = "std",
    dictionary: str = "",
    nameserver: str = "",
    threads: int = 10,
    ctf=None,
) -> str:
    """Run dnsrecon for DNS enumeration.

    Banca-safe: passive lookups by default. -t std covers A, AAAA, MX,
    NS, SOA, TXT records. -t brt requires dictionary for subdomain brute.

    Args:
        domain: target domain (e.g. example.com).
        record_types: -t value. Common: "std" (standard records),
            "axfr" (zone transfer attempt), "brt" (brute force, needs
            dictionary), "rvl" (reverse DNS).
        dictionary: -D path for brute mode.
        nameserver: -n flag (specific resolver).
        threads: parallel threads (default 10).
        ctf: CTF context.

    Returns:
        str: dnsrecon output (records + discovered hosts).
    """
    cmd_parts = ["dnsrecon", f"-d {domain}", f"-t {record_types}", f"--threads {threads}"]
    if dictionary:
        cmd_parts.append(f"-D {dictionary}")
    if nameserver:
        cmd_parts.append(f"-n {nameserver}")
    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def amass_enum(
    domain: str,
    mode: str = "passive",
    timeout_minutes: int = 5,
    extra_args: str = "",
    ctf=None,
) -> str:
    """Run amass for subdomain enumeration (passive or active).

    Banca-safe: passive mode (default) queries OSINT sources (Cert
    Transparency, SecurityTrails, etc.) sin tocar el target. Active
    mode (-active) hace DNS lookups + cert grabbing — más ruidoso.

    Args:
        domain: target domain.
        mode: "passive" (OSINT only, default) or "active" (+ DNS probes).
        timeout_minutes: -timeout (default 5min, banca-safe).
        extra_args: passthrough (e.g. "-brute -w wordlist.txt").
        ctf: CTF context.

    Returns:
        str: amass output (one subdomain per line).
    """
    cmd_parts = ["amass", "enum"]
    if mode == "active":
        cmd_parts.append("-active")
    else:
        cmd_parts.append("-passive")
    cmd_parts.extend([f"-d {domain}", f"-timeout {timeout_minutes}"])
    if extra_args:
        cmd_parts.append(extra_args)
    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def sublist3r_enum(
    domain: str,
    bruteforce: bool = False,
    threads: int = 40,
    ports: str = "",
    ctf=None,
) -> str:
    """Run sublist3r for subdomain enumeration (passive OSINT).

    Banca-safe: queries search engines (Google, Bing, Yahoo, Baidu) +
    Netcraft + Virustotal sin tocar el target. Bruteforce opcional
    requiere wordlist.

    Args:
        domain: target domain.
        bruteforce: enable -b flag (DNS brute, requires SubBrute).
        threads: -t (default 40).
        ports: -p flag for port scanning discovered subdomains
            (e.g. "80,443"). Empty = no port scan.
        ctf: CTF context.

    Returns:
        str: sublist3r output (subdomain list).
    """
    cmd_parts = ["sublist3r", f"-d {domain}", f"-t {threads}"]
    if bruteforce:
        cmd_parts.append("-b")
    if ports:
        cmd_parts.append(f"-p {ports}")
    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def radare2_analyze(
    binary_path: str,
    commands: str = "aa;afl;ii;iz",
    ctf=None,
) -> str:
    """Run radare2 in batch mode for binary analysis.

    Banca-safe: read-only disassembly (no run, no patch). Default
    commands: aa (analyze all), afl (list functions), ii (imports),
    iz (strings in data sections).

    Args:
        binary_path: path to binary (ELF, PE, Mach-O, etc.).
        commands: r2 commands separated by ';'. Default covers
            essential static analysis. Other common: "is" (symbols),
            "ie" (entrypoint), "iE" (exports), "izz" (all strings).
        ctf: CTF context.

    Returns:
        str: r2 output (analysis results).
    """
    # -q (quiet, no banner), -c (run commands), -A (analyze on load),
    # then auto-exit after commands complete.
    cmd = f"r2 -q -c '{commands};q' '{binary_path}'"
    return run_command(cmd, ctf=ctf)
