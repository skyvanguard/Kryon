"""F203.BC — Thin @function_tool wrappers para 5 herramientas Kali
instaladas en el container Kryon (v2026.3.2) pero antes solo accesibles
vía `run_command` genérico.

Cada wrapper:
- Validates schema (target URL/host, options típicos)
- Construye args canónicos del binary
- Delega a run_command (output capture + ctf context)
- Devuelve stdout/stderr para narration del LLM

Banca-safe: todos son tools de reconocimiento read-only. Para uso
intrusivo (auth bruteforce con wpscan --passwords, gobuster con
wordlists masivos) el operator debe pasar args explícitos.
"""

from __future__ import annotations

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def wpscan_scan(
    target_url: str,
    enumerate: str = "u,p,t",
    threads: int = 20,
    random_user_agent: bool = True,
    api_token: str = "",
    ctf=None,
) -> str:
    """Run wpscan against a WordPress target — enumerate users, plugins, themes.

    Banca-safe: read-only enumeration. NO brute-force passwords (eso
    requiere --passwords flag explicito del operator + ROE escrito).

    Args:
        target_url: WordPress site URL (e.g. https://wp.example.com)
        enumerate: comma-separated targets — u (users), p (plugins),
            t (themes), vp (vulnerable plugins), vt (vulnerable themes),
            tt (timthumbs), cb (config backups), dbe (db exports).
            Default: u,p,t (sane baseline).
        threads: parallel requests (default 20, banca-safe limit).
        random_user_agent: rotate UA to evade trivial WAF (default True).
        api_token: WPScan API token (optional, unlocks vuln data lookups).
        ctf: CTF context for execution.

    Returns:
        str: wpscan stdout (findings + enumeration).
    """
    cmd_parts = [
        "wpscan",
        f"--url {target_url}",
        f"--enumerate {enumerate}",
        f"-t {threads}",
    ]
    if random_user_agent:
        cmd_parts.append("--random-user-agent")
    if api_token:
        cmd_parts.append(f"--api-token {api_token}")
    cmd_parts.append("--disable-tls-checks")
    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def nikto_scan(
    target_url: str,
    tuning: str = "x6",
    max_time_seconds: int = 60,
    extra_args: str = "",
    ctf=None,
) -> str:
    """Run nikto web vulnerability scanner against a target.

    Banca-safe: nikto -Tuning x6 excluye DoS tests. max_time bound
    para no saturar el target. Read-only HTTP probes.

    Args:
        target_url: URL or host (e.g. https://target.com or 10.0.0.5).
        tuning: nikto -Tuning value. Default "x6" excludes DoS.
            Common: "x6" (no DoS), "1" (interesting files), "2" (misconfigs),
            "3" (info disclosure), "4" (injection), "5" (RFI), "9" (sqli).
        max_time_seconds: -maxtime bound, default 60.
        extra_args: passthrough extra args (e.g. "-Cgidirs all").
        ctf: CTF context.

    Returns:
        str: nikto findings (+ Server/HSTS/methods detection).
    """
    cmd_parts = [
        "nikto",
        f"-h {target_url}",
        f"-Tuning {tuning}",
        f"-maxtime {max_time_seconds}",
        "-ask no",
        "-nointeractive",
    ]
    if extra_args:
        cmd_parts.append(extra_args)
    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def gobuster_dir(
    target_url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "php,html,txt,js,json",
    threads: int = 30,
    status_codes_blacklist: str = "404",
    timeout_seconds: int = 5,
    ctf=None,
) -> str:
    """Run gobuster dir mode for directory/file enumeration.

    Banca-safe: rate-limited threads, status code filtering, common
    wordlist (Kali default). Para wordlists grandes (raft-large,
    SecLists/web-content/big.txt) usar extra_wordlist arg.

    Args:
        target_url: target URL (e.g. https://target.com)
        wordlist: path to wordlist (default Kali dirb common.txt).
        extensions: comma-separated extensions to test.
        threads: parallel (default 30, banca-safe).
        status_codes_blacklist: HTTP codes to skip (default 404).
        timeout_seconds: per-request timeout.
        ctf: CTF context.

    Returns:
        str: gobuster output (discovered paths + status codes).
    """
    cmd_parts = [
        "gobuster",
        "dir",
        f"-u {target_url}",
        f"-w {wordlist}",
        f"-x {extensions}",
        f"-t {threads}",
        f"-b {status_codes_blacklist}",
        f"--timeout {timeout_seconds}s",
        "-q",  # quiet (no banner)
        "--no-error",
    ]
    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def httpx_probe(
    targets: str,
    status_code: bool = True,
    title: bool = True,
    tech_detect: bool = True,
    follow_redirects: bool = True,
    threads: int = 50,
    timeout_seconds: int = 10,
    ctf=None,
) -> str:
    """Run httpx (projectdiscovery) for fast HTTP probing across targets.

    Banca-safe: read-only HEAD/GET. Ideal para asset discovery sobre
    grandes listas de hosts/URLs (ports 80/443/8080/8443 default).

    Args:
        targets: newline-separated targets (URL/host/CIDR) — passed
            via stdin to httpx.
        status_code: include status code in output (default True).
        title: include page <title> (default True).
        tech_detect: technology fingerprinting (default True — uses
            Wappalyzer ruleset embedded).
        follow_redirects: follow 30x (default True).
        threads: parallel (default 50, banca-safe).
        timeout_seconds: per-request (default 10).
        ctf: CTF context.

    Returns:
        str: httpx output (one line per probed target).
    """
    flags = []
    if status_code:
        flags.append("-status-code")
    if title:
        flags.append("-title")
    if tech_detect:
        flags.append("-tech-detect")
    if follow_redirects:
        flags.append("-follow-redirects")
    flags.append(f"-threads {threads}")
    flags.append(f"-timeout {timeout_seconds}")
    flags.append("-silent")
    flags.append("-no-color")
    # echo "targets" | httpx <flags>
    cmd = f"echo '{targets}' | httpx {' '.join(flags)}"
    return run_command(cmd, ctf=ctf)


@function_tool
def enum4linux_scan(
    target_host: str,
    all_checks: bool = True,
    user: str = "",
    password: str = "",
    ctf=None,
) -> str:
    """Run enum4linux for SMB/NetBIOS enumeration.

    Banca-safe: read-only NetBIOS/SMB enumeration (workgroups, users,
    shares, password policy). NO active exploitation. `-a` enables all
    safe checks by default.

    Args:
        target_host: target IP or hostname.
        all_checks: enable all safe checks (-a flag, default True).
        user: optional SMB username (empty = NULL session).
        password: optional SMB password.
        ctf: CTF context.

    Returns:
        str: enum4linux output (workgroup, users, shares, policy).
    """
    cmd_parts = ["enum4linux"]
    if all_checks:
        cmd_parts.append("-a")
    if user:
        cmd_parts.append(f"-u {user}")
    if password:
        cmd_parts.append(f"-p {password}")
    cmd_parts.append(target_host)
    return run_command(" ".join(cmd_parts), ctf=ctf)
