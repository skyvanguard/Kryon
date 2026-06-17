"""Deterministic web content enumeration — directories + vhosts/subdomains.

Kryon's hybrid phase runs *vulnerability* detectors before the LLM, but leaves
*content* enumeration (directories, vhosts, subdomains) to the agent, which must
pick the right tool + wordlist itself. That is exactly the step weak local
models stall on (observed live: a model discovered a vhost but enumerated
subdomains with a *directory* wordlist and never found the target subdomain,
then looped). This module runs ``ffuf`` deterministically with the CORRECT
wordlists + auto-calibration and returns the discovered surface, so it can be
injected as ground truth — the LLM no longer has to choose.

Design mirrors ``intelligence.source_review``: command building and JSON parsing
are PURE/testable; the only impure piece is the injected ``runner`` (subprocess).
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlparse

# Correct wordlists per phase (the whole point — the LLM kept picking wrong ones).
# COST GUARD: default to common.txt (~4.7k) — raft-medium (~30k) made the dir-enum
# take ~6min against a slow target before the LLM emitted a token, burning the wall
# budget. raft-medium is opt-in via KRYON_WEBENUM_DEEP=true for a thorough sweep.
DEFAULT_DIR_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"
DEEP_DIR_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
DEFAULT_VHOST_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
# Used if the seclists path is missing (older images).
FALLBACK_DIR_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

# ffuf's own default match set, minus the noisy 500s. -ac handles false positives.
_DIR_MATCH_CODES = "200,204,301,302,307,308,401,403,405"

# A runner takes (command, timeout_seconds) and returns the process stdout.
Runner = Callable[[str, int], str]


@dataclass(frozen=True)
class WebDiscovery:
    """One enumerated item — a directory/file or a virtual host."""

    kind: str  # "dir" | "vhost"
    value: str  # path (e.g. "admin") or hostname (e.g. "beta.creative.thm")
    status: int
    size: int


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def build_ffuf_dir_cmd(
    url: str,
    wordlist: str = DEFAULT_DIR_WORDLIST,
    *,
    host_header: str | None = None,
    match_codes: str = _DIR_MATCH_CODES,
    threads: int = 40,
) -> str:
    """ffuf directory discovery command. ``-ac`` auto-calibrates (filters the
    site's default/404 response), ``-json`` emits newline-delimited records.

    ``host_header`` sends ``-H "Host: <vhost>"`` so a bare-IP target that
    redirects to a vhost is fuzzed for its REAL content (not the 301), without
    needing the vhost in /etc/hosts.
    """
    base = url.rstrip("/")
    cmd = f"ffuf -u {base}/FUZZ -w {wordlist} -ac -mc {match_codes} -t {threads} -json -s"
    if host_header:
        cmd += f' -H "Host: {host_header}"'
    return cmd


def build_ffuf_vhost_cmd(
    base_url: str,
    domain: str,
    wordlist: str = DEFAULT_VHOST_WORDLIST,
    *,
    threads: int = 40,
) -> str:
    """ffuf vhost discovery via the Host header (``FUZZ.<domain>``). ``-ac``
    filters the baseline vhost response so only *real* vhosts come back — this is
    why a directory wordlist (or no calibration) fails to find subdomains."""
    base = base_url.rstrip("/")
    return f'ffuf -u {base}/ -H "Host: FUZZ.{domain}" -w {wordlist} -ac -t {threads} -json -s'


def parse_ffuf_json(output: str, *, kind: str, domain: str = "") -> list[WebDiscovery]:
    """Parse ffuf ``-json`` newline-delimited records into WebDiscovery objects.

    ffuf base64-encodes the FUZZ value in ``input.FUZZ``; we decode it. For vhost
    results the discovered hostname is ``<fuzz>.<domain>``.
    """
    out: list[WebDiscovery] = []
    seen: set[str] = set()
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        fuzz_b64 = (rec.get("input") or {}).get("FUZZ", "")
        if not fuzz_b64:
            continue
        try:
            fuzz = base64.b64decode(fuzz_b64).decode("utf-8", errors="replace").strip()
        except (ValueError, TypeError):
            continue
        if not fuzz:
            continue
        value = f"{fuzz}.{domain}" if kind == "vhost" and domain else fuzz
        if value in seen:
            continue
        seen.add(value)
        out.append(
            WebDiscovery(
                kind=kind,
                value=value,
                status=int(rec.get("status", 0) or 0),
                size=int(rec.get("length", 0) or 0),
            )
        )
    return out


def run_web_enum(
    url: str,
    *,
    runner: Runner,
    vhost_domain: str | None = None,
    dir_wordlist: str | None = None,
    vhost_wordlist: str = DEFAULT_VHOST_WORDLIST,
    timeout: int = 180,
    enable_vhost: bool = True,
) -> list[WebDiscovery]:
    """Run directory + vhost enumeration deterministically.

    ``vhost_domain`` is the base domain for Host-header fuzzing (e.g. the vhost a
    301 redirect revealed). When omitted it falls back to the URL host if that is
    a hostname (not an IP). ``runner`` executes a shell command and returns
    stdout (injected for tests).
    """
    # Resolve the dir wordlist: fast common.txt by default, raft-medium only when
    # the operator opts into a deep sweep (KRYON_WEBENUM_DEEP=true).
    if dir_wordlist is None:
        _deep = os.environ.get("KRYON_WEBENUM_DEEP", "").strip().lower() in ("1", "true", "yes")
        dir_wordlist = DEEP_DIR_WORDLIST if _deep else DEFAULT_DIR_WORDLIST

    discoveries: list[WebDiscovery] = []
    parsed = urlparse(url)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "http"
    base = f"{scheme}://{host}"

    # Effective web domain for Host-header fuzzing: an explicit vhost (e.g. the
    # one a 301 revealed) or the target's own hostname if it isn't a bare IP.
    domain = vhost_domain or (host if (host and "." in host and not _is_ip(host)) else "")

    # 1) Directory discovery. If the vhost differs from the request host (bare-IP
    #    target with a redirect), fuzz the IP WITH the Host header so we hit the
    #    real content instead of the 301 — no /etc/hosts needed.
    dir_host_header = domain if (domain and domain != host) else None
    try:
        dir_out = runner(build_ffuf_dir_cmd(base, dir_wordlist, host_header=dir_host_header), timeout)
        discoveries.extend(parse_ffuf_json(dir_out, kind="dir"))
    except Exception:  # noqa: BLE001 — enumeration must never break the run
        pass

    # 2) Vhost/subdomain discovery (Host header against the IP/host).
    if enable_vhost and domain:
        try:
            vhost_out = runner(build_ffuf_vhost_cmd(base, domain, vhost_wordlist), timeout)
            discoveries.extend(parse_ffuf_json(vhost_out, kind="vhost", domain=domain))
        except Exception:  # noqa: BLE001
            pass

    return discoveries
