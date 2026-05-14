"""F139 — Asset discovery.

Three discovery surfaces, each independent and disabled-by-default at
the CLI level:

  - **Subnet sweep**: nmap -sn against a CIDR / IP range to enumerate
    live hosts. The host script that runs is intentionally minimal —
    we only care about "is this IP responding". Deeper fingerprinting
    happens in ``kryon engage``.

  - **DNS subdomain enumeration**: crt.sh Certificate Transparency
    lookup for a registered domain. Returns the union of certificate
    SAN entries. No active DNS brute-forcing (passive only).

  - **Cloud asset inventory** (stub): hook for AWS/GCP/Azure asset
    listing. Returns ``[]`` by default — wire in per-tenant via
    ``kryon.discovery.cloud`` adapters when credentials are present.

All three feed into the same ``DiscoveryReport`` so the CLI emits one
JSON file per run that ``kryon queue add`` can consume.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
import socket
import subprocess
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DiscoveredAsset:
    """A single discovered target. ``kind`` distinguishes network host
    vs subdomain vs cloud resource so downstream queue/scheduler can
    route appropriately."""

    target: str  # IP, hostname, ARN, etc.
    kind: str  # "host" | "subdomain" | "cloud"
    source: str  # "nmap" | "crt.sh" | "aws-route53" | ...
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DiscoveryReport:
    assets: list[DiscoveredAsset] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"assets": [a.to_dict() for a in self.assets], "count": len(self.assets)}

    def to_targets(self) -> list[str]:
        """Deduped flat list of targets, ready to feed to ``kryon queue``."""
        seen: set[str] = set()
        out: list[str] = []
        for a in self.assets:
            if a.target not in seen:
                seen.add(a.target)
                out.append(a.target)
        return out


# ---------------------------------------------------------------------------
# Subnet sweep
# ---------------------------------------------------------------------------


_NMAP_HOST_RE = re.compile(r"Nmap scan report for ([^\s]+)(?:\s+\(([\d.]+)\))?")


def discover_subnet(cidr: str, *, timeout_s: int = 60) -> list[DiscoveredAsset]:
    """Run ``nmap -sn`` against ``cidr`` and parse hosts. Returns an
    empty list when nmap is unavailable or the scan times out — never
    raises so the CLI can fall back to subdomain-only mode."""
    cmd = f"nmap -sn -T4 {shlex.quote(cidr)}"
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout_s, check=False)
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("nmap subnet sweep failed: %s", exc)
        return []
    out: list[DiscoveredAsset] = []
    for line in (proc.stdout or "").splitlines():
        m = _NMAP_HOST_RE.search(line)
        if not m:
            continue
        host = m.group(1)
        ip = m.group(2) or host
        # Skip the literal "for cidr" header lines.
        if "/" in host:
            continue
        out.append(
            DiscoveredAsset(
                target=ip,
                kind="host",
                source="nmap",
                extra={"hostname": host if host != ip else ""},
            )
        )
    return out


# ---------------------------------------------------------------------------
# DNS subdomain enumeration (crt.sh)
# ---------------------------------------------------------------------------


def discover_subdomains(domain: str, *, timeout_s: int = 15) -> list[DiscoveredAsset]:
    """Passive subdomain enum via crt.sh JSON. Returns deduped subdomains.

    crt.sh is best-effort; banking-safe by design (passive, no active
    DNS queries against the target). Returns ``[]`` on network error
    or non-200 responses so callers don't crash."""
    if not domain:
        return []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "kryon/discovery"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            if resp.status != 200:
                return []
            data = json.loads(resp.read().decode("utf-8", errors="replace") or "[]")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError) as exc:
        logger.warning("crt.sh subdomain enum failed: %s", exc)
        return []

    seen: set[str] = set()
    out: list[DiscoveredAsset] = []
    for entry in data if isinstance(data, list) else []:
        name_value = entry.get("name_value") if isinstance(entry, dict) else None
        if not name_value:
            continue
        for sub in str(name_value).split("\n"):
            sub = sub.strip().lower()
            # Skip wildcards and empties.
            if not sub or sub.startswith("*."):
                continue
            if sub in seen:
                continue
            seen.add(sub)
            out.append(
                DiscoveredAsset(
                    target=sub,
                    kind="subdomain",
                    source="crt.sh",
                )
            )
    return out


# ---------------------------------------------------------------------------
# Cloud assets (stub)
# ---------------------------------------------------------------------------


def discover_cloud_assets(provider: str = "") -> list[DiscoveredAsset]:
    """Stub for cloud asset inventory. Returns ``[]`` until a real
    AWS/GCP/Azure adapter is wired. The signature is fixed so the CLI
    can wire it now without churning later."""
    return []


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------


def merge_assets(*lists: list[DiscoveredAsset]) -> DiscoveryReport:
    """Concatenate multiple discovery lists into a single deduped report."""
    report = DiscoveryReport()
    seen: set[tuple[str, str]] = set()
    for batch in lists:
        for asset in batch:
            key = (asset.target, asset.kind)
            if key in seen:
                continue
            seen.add(key)
            report.assets.append(asset)
    return report


# ---------------------------------------------------------------------------
# Helpers for tests / CLI
# ---------------------------------------------------------------------------


def is_valid_target(target: str) -> bool:
    """Quick validity check used by the CLI. Accepts IP, CIDR, or DNS-y
    hostname. Rejects obviously malformed strings."""
    if not target:
        return False
    if "/" in target:
        # CIDR
        try:
            base, mask = target.split("/", 1)
            socket.inet_aton(base)
            return 0 <= int(mask) <= 32
        except (ValueError, OSError):
            return False
    try:
        socket.inet_aton(target)
        return True
    except OSError:
        pass
    # Hostname: at least one dot, no whitespace.
    return "." in target and not any(c.isspace() for c in target)
