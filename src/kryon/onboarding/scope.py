"""F2.3 — Formal engagement scope.

A real audit starts from a signed scope: which IP ranges are in, which are
explicitly excluded, which systems, and who authorized it. This produces a
``scope.json`` with an integrity hash (of the scope definition, independent of
the timestamp) that the report embeds, and an ``is_in_scope`` check so the
sweep can refuse out-of-scope hosts.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class EngagementScope:
    client: str
    ip_ranges: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    systems: str = ""
    authorized_by: str = ""
    notes: str = ""
    created_utc: str = ""
    scope_hash: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ip_ranges"] = list(self.ip_ranges)
        d["exclude"] = list(self.exclude)
        return d


def _scope_hash(client: str, ip_ranges, exclude, systems: str, authorized_by: str, notes: str) -> str:
    """Integrity hash of the scope DEFINITION (excludes the timestamp, so the
    same scope hashes identically run to run)."""
    payload = json.dumps(
        {
            "client": client,
            "ip_ranges": sorted(ip_ranges),
            "exclude": sorted(exclude),
            "systems": systems,
            "authorized_by": authorized_by,
            "notes": notes,
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def create_scope(
    client: str,
    ip_ranges,
    *,
    exclude=(),
    systems: str = "",
    authorized_by: str = "",
    notes: str = "",
    created_utc: str = "",
) -> EngagementScope:
    """Build a scope with its integrity hash. ``created_utc`` is passed in (not
    generated here) so callers control reproducibility."""
    ip_ranges = tuple(ip_ranges)
    exclude = tuple(exclude)
    return EngagementScope(
        client=client,
        ip_ranges=ip_ranges,
        exclude=exclude,
        systems=systems,
        authorized_by=authorized_by,
        notes=notes,
        created_utc=created_utc,
        scope_hash=_scope_hash(client, ip_ranges, exclude, systems, authorized_by, notes),
    )


def _matches(ip: str, entry: str) -> bool:
    """True if ``ip`` is inside ``entry`` (single IP or CIDR)."""
    try:
        addr = ipaddress.ip_address(ip.strip())
        net = ipaddress.ip_network(entry.strip(), strict=False)
    except ValueError:
        # Non-IP entries (hostnames) — fall back to exact match.
        return ip.strip() == entry.strip()
    return addr in net


def is_in_scope(scope: EngagementScope, ip: str) -> bool:
    """In-scope = inside any ip_range AND not inside any exclude."""
    if any(_matches(ip, ex) for ex in scope.exclude):
        return False
    return any(_matches(ip, rng) for rng in scope.ip_ranges)


def save_scope(scope: EngagementScope, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(scope.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def load_scope(path: Path) -> EngagementScope:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return EngagementScope(
        client=data.get("client", ""),
        ip_ranges=tuple(data.get("ip_ranges", [])),
        exclude=tuple(data.get("exclude", [])),
        systems=data.get("systems", ""),
        authorized_by=data.get("authorized_by", ""),
        notes=data.get("notes", ""),
        created_utc=data.get("created_utc", ""),
        scope_hash=data.get("scope_hash", ""),
    )


def verify_scope(scope: EngagementScope) -> bool:
    """True if the stored hash matches the current definition (untampered)."""
    expected = _scope_hash(
        scope.client, scope.ip_ranges, scope.exclude, scope.systems, scope.authorized_by, scope.notes
    )
    return scope.scope_hash == expected
