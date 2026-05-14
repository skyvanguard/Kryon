"""F146 — Multi-tenancy: per-tenant namespacing + scope policy.

Goals:

  - Every artifact Kryon writes (audit, state, checkpoints, reports)
    can be namespaced by tenant so a single Kryon instance can serve
    multiple banks/clients without paths colliding.

  - A scope policy file (``.kryon/scope.json``) declares which
    targets each tenant is authorised to scan. Engagements outside
    scope are rejected at the CLI gate — this is the banca-safe
    "did the operator sign the auth letter?" check, codified.

Defaults are tenant-less so single-bank deployments don't need to do
anything new. Passing ``--tenant=<id>`` or setting ``KRYON_TENANT_ID``
turns on namespacing.

Scope policy file shape:

    {
      "tenants": {
        "britimp": {
          "allowed_targets": ["www.britimp.com.py", "cashbox.britimp.com.py", "172.18.200.0/24"],
          "blocked_targets": ["www.competitor.com"]
        },
        "bcp": {
          "allowed_targets": ["*.bcp.com.py"]
        }
      },
      "default_deny": true
    }

Matching is literal target OR glob (``*.bcp.com.py``) OR CIDR. When
``default_deny`` is true (recommended), any target NOT in the
allowed_targets list is rejected.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


_TENANT_SLUG_RE = re.compile(r"[^a-zA-Z0-9_-]+")


def _slug(value: str) -> str:
    """Filesystem-safe tenant slug."""
    return _TENANT_SLUG_RE.sub("_", (value or "").strip()).strip("_") or "default"


@dataclass(frozen=True)
class TenantContext:
    """Carries the active tenant through the engagement pipeline."""

    tenant_id: str

    @property
    def slug(self) -> str:
        return _slug(self.tenant_id)


@dataclass(frozen=True)
class ScopePolicy:
    """Resolved scope policy for one tenant."""

    tenant_id: str
    allowed_targets: tuple[str, ...] = field(default_factory=tuple)
    blocked_targets: tuple[str, ...] = field(default_factory=tuple)
    default_deny: bool = True


def _default_policy_path() -> Path:
    root = os.environ.get("KRYON_SCOPE_PATH", "").strip()
    if root:
        return Path(root)
    return Path(".kryon") / "scope.json"


def load_scope_policy(tenant_id: str, *, path: Path | None = None) -> ScopePolicy | None:
    """Read the policy file and pluck out the tenant's section.
    Returns ``None`` when the file is missing — caller decides
    whether that's allow-all (single-tenant dev) or deny-all (prod)."""
    p = path or _default_policy_path()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    tenants = data.get("tenants", {}) if isinstance(data, dict) else {}
    tenant_block = tenants.get(tenant_id, {}) if isinstance(tenants, dict) else {}
    if not isinstance(tenant_block, dict):
        tenant_block = {}
    return ScopePolicy(
        tenant_id=tenant_id,
        allowed_targets=tuple(tenant_block.get("allowed_targets", []) or []),
        blocked_targets=tuple(tenant_block.get("blocked_targets", []) or []),
        default_deny=bool(data.get("default_deny", True)),
    )


def _target_matches(pattern: str, target: str) -> bool:
    """Match ``target`` against ``pattern``. Supports literal equality,
    fnmatch glob (``*.x.com``), and CIDR (``10.0.0.0/24``)."""
    if not pattern or not target:
        return False
    if pattern == target:
        return True
    if "/" in pattern:
        # CIDR
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            addr = ipaddress.ip_address(target)
            return addr in net
        except (ValueError, ipaddress.AddressValueError):
            return False
    if any(ch in pattern for ch in ("*", "?", "[")):
        return fnmatch.fnmatchcase(target, pattern)
    return False


def is_target_in_scope(target: str, policy: ScopePolicy | None) -> tuple[bool, str]:
    """Apply the policy. Returns ``(allowed, reason)``.

    Semantics:
      - No policy at all (``policy is None``) → allowed (single-
        tenant dev mode). Caller decides whether to enforce.
      - Target on blocked list → denied (blocklist wins).
      - Target on allowed list → allowed.
      - Otherwise: ``default_deny`` flips the verdict.
    """
    if policy is None:
        return True, "no scope policy (single-tenant mode)"
    for blocked in policy.blocked_targets:
        if _target_matches(blocked, target):
            return False, f"blocked by '{blocked}'"
    for allowed in policy.allowed_targets:
        if _target_matches(allowed, target):
            return True, f"matched allow pattern '{allowed}'"
    if policy.default_deny:
        return False, "not in allowed_targets and default_deny=true"
    return True, "not in allowed_targets but default_deny=false (allow-by-default)"


def namespaced_engagement_id(engagement_id: str, *, tenant: TenantContext | None) -> str:
    """Prefix the engagement_id with the tenant slug so per-tenant
    audit / state / report paths don't collide.

    ``namespaced_engagement_id("eng-1", tenant=britimp) → "britimp/eng-1"``"""
    if tenant is None or not tenant.tenant_id:
        return engagement_id
    return f"{tenant.slug}/{engagement_id}"


def namespaced_path(base: Path, *, tenant: TenantContext | None) -> Path:
    """Insert the tenant slug between the base dir and its contents.
    Used to namespace ``.kryon/audit/<tenant>/...``,
    ``.kryon/state/<tenant>/...``, etc."""
    if tenant is None or not tenant.tenant_id:
        return base
    return base / tenant.slug
