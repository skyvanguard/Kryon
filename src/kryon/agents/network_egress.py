"""Network egress cage — the defense-in-depth layer below the scope gate.

The scope gate (``scope_gate.py``) validates a tool's *declared* target by regex,
which a subprocess tool (nmap, nuclei) or an obfuscated target (decimal IP) can
slip. The network cage closes that at the OS level: an iptables egress lockdown,
generated from ``KRYON_SCOPE``, that DROPs all outbound traffic except to the
authorized targets (+ DNS, loopback, established flows, and the infra/LLM
network). Applied at container start, it caps EVERY process in the container —
the agent physically cannot route a packet to anything it isn't authorized for.

Generated here so it can be unit-tested and dry-run; applied by the operator /
entrypoint:

    KRYON_SCOPE=10.65.168.0/24 KRYON_INFRA_ALLOW=172.20.0.0/24 \
        python -m kryon.agents.network_egress apply

Domains in the scope are resolved to their current IPs at apply time (iptables is
IP-only). Re-run apply if a target's DNS changes — that residual is why the
software scope gate stays the primary, name-aware control.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import subprocess
import sys

logger = logging.getLogger(__name__)

# Always-allowed egress: loopback handled separately; DNS needed for resolution.
_DNS_PORT = "53"


def _resolve_to_cidr(entry: str) -> str | None:
    """Scope entry → an iptables -d value (CIDR/IP). URLs and domains are
    resolved to their current A record; unresolvable entries return None."""
    e = entry.strip()
    if not e:
        return None
    if e.lower().startswith(("http://", "https://")):
        from urllib.parse import urlparse

        e = urlparse(e).hostname or ""
    if not e:
        return None
    e = e.lstrip("*.")  # *.creative.thm → resolve creative.thm
    # already a CIDR or IP?
    try:
        ipaddress.ip_network(e, strict=False)
        return e
    except ValueError:
        pass
    try:
        info = socket.getaddrinfo(e, None, socket.AF_INET, socket.SOCK_STREAM)
        return info[0][4][0] if info else None
    except (socket.gaierror, OSError, ValueError):
        logger.warning("network egress: cannot resolve scope entry %r", e)
        return None


def build_iptables_commands(
    scope: list[str], deny: list[str], infra: list[str]
) -> list[list[str]]:
    """Build the egress-lockdown iptables ruleset as argv lists (idempotent-ish:
    flushes OUTPUT first). Order: flush → loopback → established → DNS → explicit
    deny (DROP) → infra+scope (ACCEPT) → default-policy DROP."""
    cmds: list[list[str]] = [
        ["iptables", "-F", "OUTPUT"],
        ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", _DNS_PORT, "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", _DNS_PORT, "-j", "ACCEPT"],
    ]
    # Explicit denies win — inserted before the allows.
    for d in deny:
        cidr = _resolve_to_cidr(d)
        if cidr:
            cmds.append(["iptables", "-A", "OUTPUT", "-d", cidr, "-j", "DROP"])
    # Infra (LLM / mgmt network) must stay reachable or the agent can't think.
    for i in infra:
        if i.strip():
            cmds.append(["iptables", "-A", "OUTPUT", "-d", i.strip(), "-j", "ACCEPT"])
    # Authorized targets.
    for s in scope:
        cidr = _resolve_to_cidr(s)
        if cidr:
            cmds.append(["iptables", "-A", "OUTPUT", "-d", cidr, "-j", "ACCEPT"])
    # Default deny everything else.
    cmds.append(["iptables", "-A", "OUTPUT", "-j", "DROP"])
    return cmds


def _scope_from_env() -> tuple[list[str], list[str], list[str]]:
    scope = [e.strip() for e in os.environ.get("KRYON_SCOPE", "").split(",") if e.strip()]
    deny = [e.strip() for e in os.environ.get("KRYON_SCOPE_DENY", "").split(",") if e.strip()]
    infra = [e.strip() for e in os.environ.get("KRYON_INFRA_ALLOW", "").split(",") if e.strip()]
    # Auto-allow the LLM endpoint host so the cage never starves the agent.
    base = os.environ.get("OPENAI_BASE_URL", "")
    if base:
        from urllib.parse import urlparse

        host = urlparse(base).hostname
        if host:
            cidr = _resolve_to_cidr(host)
            if cidr and cidr not in infra:
                infra.append(cidr)
    return scope, deny, infra


def apply_egress(dry_run: bool = False) -> tuple[bool, str]:
    """Apply the egress lockdown from env. Returns (applied, message). No-op (and
    not an error) when no scope is declared — the cage is opt-in."""
    scope, deny, infra = _scope_from_env()
    if not scope:
        return False, "no KRYON_SCOPE declared — egress cage skipped"
    cmds = build_iptables_commands(scope, deny, infra)
    if dry_run:
        return True, "\n".join(" ".join(c) for c in cmds)
    failures = []
    for c in cmds:
        try:
            subprocess.run(c, check=True, capture_output=True, timeout=10)
        except (subprocess.SubprocessError, OSError) as e:
            failures.append(f"{' '.join(c)} → {e}")
    if failures:
        return False, "egress cage PARTIAL/FAILED (need NET_ADMIN + iptables):\n" + "\n".join(failures)
    logger.info("network egress cage APPLIED: %d scope, %d deny, %d infra", len(scope), len(deny), len(infra))
    return True, f"egress cage applied: {len(cmds)} rules"


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    dry = "apply" not in args  # default to dry-run unless 'apply' is passed
    ok, msg = apply_egress(dry_run=dry)
    print(("[dry-run]\n" if dry else "") + msg)
    return 0 if ok or "skipped" in msg else 1


if __name__ == "__main__":
    raise SystemExit(main())
