"""run_network_pivot — autonomous multi-stage network pivot as a tool.

``orchestrator.autonomous_network_pivot`` establishes a foothold, discovers
internal networks, tunnels, and moves laterally toward an objective. It was only
reachable as a bare function. This exposes it to the agent.

Lateral movement is intrusive and can reach hosts NOT in the original scope, so
it is DOUBLE-gated (same contract as run_autonomous_pentest):
  1. Registered only under KRYON_RED_TEAM=true (authorized pentest).
  2. Executes only under KRYON_AUTOSCAN_FIRE=true.
Both require written authorization. Without the fire env it returns a note and
pivots nothing. Prefer per-host audit_target / autonomous_ctf_solver unless a
full autonomous pivot is truly what the operator authorized.
"""

from __future__ import annotations

import os
from typing import Any

from kryon.sdk.agents import function_tool


def _fire_on() -> bool:
    return os.environ.get("KRYON_AUTOSCAN_FIRE", "").strip().lower() in ("1", "true", "yes", "on")


def _fmt(result: dict[str, Any]) -> str:
    chain = result.get("pivot_chain", []) or []
    comp = result.get("compromised_hosts", []) or []
    lines = [
        "# Autonomous network pivot",
        "",
        f"**Objetivo logrado**: {result.get('objective_achieved', False)} · "
        f"**Acceso final**: {result.get('final_access_level', 'none')}",
        f"**Cadena de pivot**: {' → '.join(str(h) for h in chain) if chain else '(ninguna)'}",
        f"**Hosts comprometidos**: {len(comp)} · **Túneles**: {len(result.get('tunnels_created', []) or [])}",
    ]
    if result.get("error"):
        lines.append(f"**Error**: {result['error']}")
    return "\n".join(lines)


def _network_pivot_impl(
    entry_point_ip: str,
    username: str = "",
    password: str = "",
    ssh_key: str = "",
    internal_network: str = "auto",
    max_depth: int = 3,
    objective: str = "domain_admin",
) -> str:
    """Implementation, separated from the function_tool wrapper for tests."""
    if not entry_point_ip or not entry_point_ip.strip():
        return "ERROR: entry_point_ip is empty"
    if not _fire_on():
        return (
            "Network pivot is OFF. It moves laterally and can reach out-of-scope "
            "hosts, so it needs KRYON_AUTOSCAN_FIRE=true AND written authorization. "
            "For a single host prefer audit_target or autonomous_ctf_solver."
        )

    creds: dict[str, str] = {"username": username}
    if password:
        creds["password"] = password
    if ssh_key:
        creds["ssh_key"] = ssh_key

    try:
        from kryon.tools.autonomous.orchestrator import autonomous_network_pivot

        result = autonomous_network_pivot(
            entry_point_ip=entry_point_ip.strip(),
            entry_credentials=creds,
            internal_network=internal_network,
            max_depth=max_depth,
            objective=objective,
        )
    except Exception as e:  # noqa: BLE001 — surface to the model, don't crash the turn
        return f"ERROR during network pivot: {type(e).__name__}: {e}"

    if not isinstance(result, dict):
        return "ERROR: pivot returned an unexpected result"
    return _fmt(result)


@function_tool(strict_mode=False)
def run_network_pivot(
    entry_point_ip: str,
    username: str,
    password: str = "",
    ssh_key: str = "",
    internal_network: str = "auto",
    max_depth: int = 3,
    objective: str = "domain_admin",
) -> str:
    """Launch an AUTONOMOUS multi-stage network pivot from a compromised host.

    Establishes a foothold on ``entry_point_ip`` with the given credentials,
    discovers internal networks, tunnels, and moves laterally toward
    ``objective``. This ACTIVELY EXPLOITS internal hosts and can reach targets
    NOT in the original scope — use ONLY with written authorization. Requires
    KRYON_AUTOSCAN_FIRE=true. For a single host prefer audit_target.

    Args:
        entry_point_ip: Already-compromised entry host to pivot from.
        username: SSH username for the entry host.
        password: SSH password (or leave empty and pass ssh_key).
        ssh_key: Path to an SSH private key (alternative to password).
        internal_network: Target internal CIDR, or "auto" to discover.
        max_depth: Maximum pivot hops (default 3).
        objective: "domain_admin" | "data_exfil" | "persistence".

    Returns a markdown summary: pivot chain, compromised hosts, objective status.
    """
    return _network_pivot_impl(
        entry_point_ip, username, password, ssh_key, internal_network, max_depth, objective
    )
