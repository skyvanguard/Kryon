"""audit_target — the engage-grade network pipeline as an agentic tool (gap #2).

Kryon's deterministic network audit (nmap discovery → per-service battery →
device-family compliance → skill hot-swap → dedup → ground-truth) lived in
``services/target_orchestrator.run_target_orchestration`` and was ONLY reachable
from the REPL's pre-agent router (`cli/_original.py`) or `kryon engage`. The
agent itself couldn't invoke it — so if the model, reasoning, discovered a new
host mid-conversation, it had no way to audit it.

This exposes that pipeline as a tool. Crucially it does NOT hand routing to the
model — the pipeline stays 100% deterministic; the agent only decides *when* to
run it. That respects Kryon's doctrine ("determinism routes, the model narrates")
while making the capability agentic for a model that reasons well (V4-Flash).

Banca-safe: the pipeline is read-only recon/compliance (nmap + deterministic
checks); it never exploits. SSH creds are optional and only used for host-level
compliance the operator explicitly authorizes.
"""

from __future__ import annotations

from typing import Any

from kryon.sdk.agents import function_tool


def _make_console() -> Any:
    """A silent console — the tool returns text, it doesn't print to a terminal."""
    try:
        from rich.console import Console

        return Console(quiet=True)
    except Exception:  # noqa: BLE001 — rich should be present; degrade gracefully

        class _Null:
            def __getattr__(self, _name: str):  # noqa: ANN204
                return lambda *a, **k: None

        return _Null()


def _audit_impl(
    target: str,
    discover: bool = True,
    include_dns: bool = False,
    include_smb: bool = False,
    ssh_user: str = "",
    ssh_password: str = "",
    ssh_key: str = "",
    max_services: int = 24,
) -> str:
    """Implementation, separated from the function_tool wrapper for tests."""
    if not target or not target.strip():
        return "ERROR: target is empty"

    try:
        from kryon.services.target_orchestrator import run_target_orchestration
    except ImportError as e:
        return f"ERROR: orchestrator unavailable: {e}"

    try:
        result = run_target_orchestration(
            target.strip(),
            console=_make_console(),
            discover=discover,
            include_dns=include_dns,
            include_smb=include_smb,
            ssh_user=ssh_user,
            ssh_password=ssh_password,
            ssh_key=ssh_key,
            max_services=max_services,
        )
    except Exception as e:  # noqa: BLE001 — orchestrator is guarded, but be defensive
        return f"ERROR during audit: {type(e).__name__}: {e}"

    # CIDR / unresolvable → the orchestrator returns a note explaining the path.
    if getattr(result, "note", ""):
        return result.note

    services = getattr(result, "services", []) or []
    families = getattr(result, "families", []) or []
    findings = getattr(result, "findings", []) or []
    ground_truth = getattr(result, "ground_truth", "") or ""

    fam_names = ", ".join(str(getattr(f, "name", f)) for f in families) if families else "—"
    lines = [
        f"# Auditoría de red — `{target}`",
        "",
        f"**Servicios**: {len(services)} "
        f"({'nmap corrió' if getattr(result, 'discovery_ran', False) else 'discovery omitido'}) · "
        f"**Familias**: {fam_names} · **Findings**: {len(findings)}",
        "",
    ]
    if ground_truth:
        lines.append(ground_truth)
    elif not findings:
        lines.append("_Sin findings deterministas — el agente puede seguir con enumeración manual._")
    return "\n".join(lines)


@function_tool(strict_mode=False)
def audit_target(
    target: str,
    discover: bool = True,
    include_dns: bool = False,
    include_smb: bool = False,
    ssh_user: str = "",
    ssh_password: str = "",
    ssh_key: str = "",
    max_services: int = 24,
) -> str:
    """Run Kryon's deterministic engage-grade network audit on a host or URL.

    Use this when the operator asks to audit / scan / assess a network target
    (an IP, hostname, or URL) — e.g. "auditá 10.0.0.5", "revisá este host",
    "corré un análisis contra example.com". It runs the full deterministic
    pipeline (nmap discovery → per-service checks → device-family compliance →
    dedup) and returns the ground-truth findings for you to narrate. Read-only
    recon/compliance — it never exploits.

    Args:
        target: A single host, IP, or URL. NOT a CIDR (segments go via discover→queue).
        discover: Run nmap discovery first (default True). False = check the raw target only.
        include_dns: Add DNS-zone/DNSSEC/reverse-DNS checks (opt-in).
        include_smb: Add anonymous-SMB checks (opt-in).
        ssh_user / ssh_password / ssh_key: Optional creds for host-level compliance
            checks the operator authorizes.
        max_services: Cap services put through the battery (default 24).

    Returns a markdown report: discovered services, device families, and the
    deterministic findings (ground truth).
    """
    return _audit_impl(target, discover, include_dns, include_smb, ssh_user, ssh_password, ssh_key, max_services)
