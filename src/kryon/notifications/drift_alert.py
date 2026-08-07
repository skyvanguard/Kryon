"""Q2 — Drift alerting: notify when a re-audit surfaces NEW/CHANGED findings.

engage already diffs each run against the saved baseline (F133). This turns a
drift (something appeared or worsened since last time) into a notification via
the env-configured channel (Slack/email/stdout). Pure builder + a thin sender
so the alert text is testable without touching the network.
"""

from __future__ import annotations

from typing import Any

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _highest_severity(findings: list[dict]) -> str:
    best = "INFO"
    for f in findings:
        sev = str((f or {}).get("severity", "")).upper()
        if _SEV_RANK.get(sev, 99) < _SEV_RANK.get(best, 99):
            best = sev
    return best


def build_drift_alert(diff: Any, target: str, client: str = "") -> tuple[str, str]:
    """Return ``(subject, body)`` summarizing a baseline drift. Pure."""
    new = list(getattr(diff, "new", []) or [])
    gone = list(getattr(diff, "gone", []) or [])
    changed = list(getattr(diff, "changed", []) or [])
    worst = _highest_severity(new + [c.get("current", {}) for c in changed if isinstance(c, dict)])

    who = f"{client} · " if client else ""
    subject = f"[Kryon] Drift on {who}{target}: +{len(new)} new, ~{len(changed)} changed, -{len(gone)} resolved"

    lines = [
        f"Baseline drift detected on {target}" + (f" (client: {client})" if client else ""),
        "",
        f"  NEW:      {len(new)} (worst severity: {worst})",
        f"  CHANGED:  {len(changed)}",
        f"  RESOLVED: {len(gone)}",
    ]
    if new:
        lines.append("")
        lines.append("New findings:")
        for f in new[:10]:
            sev = str((f or {}).get("severity", "")).upper()
            msg = (f or {}).get("message") or (f or {}).get("rule_id") or "finding"
            host = (f or {}).get("host", "")
            lines.append(f"  - [{sev}] {msg}" + (f" @ {host}" if host else ""))
        if len(new) > 10:
            lines.append(f"  … and {len(new) - 10} more")
    return subject, "\n".join(lines)


def notify_drift(diff: Any, target: str, client: str = "", provider: Any = None):
    """Send a drift alert if the diff has NEW/CHANGED/GONE. Returns the
    NotificationResult, or None when there's nothing to report. Never raises."""
    has_changes = bool(getattr(diff, "has_changes", False))
    if not has_changes:
        return None
    try:
        if provider is None:
            from kryon.notifications.notify import default_provider_from_env

            provider = default_provider_from_env()
        subject, body = build_drift_alert(diff, target, client)
        return provider.send(subject=subject, body=body)
    except Exception:  # pragma: no cover — alerting must never break a run
        return None


def run_drift_check(
    previous_findings: list[Any] | None,
    current_findings: list[Any],
    *,
    baseline_existed: bool,
    notify_enabled: bool,
    target: str,
    client: str = "",
    provider: Any = None,
) -> tuple[Any, bool]:
    """R3 appliance warm-up — compute the baseline diff and alert on drift,
    staying silent on a first-ever run.

    Returns ``(diff, alerted)``:
      - First-ever run (``baseline_existed`` is False, i.e. no baseline file):
        returns ``(None, False)`` — no diff, no alert, so the operator's first
        night on a new target isn't an avalanche of "NEW" findings.
      - Baseline present: compute the diff. When ``notify_enabled`` and the
        diff carries real drift (NEW/CHANGED/GONE), fire the alert. A present
        but empty baseline (previous run was clean) correctly treats this
        run's findings as real drift.

    ``provider`` is injectable so the whole warm-up decision is testable
    without touching the network.
    """
    if not baseline_existed:
        return None, False
    from kryon.state.baseline_diff import compute_diff

    diff = compute_diff(previous_findings, current_findings)
    alerted = False
    if notify_enabled:
        res = notify_drift(diff, target, client=client, provider=provider)
        alerted = bool(res is not None and getattr(res, "ok", False))
    return diff, alerted
