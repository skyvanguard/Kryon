"""@function_tool request_approval — the agent asks the operator before
applying changes to client infrastructure (F12.6).

Used inside `server-hardening` Fase 2 and any playbook that modifies
remote state. The agent builds a list of proposed actions (severity,
purpose, command, reversibility) and calls this tool. The rich
approval UI (F12.1) renders the bundle, captures the operator's
y/N/d/a, and returns a structured verdict the agent can branch on.

Safety invariants:
  - Default answer on Enter is NO. Silent confirmation on destructive
    actions is the failure mode we prevent — keep it that way.
  - Ctrl+C is ABORT, never a silent accept.
  - When running in a non-interactive context (agent loop without TTY,
    e.g. CI or KRYON_AUTO_APPROVE=false), the tool returns "no" without
    rendering — the agent sees an explicit rejection and the engagement
    stops safely.
  - KRYON_AUTO_APPROVE=true (demo automation) skips the prompt and
    returns "yes". Only use in controlled environments (lab, CI with
    known-benign fixtures). NEVER document this to end users.
"""

from __future__ import annotations

import json
import logging
import os
import sys

from kryon.sdk.agents import function_tool

logger = logging.getLogger(__name__)


_SEV_ALIAS = {
    "crit": "destructive",
    "critical": "destructive",
    "destructive": "destructive",
    "destroy": "destructive",
    "high": "modify",
    "modify": "modify",
    "write": "modify",
    "mod": "modify",
    "medium": "modify",
    "read": "read",
    "ro": "read",
    "info": "read",
    "neutral": "neutral",
    "low": "neutral",
}


def _normalise_severity(raw: str) -> str:
    return _SEV_ALIAS.get((raw or "modify").strip().lower(), "modify")


def _is_auto_approve() -> bool:
    return os.environ.get("KRYON_AUTO_APPROVE", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _is_interactive() -> bool:
    """True only if we can actually prompt the operator."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def _format_decline(reason: str) -> str:
    return json.dumps({"verdict": "no", "reason": reason})


@function_tool(strict_mode=False)
def request_approval(
    title: str,
    actions: list[dict],
    subtitle: str = "",
    dry_run: bool = False,
    impact_notes: list[str] | None = None,
) -> str:
    """Ask the operator before applying a bundle of proposed actions.

    Intended for playbook Fase 2 (Propuesta) in server-hardening and any
    flow that modifies remote infrastructure. The agent emits a list of
    actions; this tool shows them in the rich approval UI (F12.1) and
    returns the operator's verdict.

    Args:
        title: One-line description of the bundle. Example:
            "Aplicar 3 correcciones CRITICAL en 192.168.1.10".
        actions: List of dicts, each with:
            - command (str): the exact shell command, shown verbatim.
            - purpose (str, optional): human-readable one-liner.
            - severity (str): destructive | modify | read | neutral.
              Synonyms accepted (critical, high, medium, low, info).
            - reversible (bool, optional): default False.
            - backup_path (str, optional): where the pre-change backup lives.
            - target_host (str, optional): user@host the command runs against.
        subtitle: Second-line context shown under the title (engagement
            id, host list, playbook name).
        dry_run: If True, the UI shows a [DRY-RUN] banner and makes clear
            the actions WILL NOT execute — used for previewing.
        impact_notes: Free-form bullets the operator sees under the
            action table (rollback policy, affected services, SLA).

    Returns:
        JSON string with `{"verdict": "yes"|"no"|"abort", "reason": str,
        "n_actions": int}`. Non-interactive contexts always return "no"
        unless KRYON_AUTO_APPROVE is truthy (demo automation only).
    """
    n = len(actions or [])
    notes = impact_notes or []

    # Non-interactive short-circuit — never try to render rich.prompt in
    # a pipe / headless agent loop. Return an explicit "no" so the agent
    # stops safely.
    if not _is_interactive() and not _is_auto_approve():
        return _format_decline(
            "non-interactive context; operator approval required. "
            "Set KRYON_AUTO_APPROVE=true only in controlled demo runs."
        )

    if _is_auto_approve():
        logger.warning(
            "KRYON_AUTO_APPROVE bypass engaged for %d actions (%s)",
            n,
            title,
        )
        return json.dumps(
            {
                "verdict": "yes",
                "reason": "KRYON_AUTO_APPROVE=true (demo mode)",
                "n_actions": n,
            }
        )

    try:
        from kryon.repl.ui.approval import (
            ApprovalRequest,
            ApprovalResult,
            ProposedAction,
            Severity,
            ask_approval,
        )
    except ImportError as exc:  # rich or ui module missing
        logger.error("approval UI unavailable: %s", exc)
        return _format_decline(f"approval UI unavailable: {exc}")

    severity_map = {
        "destructive": Severity.DESTRUCTIVE,
        "modify": Severity.MODIFY,
        "read": Severity.READ,
        "neutral": Severity.NEUTRAL,
    }

    built: list[ProposedAction] = []
    for a in actions or []:
        if not isinstance(a, dict) or not a.get("command"):
            continue
        built.append(
            ProposedAction(
                command=str(a.get("command", "")),
                purpose=str(a.get("purpose", "")),
                severity=severity_map[_normalise_severity(str(a.get("severity", "modify")))],
                reversible=bool(a.get("reversible", False)),
                backup_path=a.get("backup_path") or None,
                target_host=str(a.get("target_host", "")),
            )
        )

    if not built:
        return _format_decline("no actions supplied")

    req = ApprovalRequest(
        title=title,
        subtitle=subtitle,
        actions=built,
        impact_notes=[str(x) for x in notes if x],
        dry_run=bool(dry_run),
    )

    try:
        result = ask_approval(req, default=ApprovalResult.NO)
    except Exception as exc:  # noqa: BLE001 — UI error shouldn't hang the agent
        logger.exception("approval UI raised")
        return _format_decline(f"UI error: {exc}")

    return json.dumps(
        {
            "verdict": result.value,
            "reason": "",
            "n_actions": n,
        }
    )
