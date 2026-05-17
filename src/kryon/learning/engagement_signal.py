"""F194 — Engagement → learning signal wire.

F193 confirmed the synthesizer (``synthesize_draft`` +
``try_synthesize_and_persist``) works atomically but
``auto_extract_on_exit`` only fires from the REPL — engage runs
finish without ever invoking it. Result: 25+ benches, zero drafts.

This module bridges the gap. ``emit_engagement_learning_signal`` is
called at the end of ``_invoke_orchestrated_engagement`` and:

1. Maps the engagement verdict (``SATISFIED``/``PARTIAL``/``NOT_MET``)
   to the synthesizer's outcome label (``success``/``partial``/
   ``recon-only``/``fail``).
2. Reads the audit JSONL log to reconstruct the chain of tool calls
   (the synthesizer's quality bar is ``chain_len >= 2``).
3. Serializes findings + family detection into the experience dict
   shape ``synthesize_draft`` expects.
4. Calls ``try_synthesize_and_persist``.

The function is best-effort: ANY exception is caught and logged at
debug level so a learning side-effect can never crash an
engagement. Returns the path of the generated draft (or ``None``).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# Map engage's verdict.value strings → synthesizer outcome labels.
# Both use case-insensitive matching at the call site.
_VERDICT_TO_OUTCOME = {
    "satisfied": "success",
    "partial": "partial",
    "not_met": "recon-only",
    # Other verdicts (error / timeout / etc.) collapse to fail and
    # get filtered by the synthesizer's _DEFAULT_MIN_OUTCOME=partial.
}


def _map_verdict_to_outcome(verdict: str | None) -> str:
    if not isinstance(verdict, str) or not verdict:
        return "fail"
    return _VERDICT_TO_OUTCOME.get(verdict.lower().strip(), "fail")


def _serialize_finding(f: Any) -> dict:
    """Reduce a Finding object or dict to the schema the synthesizer
    body builder expects."""
    if isinstance(f, dict):
        msg = str(f.get("message", "") or "")[:200]
        return {
            "cwe": str(f.get("cwe", "") or ""),
            "severity": str(f.get("severity", "") or ""),
            "rule_id": str(f.get("rule_id", "") or ""),
            "message": msg,
        }
    msg = str(getattr(f, "message", "") or "")[:200]
    return {
        "cwe": str(getattr(f, "cwe", "") or ""),
        "severity": str(getattr(f, "severity", "") or ""),
        "rule_id": str(getattr(f, "rule_id", "") or ""),
        "message": msg,
    }


def _read_audit_chain(audit_log_path: Path | str | None) -> list[dict]:
    """Parse the engagement's audit JSONL into the chain shape the
    synthesizer wants: ``[{tool, args, outcome}, ...]``.

    Each line in the audit log is a JSON dict with at least
    ``tool_name`` + ``args_redacted`` + ``status``. We pass
    ``args_redacted`` through (PAN/credentials already stripped by
    F119 — that's exactly what we want in a reusable draft).
    """
    if audit_log_path is None:
        return []
    path = Path(audit_log_path)
    if not path.exists():
        return []

    chain: list[dict] = []
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            tool = doc.get("tool_name") or ""
            if not tool:
                continue
            # Skip orchestrator-internal events (circuit_breaker_trip,
            # phase_run, etc.) — synthesizer wants actual tool calls.
            if tool in {"phase_run", "phase_run_retry", "circuit_breaker_trip", "audit_summary"}:
                continue
            args_str = str(doc.get("args_redacted") or doc.get("args") or "")[:500]
            status = doc.get("status") or "ok"
            chain.append({"tool": tool, "args": args_str, "outcome": status})
    except OSError as exc:
        logger.debug("F194 audit read failed: %s", exc)
        return []
    return chain


def emit_engagement_learning_signal(
    *,
    target: str | None,
    verdict_info: dict | None,
    findings: list | None,
    families: list[str] | None,
    audit_log_path: Path | str | None,
    engagement_id: str | None = "",
    objective: str = "",
) -> str | None:
    """Build the experience dict and trigger draft synthesis.

    Returns the path string of the generated draft, or ``None`` if
    the engagement didn't qualify (fail outcome, thin chain, etc.).

    NEVER raises. Best-effort: a logging side-effect must never crash
    an engagement.
    """
    try:
        outcome = _map_verdict_to_outcome((verdict_info or {}).get("verdict"))
        # Synthesizer's _DEFAULT_MIN_OUTCOME is "partial" — fail won't
        # qualify, so skip the IO entirely for known-fail engagements.
        if outcome == "fail":
            return None

        chain = _read_audit_chain(audit_log_path)
        if len(chain) < 2:
            return None

        experience = {
            "id": engagement_id or "engage-anon",
            "outcome": outcome,
            "host": target or "",
            "target": target or "",
            "target_profile": {
                "tech": list(families or []),
                "ports": [],
            },
            "objective": (verdict_info or {}).get("goal_raw") or objective,
            "chain": chain,
            "findings": [_serialize_finding(f) for f in (findings or [])],
            "summary": (verdict_info or {}).get("reasoning") or f"Engagement outcome: {outcome}",
            "tags": [],
        }

        from kryon.learning.draft_writer import try_synthesize_and_persist

        draft_path = try_synthesize_and_persist(experience)
        if draft_path is None:
            return None
        return str(draft_path)
    except Exception as exc:  # noqa: BLE001 — best-effort wire, never raise
        logger.debug("F194 emit_engagement_learning_signal failed: %s", exc)
        return None
