"""Adapter — engage.Finding → SIEMEvent, plus the cron-path dispatch.

This is the missing wire between the finding pipeline and the SIEM
forwarder framework. Before this, ``forward_event`` was only ever called
from the server's audit middleware (one ``audit`` event per HTTP request)
— a ``kryon engage`` run produced findings but never forwarded them.

``emit_findings_to_siem`` is best-effort and banca-safe by default:
  - No-op unless a SIEM is configured (env ``KRYON_SIEM_TYPE`` or a
    server store config). Returns 0 and never raises.
  - Evidence is OMITTED by default (it can carry PAN/secret fragments,
    same stance as the SARIF exporter). Opt in with
    ``KRYON_SIEM_INCLUDE_EVIDENCE=true`` (redacted when the pan_redactor
    is available).
  - ``delta`` (new|changed|existing) is derived from the baseline diff so
    the SIEM can alert only on what changed since the last cron run.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from kryon.integrations.models import SIEMEvent

logger = logging.getLogger(__name__)

# engage uses UPPER-case severities; SIEMEvent/ECS use lower-case.
_SEV_LOWER = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
}


def _include_evidence() -> bool:
    return os.environ.get("KRYON_SIEM_INCLUDE_EVIDENCE", "").strip().lower() in {"1", "true", "yes", "on"}


def _redact(text: str) -> str:
    try:
        from kryon.redaction.pan_redactor import redact_sensitive

        return redact_sensitive(text)
    except Exception:  # noqa: BLE001 — redactor optional; omit evidence if it fails
        return ""


def _fingerprint(finding: Any) -> str:
    """Stable finding id — reuse the SARIF fingerprint so the same finding
    across runs maps to the same SIEM event id."""
    try:
        from kryon.reporting.sarif import _fingerprint_for_finding

        return _fingerprint_for_finding(
            {
                "cwe_id": getattr(finding, "cwe", "") or "",
                "host": getattr(finding, "host", "") or "",
                "url_shape": "",
                "probe_id": getattr(finding, "rule_id", "") or "",
            }
        )
    except Exception:  # noqa: BLE001
        return ""


def finding_to_siem_event(
    finding: Any,
    *,
    engagement_id: str,
    delta: str = "existing",
    client: str = "",
) -> SIEMEvent:
    """Map one engage.Finding to a normalized SIEMEvent.

    Offensive context (cwe/mitre/rule_id/finding_id/host/delta/confidence)
    travels in ``metadata`` — the Wazuh forwarder flattens it to top-level;
    Splunk/ECS keep it nested under ``event``.
    """
    sev_raw = str(getattr(finding, "severity", "") or "").upper()
    message = str(getattr(finding, "message", "") or "")
    rule_id = str(getattr(finding, "rule_id", "") or "")
    host = str(getattr(finding, "host", "") or getattr(finding, "target_host", "") or "")

    metadata: dict[str, Any] = {
        "host": host,
        "rule_id": rule_id,
        "cwe": getattr(finding, "cwe", "") or "",
        "mitre": getattr(finding, "mitre", "") or getattr(finding, "mitre_technique", "") or "",
        "finding_id": _fingerprint(finding),
        "delta": delta,
        "confidence": getattr(finding, "confidence", None),
        "remediation": getattr(finding, "remediation", "") or "",
        "needs_verification": bool(getattr(finding, "needs_verification", False)),
        "engagement_id": engagement_id,
    }
    if _include_evidence():
        ev = _redact(str(getattr(finding, "evidence", "") or ""))
        if ev:
            metadata["evidence"] = ev[:2000]

    return SIEMEvent(
        event_type="finding",
        severity=_SEV_LOWER.get(sev_raw, "info"),
        source="kryon",
        title=(message[:120] or rule_id or "finding"),
        description=message,
        metadata=metadata,
        client_id=client or None,
    )


def _delta_keys(baseline_diff: Any) -> tuple[set, set]:
    """Return (new_keys, changed_keys) as (rule_id, host) tuples from a
    BaselineDiff. Empty sets when no diff was computed (all 'existing')."""
    if baseline_diff is None:
        return set(), set()
    try:
        from kryon.state.baseline_diff import _key

        new_keys = {_key(d) for d in getattr(baseline_diff, "new", [])}
        changed_keys = {_key(d.get("current", d)) for d in getattr(baseline_diff, "changed", [])}
        return new_keys, changed_keys
    except Exception:  # noqa: BLE001
        return set(), set()


def emit_findings_to_siem(
    findings: list[Any],
    baseline_diff: Any = None,
    *,
    engagement_id: str,
    client: str = "",
) -> int:
    """Forward findings to the configured SIEM(s). Best-effort: returns
    the number of events dispatched (0 when no SIEM is configured or on
    any error). Never raises."""
    if not findings:
        return 0
    try:
        from kryon.integrations import get_integration_manager
        from kryon.state.baseline_diff import _finding_to_dict, _key

        mgr = get_integration_manager()
        # Cron path: load from env if the server store left us empty.
        if not getattr(mgr, "_forwarders", None):
            try:
                mgr.load_from_env()
            except Exception:  # noqa: BLE001
                pass
        if not getattr(mgr, "_forwarders", None):
            return 0  # no SIEM configured → silent no-op

        new_keys, changed_keys = _delta_keys(baseline_diff)
        events: list[SIEMEvent] = []
        for f in findings:
            try:
                k = _key(_finding_to_dict(f))
            except Exception:  # noqa: BLE001
                k = ("", "")
            delta = "new" if k in new_keys else ("changed" if k in changed_keys else "existing")
            events.append(finding_to_siem_event(f, engagement_id=engagement_id, delta=delta, client=client))

        import asyncio

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(mgr.forward_batch(events))
            return len(events)
        # Already inside a loop (rare for the CLI path) — run in a thread.
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            ex.submit(lambda: asyncio.run(mgr.forward_batch(events))).result(timeout=60)
        return len(events)
    except Exception:  # noqa: BLE001 — telemetry must never break the engagement
        logger.debug("emit_findings_to_siem failed", exc_info=True)
        return 0
