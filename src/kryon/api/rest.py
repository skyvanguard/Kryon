"""F145 — Minimal REST API for Kryon.

Read-only endpoints surfacing engagement state + audit aggregator so
external dashboards (operator UI, SOC) can integrate without parsing
the underlying JSONL files themselves.

This is intentionally narrow — full multi-tenant + write endpoints
+ websocket streaming belong in ``kryon.server`` (the existing
FastAPI app under ``server/``). This module gives operators a
zero-config local API for prototyping and Slack-bot style integrations.

Endpoints:
    GET  /health
    GET  /engagements
    GET  /engagements/{engagement_id}
    GET  /findings/{engagement_id}
    GET  /audit/summary
    GET  /schedule
    GET  /queue
    GET  /approvals

Auth: optional ``X-API-Token`` header check (``KRYON_API_TOKEN``).
Empty/unset env disables auth (local dev mode).
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def _check_auth(provided: str) -> bool:
    expected = os.environ.get("KRYON_API_TOKEN", "").strip()
    if not expected:
        return True  # local dev mode
    return provided == expected


def build_app():
    """Build the FastAPI app. Late import so ``kryon.api`` is
    importable even when fastapi isn't installed."""
    try:
        from fastapi import FastAPI, Header, HTTPException, Query
        from fastapi.responses import JSONResponse
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("F145 REST API requires fastapi. Install via `uv pip install fastapi uvicorn`.") from exc

    app = FastAPI(title="Kryon REST API", version="1.0")

    def _auth_or_raise(token: str | None) -> None:
        if not _check_auth(token or ""):
            raise HTTPException(status_code=401, detail="invalid API token")

    @app.get("/health")
    def health(x_api_token: str | None = Header(default=None)):
        _auth_or_raise(x_api_token)
        from kryon.health import run_doctor

        results = run_doctor(check_ollama=False)
        return {
            "ok": all(r.ok for r in results),
            "checks": [r.to_dict() for r in results],
        }

    @app.get("/engagements")
    def list_engagements(x_api_token: str | None = Header(default=None)):
        _auth_or_raise(x_api_token)
        state_dir = Path(".kryon") / "state"
        if not state_dir.exists():
            return {"engagements": []}
        out: list[dict] = []
        for f in sorted(state_dir.glob("*.json")):
            try:
                out.append(json.loads(f.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
        return {"engagements": out, "count": len(out)}

    @app.get("/engagements/{engagement_id}")
    def get_engagement(engagement_id: str, x_api_token: str | None = Header(default=None)):
        _auth_or_raise(x_api_token)
        # Look up by engagement_id across state files.
        state_dir = Path(".kryon") / "state"
        if state_dir.exists():
            for f in state_dir.glob("*.json"):
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                    if data.get("last_engagement_id") == engagement_id:
                        return data
                except (OSError, json.JSONDecodeError):
                    continue
        # Fallback: checkpoint.
        from kryon.state.checkpoint import load_checkpoint

        cp = load_checkpoint(engagement_id)
        if cp is None:
            raise HTTPException(status_code=404, detail="engagement not found")
        return cp.to_dict()

    @app.get("/findings/{engagement_id}")
    def get_findings(engagement_id: str, x_api_token: str | None = Header(default=None)):
        _auth_or_raise(x_api_token)
        # findings.json is in the report output dir, which is per-engagement.
        # Look for it under default reports/ first.
        for candidate in [
            Path("reports") / f"{engagement_id}" / f"kryon-{engagement_id}.findings.json",
            Path("reports") / f"kryon-{engagement_id}.findings.json",
        ]:
            if candidate.exists():
                try:
                    return json.loads(candidate.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    raise HTTPException(status_code=500, detail="findings file unreadable")
        raise HTTPException(status_code=404, detail="findings not found")

    @app.get("/audit/summary")
    def audit_summary(
        x_api_token: str | None = Header(default=None),
        dir: str = Query(default=".kryon/audit"),
    ):
        _auth_or_raise(x_api_token)
        from kryon.audit.aggregator import aggregate_audit_logs

        report = aggregate_audit_logs(dir)
        return report.to_dict()

    @app.get("/schedule")
    def list_schedule(x_api_token: str | None = Header(default=None)):
        _auth_or_raise(x_api_token)
        from kryon.scheduler import Scheduler

        s = Scheduler.load()
        return {"jobs": [j.to_dict() for j in s.jobs]}

    @app.get("/queue")
    def list_queue(x_api_token: str | None = Header(default=None)):
        _auth_or_raise(x_api_token)
        from kryon.queue import EngagementQueue

        q = EngagementQueue.load()
        return {"items": [i.to_dict() for i in q.items]}

    @app.get("/approvals")
    def list_approvals(x_api_token: str | None = Header(default=None)):
        _auth_or_raise(x_api_token)
        from kryon.approval import ApprovalQueue

        a = ApprovalQueue.load()
        return {"pending": [p.to_dict() for p in a.pending]}

    return app
