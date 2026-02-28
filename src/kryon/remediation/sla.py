"""SLA calculation and enforcement for remediation workflow."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# SLA deadlines by priority (in days)
SLA_DEADLINES = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
}


def calculate_sla_deadline(priority: str, from_date: datetime | None = None) -> str:
    """Calculate SLA deadline based on priority. Returns ISO format string."""
    if from_date is None:
        from_date = datetime.now(timezone.utc)
    days = SLA_DEADLINES.get(priority.lower(), 90)
    deadline = from_date + timedelta(days=days)
    return deadline.isoformat()


def get_overdue_findings(store, client_id: str = "") -> list:
    """Get all findings past their SLA deadline."""
    return store.get_overdue_findings(client_id=client_id)


def calculate_mttr(store, client_id: str = "") -> dict:
    """Calculate Mean Time To Remediate metrics."""
    base = store.get_mttr(client_id=client_id)

    # Add SLA compliance percentage
    now = datetime.now(timezone.utc).isoformat()
    conn = store._get_conn()

    sql_total = "SELECT COUNT(*) FROM findings WHERE sla_deadline IS NOT NULL"
    sql_overdue = "SELECT COUNT(*) FROM findings WHERE sla_deadline IS NOT NULL AND sla_deadline < ? AND status = 'open'"
    params_total: list = []
    params_overdue: list = [now]

    if client_id:
        sql_total += " AND client_id = ?"
        params_total.append(client_id)
        sql_overdue += " AND client_id = ?"
        params_overdue.append(client_id)

    total = conn.execute(sql_total, params_total).fetchone()[0]
    overdue = conn.execute(sql_overdue, params_overdue).fetchone()[0]

    sla_compliance = round(((total - overdue) / total * 100) if total > 0 else 100.0, 1)

    return {
        **base,
        "overdue_count": overdue,
        "total_with_sla": total,
        "sla_compliance_pct": sla_compliance,
    }
