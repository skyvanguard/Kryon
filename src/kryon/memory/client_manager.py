"""High-level client lifecycle management."""

from __future__ import annotations

from kryon.memory.store import MemoryStore


class ClientManager:
    """High-level client lifecycle management."""

    def __init__(self, store: MemoryStore):
        self.store = store

    def get_client_progress(self, client_id: str) -> dict:
        """Compare first scan vs latest: findings delta, risk trend."""
        scans = self.store.list_scans(client_id)
        if not scans:
            return {"scans": 0, "trend": "no_data"}

        first = scans[-1]  # oldest (list is DESC)
        latest = scans[0]  # newest

        return {
            "client_id": client_id,
            "scans": len(scans),
            "first_scan": {
                "id": first.id,
                "date": first.started_at,
                "findings": first.finding_count,
                "risk_score": first.risk_score,
            },
            "latest_scan": {
                "id": latest.id,
                "date": latest.started_at,
                "findings": latest.finding_count,
                "risk_score": latest.risk_score,
            },
            "risk_delta": latest.risk_score - first.risk_score,
            "trend": (
                "improving"
                if latest.risk_score < first.risk_score
                else "stable"
                if latest.risk_score == first.risk_score
                else "worsening"
            ),
        }

    def get_client_timeline(self, client_id: str) -> list[dict]:
        """Chronological scan history with risk scores."""
        scans = self.store.list_scans(client_id)
        return [
            {
                "scan_id": s.id,
                "date": s.started_at,
                "agent": s.agent_key,
                "status": s.status,
                "findings": s.finding_count,
                "risk_score": s.risk_score,
            }
            for s in reversed(scans)  # chronological order
        ]

    def get_remediation_rate(self, client_id: str) -> float:
        """Percentage of findings remediated across all scans."""
        all_findings = self.store.get_client_findings(client_id)
        if not all_findings:
            return 0.0
        remediated = sum(1 for f in all_findings if f.status == "remediated")
        return round(remediated / len(all_findings) * 100, 1)
