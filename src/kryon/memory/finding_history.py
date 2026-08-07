"""Finding deduplication and historical tracking."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from kryon.intelligence.models import Finding
from kryon.memory.models import FindingRecord
from kryon.memory.store import MemoryStore


class FindingTracker:
    """Track findings across scans, dedup, and update history."""

    def __init__(self, store: MemoryStore):
        self.store = store

    def record_findings(self, findings: list[Finding], scan_id: str, client_id: str) -> list[FindingRecord]:
        """Record findings from a scan, deduplicating against existing records."""
        existing = self.store.get_client_findings(client_id)
        existing_keys = {self._finding_key(f): f for f in existing}
        now = datetime.now(timezone.utc).isoformat()

        records = []
        for f in findings:
            key = self._finding_key_from_finding(f)
            if key in existing_keys:
                # Update existing finding
                existing_rec = existing_keys[key]
                self.store._get_conn().execute(
                    "UPDATE findings SET last_seen = ?, occurrences = occurrences + 1 WHERE id = ?",
                    (now, existing_rec.id),
                )
                self.store._get_conn().commit()
                records.append(existing_rec)
            else:
                # New finding
                record = FindingRecord(
                    scan_id=scan_id,
                    client_id=client_id,
                    finding_json=f.model_dump_json(),
                    first_seen=now,
                    last_seen=now,
                )
                self.store.save_finding(record)
                records.append(record)

        return records

    def _finding_key(self, record: FindingRecord) -> str:
        """Generate dedup key from finding record."""
        try:
            data = json.loads(record.finding_json)
            return f"{data.get('title', '')}|{data.get('affected_asset', '')}"
        except (json.JSONDecodeError, KeyError):
            return record.id

    def _finding_key_from_finding(self, finding: Finding) -> str:
        """Generate dedup key from Finding model."""
        return f"{finding.title}|{finding.affected_asset}"
