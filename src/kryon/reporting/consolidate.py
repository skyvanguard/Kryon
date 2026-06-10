"""F1.1 — Consolidate a multi-host engagement into ONE client deliverable.

``kryon queue process --out <root>`` writes each host's engage output to
``<root>/<item_id>/``. The client should get ONE spreadsheet + ONE summary for
the whole segment, not N separate folders. This walks those per-host findings
JSONs, normalizes them, and emits a consolidated CSV/Excel plus a segment
summary (per-host + global severity counts + an integrity hash).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from kryon.reporting.findings_export import (
    FindingRow,
    export_findings,
    from_engage_finding,
)

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@dataclass(frozen=True)
class HostFindings:
    item_id: str
    host: str
    findings: list[dict]


def collect_host_findings(root: Path) -> list[HostFindings]:
    """Walk ``<root>/<item_id>/*.findings.json`` and return per-host findings.

    Robust to missing/partial folders (a host whose engage failed simply
    contributes zero findings instead of breaking the consolidation).
    """
    root = Path(root)
    out: list[HostFindings] = []
    if not root.is_dir():
        return out
    for item_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        json_files = sorted(item_dir.glob("*.findings.json"))
        if not json_files:
            continue
        # One engagement per item dir; take the first findings JSON.
        try:
            data = json.loads(json_files[0].read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        findings = data.get("findings") or []
        context = data.get("context") or {}
        host = str(context.get("target_scope") or context.get("host") or item_dir.name)
        out.append(HostFindings(item_id=item_dir.name, host=host, findings=findings))
    return out


def _rows_for_host(hf: HostFindings) -> list[FindingRow]:
    rows: list[FindingRow] = []
    for fd in hf.findings:
        ns = SimpleNamespace(**fd)
        row = from_engage_finding(ns)
        # Ensure the host column is populated from the engagement context when
        # the finding itself didn't carry a host.
        if not row.host:
            row = FindingRow(**{**row.as_dict(), "host": hf.host})
        rows.append(row)
    return rows


def _severity_counts(rows: list[FindingRow]) -> dict[str, int]:
    counts = dict.fromkeys(_SEVERITY_ORDER, 0)
    for r in rows:
        sev = r.severity.upper()
        counts[sev] = counts.get(sev, 0) + 1
    return {k: v for k, v in counts.items() if v}


def consolidate_rows(hosts: list[HostFindings]) -> list[FindingRow]:
    rows: list[FindingRow] = []
    for hf in hosts:
        rows.extend(_rows_for_host(hf))
    return rows


def segment_summary(hosts: list[HostFindings], rows: list[FindingRow]) -> dict:
    """Per-host + global breakdown with a deterministic integrity hash."""
    per_host = []
    for hf in hosts:
        hrows = _rows_for_host(hf)
        per_host.append(
            {
                "item_id": hf.item_id,
                "host": hf.host,
                "findings": len(hrows),
                "by_severity": _severity_counts(hrows),
            }
        )
    digest_src = json.dumps(
        [r.as_dict() for r in sorted(rows, key=lambda r: (r.host, r.id, r.severity))],
        sort_keys=True,
        ensure_ascii=False,
    )
    return {
        "host_count": len(hosts),
        "total_findings": len(rows),
        "by_severity": _severity_counts(rows),
        "hosts": per_host,
        "hash": hashlib.sha256(digest_src.encode("utf-8")).hexdigest(),
    }


def consolidate_engagement_dir(
    root: Path,
    client_name: str = "",
    fmt: str = "xlsx",
) -> dict[str, object]:
    """Build the consolidated deliverable for a processed queue ``--out`` dir.

    Returns a dict with the written spreadsheet path, the summary JSON path,
    and the in-memory summary. Falls back to CSV cleanly if openpyxl is absent.
    """
    root = Path(root)
    hosts = collect_host_findings(root)
    rows = consolidate_rows(hosts)
    summary = segment_summary(hosts, rows)

    try:
        sheet_path = export_findings(rows, fmt=fmt, client_name=client_name or "segment", report_type="consolidated")
    except RuntimeError:
        # openpyxl missing — degrade to CSV so the deliverable still ships.
        sheet_path = export_findings(rows, fmt="csv", client_name=client_name or "segment", report_type="consolidated")

    summary_path = root / "segment-summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    return {"spreadsheet": sheet_path, "summary_json": summary_path, "summary": summary}
