"""F88 — RetestRecord: the serializable reproduction blob.

A RetestRecord captures everything the retester needs to replay one
finding deterministically:

  - finding_id            — back-reference to findings_library
  - cwe_id                — for filtering / sorting in reports
  - severity              — preserved so the report uses the original
  - method, url           — exact request to replay
  - headers               — dict (sanitized — see _sanitize_headers)
  - body                  — request body (may be empty)
  - original_http_status  — what the engagement saw
  - original_body_sha256  — full-body hash from the engagement
  - original_body_fingerprint — first 200 chars from the engagement
  - reproduced_at         — ISO-8601 timestamp of the engagement
  - reproduction_notes    — free-text from the auditor

JSON ser/de is built in so an engagement report can carry the
records inline (the auditor exports them, the operator imports them
into the retester). Headers are sanitized at serialization time —
Authorization and Cookie values are stored as their SHA-256 prefix
rather than the raw token. Replay re-injects the operator's CURRENT
auth header at fire time (it's a fresh retest, not a token replay).

Banca-safety:
  - Body fingerprints, not full bodies. The full SHA-256 is stored
    for byte-equivalence matching but the verbatim body never lives
    on disk.
  - Auth headers redacted at serialization. Replay requires the
    operator to supply the current token via a separate channel.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

__all__ = [
    "RetestRecord",
    "record_from_dict",
    "record_to_json",
    "record_from_json",
    "_sanitize_headers",
    "_REDACTED_HEADERS",
]


# Headers that carry secrets — redacted at serialization. The replay
# layer re-injects the operator's current values (different from the
# original engagement — that's the whole point of a retest).
_REDACTED_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "proxy-authorization",
    }
)


def _sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Replace secret-carrying header values with their SHA-256 prefix.

    The prefix is short (16 chars) — enough to verify "you're using the
    same token I tested with" without disclosing the token. Non-secret
    headers pass through verbatim."""
    out: dict[str, str] = {}
    for name, value in headers.items():
        lower = name.lower()
        if lower in _REDACTED_HEADERS:
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
            out[name] = f"<redacted:sha256:{digest}>"
        else:
            out[name] = value
    return out


@dataclass(frozen=True)
class RetestRecord:
    """A self-contained reproduction blob for one finding.

    Engineered to round-trip cleanly through JSON: every field is a
    primitive or a primitive container. No nested dataclasses, no
    Path / datetime / set — those would force callers to handle
    serialization themselves.
    """

    finding_id: str
    cwe_id: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    method: str  # GET / POST / PUT / PATCH / DELETE / HEAD / OPTIONS
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    original_http_status: int = 0
    original_body_sha256: str = ""
    original_body_fingerprint: str = ""
    reproduced_at: str = ""
    reproduction_notes: str = ""

    def sanitized(self) -> RetestRecord:
        """Return a copy of this record with secret headers redacted.

        Used at serialization time; raw records produced by an
        engagement may still carry plaintext tokens, but anything
        that hits disk goes through sanitization first."""
        return RetestRecord(
            finding_id=self.finding_id,
            cwe_id=self.cwe_id,
            severity=self.severity,
            method=self.method,
            url=self.url,
            headers=_sanitize_headers(self.headers),
            body=self.body,
            original_http_status=self.original_http_status,
            original_body_sha256=self.original_body_sha256,
            original_body_fingerprint=self.original_body_fingerprint[:200],
            reproduced_at=self.reproduced_at,
            reproduction_notes=self.reproduction_notes,
        )


def record_from_dict(payload: dict[str, Any]) -> RetestRecord:
    """Build a RetestRecord from a dict. Missing fields default; wrong
    types are coerced where unambiguous, dropped where not.

    Defensive: never raises on a well-shaped-but-imperfect dict so the
    retester can ingest engagement reports with minor schema drift.
    """
    headers = payload.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    return RetestRecord(
        finding_id=str(payload.get("finding_id") or ""),
        cwe_id=str(payload.get("cwe_id") or ""),
        severity=str(payload.get("severity") or "MEDIUM"),
        method=str(payload.get("method") or "GET").upper(),
        url=str(payload.get("url") or ""),
        headers={str(k): str(v) for k, v in headers.items()},
        body=str(payload.get("body") or ""),
        original_http_status=int(payload.get("original_http_status") or 0),
        original_body_sha256=str(payload.get("original_body_sha256") or ""),
        original_body_fingerprint=str(payload.get("original_body_fingerprint") or ""),
        reproduced_at=str(payload.get("reproduced_at") or ""),
        reproduction_notes=str(payload.get("reproduction_notes") or ""),
    )


def record_to_json(record: RetestRecord, *, sanitize: bool = True) -> str:
    """Serialize one record to JSON. Sanitization is on by default —
    explicit opt-out via `sanitize=False` for callers that have a
    reason (typically: a vetted in-memory pipeline that never persists
    the raw record)."""
    target = record.sanitized() if sanitize else record
    return json.dumps(asdict(target), ensure_ascii=False, sort_keys=True)


def record_from_json(payload: str) -> RetestRecord:
    """Inverse of record_to_json. Raises ValueError on un-parseable
    JSON; defensive on well-shaped-but-imperfect docs."""
    try:
        doc = json.loads(payload)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid retest record JSON: {e}") from e
    if not isinstance(doc, dict):
        raise ValueError("retest record must be a JSON object")
    return record_from_dict(doc)
