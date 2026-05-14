"""F88 — Replay primitives: issue the engagement probe again under gates.

Composes RetestRecord (what to replay) + operator-supplied current
auth + the comparator (what verdict to emit).

Banca-safety:
  - Double gate: KRYON_RETEST_FIRE=true env AND fire=True kwarg.
    Default DRY-RUN returns verdict="dry_run" with no HTTP traffic.
  - GET-only by default. Mutations (POST/PUT/PATCH/DELETE) refuse
    unless KRYON_RETEST_ALLOW_MUTATIONS=true env is set too. We don't
    want a retest accidentally re-submitting a transfer that was the
    original finding.
  - Stdlib urllib only.
  - 2 MB response cap — same as F87.3 GraphQL.
  - Body fingerprint (200 chars) + SHA-256 hash on the wire. Full
    body NEVER persisted.
"""

from __future__ import annotations

import hashlib
import logging
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from kryon.retester.comparator import CurrentResponse, RetestVerdict, verdict_for
from kryon.retester.record import RetestRecord

logger = logging.getLogger(__name__)

__all__ = ["replay_finding", "RESPONSE_CAP_BYTES"]


RESPONSE_CAP_BYTES = 2 * 1024 * 1024  # 2 MB
_BODY_FINGERPRINT_CHARS = 200

_MUTATION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _fire_enabled(fire: bool) -> bool:
    if not fire:
        return False
    return os.environ.get("KRYON_RETEST_FIRE", "").strip().lower() in ("1", "true", "yes")


def _mutations_allowed() -> bool:
    return os.environ.get("KRYON_RETEST_ALLOW_MUTATIONS", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )


def _build_request(record: RetestRecord, *, current_auth: dict[str, str] | None) -> Request:
    """Compose the urllib Request. `current_auth` is the operator's
    current-token headers, NOT what's stored in the record (record
    headers are sanitized; auth was redacted at serialization)."""
    method = record.method.upper()
    headers = {k: v for k, v in record.headers.items() if not v.startswith("<redacted:")}
    if current_auth:
        headers.update(current_auth)
    data = record.body.encode("utf-8") if record.body else None
    req = Request(record.url, data=data, headers=headers, method=method)
    return req


def replay_finding(
    record: RetestRecord,
    *,
    current_auth: dict[str, str] | None = None,
    fire: bool = False,
    timeout: int = 30,
) -> RetestVerdict:
    """Replay one finding's probe and return the verdict.

    Args:
        record: the engagement reproduction blob.
        current_auth: headers to inject for auth (typically
            `{"Authorization": "Bearer <fresh-token>"}`). Required for
            replays where the original engagement used an Authorization
            header — without it the server returns 401 which would
            be misclassified as "fixed".
        fire: opt-in for live HTTP. Combined with KRYON_RETEST_FIRE
            env, gates the network call.
        timeout: per-request timeout in seconds.

    Returns:
        RetestVerdict from the comparator. Verdict='dry_run' when
        gates aren't satisfied; verdict='error' when the probe
        couldn't run.
    """
    # Dry-run path: no HTTP, no comparator call. We construct a
    # verdict that mirrors what the comparator would say if both
    # responses matched verbatim — but tagged dry_run so consumers
    # don't confuse it with a real result.
    if not _fire_enabled(fire):
        return RetestVerdict(
            verdict="dry_run",
            confidence=0.0,
            reason=(
                f"dry-run: would {record.method} {record.url}. "
                "Set KRYON_RETEST_FIRE=true and pass fire=True to execute."
            ),
            original_status=record.original_http_status,
            current_status=None,
            body_changed=False,
            status_changed=False,
        )

    method = record.method.upper()
    if method in _MUTATION_METHODS and not _mutations_allowed():
        return RetestVerdict(
            verdict="error",
            confidence=1.0,
            reason=(
                f"banca-safety: refusing to replay {method} (mutation). "
                "Set KRYON_RETEST_ALLOW_MUTATIONS=true to opt in."
            ),
            original_status=record.original_http_status,
            current_status=None,
            body_changed=False,
            status_changed=False,
        )

    req = _build_request(record, current_auth=current_auth)
    try:
        with urlopen(req, timeout=timeout) as resp:
            status = resp.status
            raw = resp.read(RESPONSE_CAP_BYTES)
    except HTTPError as e:
        status = e.code
        try:
            raw = e.read(RESPONSE_CAP_BYTES)
        except Exception:  # noqa: BLE001
            raw = b""
    except (URLError, TimeoutError, OSError) as e:
        return verdict_for(
            record,
            CurrentResponse(http_status=0, body_sha256="", error=f"{type(e).__name__}: {e}"),
        )
    except Exception as e:  # noqa: BLE001
        return verdict_for(
            record,
            CurrentResponse(http_status=0, body_sha256="", error=f"{type(e).__name__}: {e}"),
        )

    body_sha256 = hashlib.sha256(raw).hexdigest() if raw else ""
    fingerprint = raw[:_BODY_FINGERPRINT_CHARS].decode("utf-8", errors="replace") if raw else ""
    current = CurrentResponse(
        http_status=status,
        body_sha256=body_sha256,
        body_fingerprint=fingerprint,
    )
    return verdict_for(record, current)
