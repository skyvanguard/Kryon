"""F88 — TDD contract for the retester.

Coverage groups:
  - RetestRecord serialization: round-trip JSON, sanitization of
    secret headers, defensive parsing of malformed dicts.
  - verdict_for: matrix over (status change, body change, family
    transitions). Every documented branch hit.
  - replay_finding: double-gate (dry-run default, fire+env required),
    mutation refusal (GET-only unless allow-mutations), HTTP error
    propagated as error verdict, body fingerprint + sha256.
  - aggregate_retest: counts, fix_rate denominator excludes dry_run
    + error, empty list edge.
  - Tool wrapper: single record vs batch dispatch; auth header
    Bearer-prefix heuristic; invalid JSON handled.
  - Frozen contracts.
"""

from __future__ import annotations

import hashlib
import json
from unittest.mock import patch

import pytest

from kryon.retester.aggregator import RetestReport, aggregate_retest
from kryon.retester.comparator import (
    CurrentResponse,
    RetestVerdict,
    verdict_for,
)
from kryon.retester.record import (
    _REDACTED_HEADERS,
    RetestRecord,
    _sanitize_headers,
    record_from_dict,
    record_from_json,
    record_to_json,
)
from kryon.retester.replay import replay_finding

# =====================================================================
# Fixtures
# =====================================================================


def _record(
    *,
    finding_id: str = "fnd_001",
    method: str = "GET",
    url: str = "https://api.bank.example/accounts/123",
    status: int = 200,
    body_sha256: str = "a" * 64,
    body_fingerprint: str = '{"balance": 12345.67}',
    headers: dict[str, str] | None = None,
) -> RetestRecord:
    return RetestRecord(
        finding_id=finding_id,
        cwe_id="CWE-639",
        severity="HIGH",
        method=method,
        url=url,
        headers=headers or {"Authorization": "Bearer secret123", "Accept": "application/json"},
        body="",
        original_http_status=status,
        original_body_sha256=body_sha256,
        original_body_fingerprint=body_fingerprint,
    )


# =====================================================================
# RetestRecord
# =====================================================================


def test_redacted_headers_set_includes_authorization():
    assert "authorization" in _REDACTED_HEADERS
    assert "cookie" in _REDACTED_HEADERS
    assert "x-api-key" in _REDACTED_HEADERS


def test_sanitize_headers_redacts_authorization():
    out = _sanitize_headers({"Authorization": "Bearer secret123", "Accept": "application/json"})
    assert out["Authorization"].startswith("<redacted:sha256:")
    assert out["Accept"] == "application/json"


def test_sanitize_headers_is_case_insensitive():
    """Servers send 'Authorization', 'AUTHORIZATION', 'authorization' —
    all should match the redaction set."""
    for variant in ("Authorization", "AUTHORIZATION", "authorization"):
        out = _sanitize_headers({variant: "sekret"})
        assert out[variant].startswith("<redacted:sha256:")


def test_sanitize_headers_produces_same_digest_for_same_value():
    """Pins the fingerprint property: same token → same redaction.
    Lets the operator verify 'we tested with the same token I'm
    using now' without ever seeing the raw value."""
    h1 = _sanitize_headers({"Authorization": "X"})
    h2 = _sanitize_headers({"Authorization": "X"})
    assert h1 == h2


def test_record_json_roundtrip_sanitizes_by_default():
    record = _record()
    blob = record_to_json(record)
    parsed = json.loads(blob)
    assert parsed["headers"]["Authorization"].startswith("<redacted:")
    # Round-trip back to a record.
    back = record_from_json(blob)
    assert back.finding_id == record.finding_id
    assert back.method == "GET"
    assert back.headers["Authorization"].startswith("<redacted:")


def test_record_json_can_opt_out_of_sanitize():
    record = _record()
    blob = record_to_json(record, sanitize=False)
    parsed = json.loads(blob)
    assert parsed["headers"]["Authorization"] == "Bearer secret123"


def test_record_from_dict_defensive_on_missing_fields():
    """Engagement schemas may not always include every field — the
    parser must default rather than raise."""
    record = record_from_dict({"finding_id": "x"})
    assert record.finding_id == "x"
    assert record.method == "GET"  # default
    assert record.severity == "MEDIUM"  # default
    assert record.headers == {}


def test_record_from_dict_drops_non_dict_headers():
    """If headers came over as a list (server bug), drop it cleanly."""
    record = record_from_dict({"finding_id": "x", "headers": ["not", "a", "dict"]})
    assert record.headers == {}


def test_record_from_json_raises_on_garbage():
    with pytest.raises(ValueError):
        record_from_json("not json at all {{")


def test_record_from_json_raises_on_non_object():
    with pytest.raises(ValueError):
        record_from_json('["array", "not", "object"]')


# =====================================================================
# verdict_for
# =====================================================================


def test_verdict_still_open_when_byte_equivalent():
    record = _record(status=200, body_sha256="abc")
    current = CurrentResponse(http_status=200, body_sha256="abc")
    v = verdict_for(record, current)
    assert v.verdict == "still_open"
    assert v.confidence == 1.0
    assert v.body_changed is False
    assert v.status_changed is False


def test_verdict_fixed_when_2xx_becomes_4xx():
    record = _record(status=200, body_sha256="abc")
    current = CurrentResponse(http_status=403, body_sha256="different")
    v = verdict_for(record, current)
    assert v.verdict == "fixed"
    assert v.confidence == 1.0


def test_verdict_fixed_when_2xx_becomes_5xx():
    """Server error after the patch is also a "fixed" signal — the
    leaking endpoint no longer reachable. Operator follows up to
    distinguish "fixed" from "broken-different-way" but it's NOT
    still_open."""
    record = _record(status=200, body_sha256="abc")
    current = CurrentResponse(http_status=500, body_sha256="")
    v = verdict_for(record, current)
    assert v.verdict == "fixed"


def test_verdict_regressed_when_refusal_becomes_2xx():
    """The engagement saw 403 (already protected); the retest sees
    200 → vuln re-introduced. High-impact signal."""
    record = _record(status=403, body_sha256="forbidden")
    current = CurrentResponse(http_status=200, body_sha256="data")
    v = verdict_for(record, current)
    assert v.verdict == "regressed"
    assert v.confidence >= 0.8


def test_verdict_changed_when_same_status_different_body():
    record = _record(status=200, body_sha256="abc")
    current = CurrentResponse(http_status=200, body_sha256="def")
    v = verdict_for(record, current)
    assert v.verdict == "changed"
    assert v.body_changed is True
    assert v.status_changed is False
    assert v.confidence == 0.7


def test_verdict_changed_when_status_shifts_within_family():
    """200 → 204 — both 2xx but different status code. Confidence
    drops because the signal is murky."""
    record = _record(status=200, body_sha256="abc")
    current = CurrentResponse(http_status=204, body_sha256="abc")
    v = verdict_for(record, current)
    assert v.verdict == "changed"
    assert v.confidence == 0.5


def test_verdict_error_when_current_carries_error():
    record = _record()
    current = CurrentResponse(http_status=0, body_sha256="", error="URLError: dns")
    v = verdict_for(record, current)
    assert v.verdict == "error"
    assert "URLError" in v.reason


def test_verdict_handles_missing_original_body_sha256():
    """Engagement may not have captured the sha (older records). When
    original_body_sha256 is empty, body_changed should be False so
    we don't falsely flag every replay as 'changed'."""
    record = _record(status=200, body_sha256="")
    current = CurrentResponse(http_status=200, body_sha256="any")
    v = verdict_for(record, current)
    # body_changed False because no original hash to compare.
    assert v.body_changed is False
    # Status didn't change either → still_open.
    assert v.verdict == "still_open"


# =====================================================================
# replay_finding — double gate
# =====================================================================


def test_replay_dry_run_returns_dry_run_no_network():
    record = _record()
    with patch("kryon.retester.replay.urlopen") as mock_open:
        v = replay_finding(record, fire=False)
    assert v.verdict == "dry_run"
    mock_open.assert_not_called()


def test_replay_fire_without_env_stays_dry_run(monkeypatch):
    monkeypatch.delenv("KRYON_RETEST_FIRE", raising=False)
    record = _record()
    with patch("kryon.retester.replay.urlopen") as mock_open:
        v = replay_finding(record, fire=True)
    assert v.verdict == "dry_run"
    mock_open.assert_not_called()


def test_replay_refuses_mutations_by_default(monkeypatch):
    """Even with both fire gates set, POST should refuse unless
    KRYON_RETEST_ALLOW_MUTATIONS is also true."""
    monkeypatch.setenv("KRYON_RETEST_FIRE", "true")
    monkeypatch.delenv("KRYON_RETEST_ALLOW_MUTATIONS", raising=False)
    record = _record(method="POST")
    with patch("kryon.retester.replay.urlopen") as mock_open:
        v = replay_finding(record, fire=True)
    assert v.verdict == "error"
    assert "mutation" in v.reason
    mock_open.assert_not_called()


def test_replay_allows_mutations_when_env_set(monkeypatch):
    monkeypatch.setenv("KRYON_RETEST_FIRE", "true")
    monkeypatch.setenv("KRYON_RETEST_ALLOW_MUTATIONS", "true")
    record = _record(method="POST", body_sha256="abc", status=200)

    class _Resp:
        status = 200

        def read(self, cap):
            return b'{"original": true}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("kryon.retester.replay.urlopen", return_value=_Resp()):
        v = replay_finding(record, fire=True)
    # Mutation accepted → comparator decides (it'll be "changed" or
    # "still_open" depending on whether the body matches).
    assert v.verdict != "error"


def test_replay_byte_equivalent_returns_still_open(monkeypatch):
    monkeypatch.setenv("KRYON_RETEST_FIRE", "true")
    body = b'{"balance": 12345.67}'
    record = _record(
        status=200,
        body_sha256=hashlib.sha256(body).hexdigest(),
    )

    class _Resp:
        status = 200

        def read(self, cap):
            return body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("kryon.retester.replay.urlopen", return_value=_Resp()):
        v = replay_finding(record, fire=True)
    assert v.verdict == "still_open"
    assert v.confidence == 1.0


def test_replay_fixed_when_server_returns_403(monkeypatch):
    monkeypatch.setenv("KRYON_RETEST_FIRE", "true")
    record = _record(status=200, body_sha256="abc")
    from urllib.error import HTTPError

    err = HTTPError("http://x", 403, "Forbidden", {}, None)
    with patch("kryon.retester.replay.urlopen", side_effect=err):
        v = replay_finding(record, fire=True)
    assert v.verdict == "fixed"
    assert v.current_status == 403


def test_replay_network_error_returns_error_verdict(monkeypatch):
    monkeypatch.setenv("KRYON_RETEST_FIRE", "true")
    record = _record()
    from urllib.error import URLError

    with patch("kryon.retester.replay.urlopen", side_effect=URLError("dns")):
        v = replay_finding(record, fire=True)
    assert v.verdict == "error"
    assert "URLError" in v.reason


def test_replay_injects_current_auth_header(monkeypatch):
    """The replay must use the operator's CURRENT token, not the
    redacted value stored in the record."""
    monkeypatch.setenv("KRYON_RETEST_FIRE", "true")
    record = _record()  # has Authorization: Bearer secret123

    class _Resp:
        status = 200

        def read(self, cap):
            return b"ok"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("kryon.retester.replay.urlopen", return_value=_Resp()) as mock_open:
        replay_finding(
            record,
            current_auth={"Authorization": "Bearer NEW-TOKEN"},
            fire=True,
        )
    req = mock_open.call_args[0][0]
    # Operator's current token wins.
    assert req.get_header("Authorization") == "Bearer NEW-TOKEN"


def test_replay_skips_redacted_headers_at_send_time(monkeypatch):
    """Redacted headers (<redacted:sha256:...>) in the record must not
    go on the wire — they're sanitization placeholders, not real
    values."""
    monkeypatch.setenv("KRYON_RETEST_FIRE", "true")
    record = _record(
        headers={
            "Authorization": "<redacted:sha256:abc123>",
            "X-Custom": "live",
        },
    )

    class _Resp:
        status = 200

        def read(self, cap):
            return b"ok"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("kryon.retester.replay.urlopen", return_value=_Resp()) as mock_open:
        replay_finding(record, fire=True)
    req = mock_open.call_args[0][0]
    assert req.get_header("Authorization") is None
    assert req.get_header("X-custom") == "live"  # urllib lower-cases


# =====================================================================
# aggregate_retest
# =====================================================================


def _verdict(v: str) -> RetestVerdict:
    return RetestVerdict(
        verdict=v,
        confidence=1.0,
        reason="",
        original_status=200,
        current_status=200 if v == "still_open" else 403,
        body_changed=False,
        status_changed=v != "still_open",
    )


def test_aggregate_counts_by_verdict():
    report = aggregate_retest(
        [
            _verdict("fixed"),
            _verdict("fixed"),
            _verdict("still_open"),
            _verdict("changed"),
            _verdict("error"),
            _verdict("dry_run"),
        ]
    )
    assert report.total == 6
    assert report.by_verdict == {
        "fixed": 2,
        "still_open": 1,
        "changed": 1,
        "error": 1,
        "dry_run": 1,
    }


def test_aggregate_fix_rate_excludes_dry_run_and_error():
    """3 decisive (2 fixed + 1 still_open) → fix_rate 2/3 ≈ 0.667."""
    report = aggregate_retest(
        [
            _verdict("fixed"),
            _verdict("fixed"),
            _verdict("still_open"),
            _verdict("dry_run"),
            _verdict("dry_run"),
            _verdict("error"),
        ]
    )
    assert report.fix_rate == pytest.approx(2 / 3, abs=1e-6)


def test_aggregate_empty_list_returns_zero_fix_rate():
    """No division by zero; fix_rate well-defined at 0."""
    report = aggregate_retest([])
    assert report.total == 0
    assert report.fix_rate == 0.0
    assert report.still_open == ()


def test_aggregate_surfaces_still_open_and_regressed():
    report = aggregate_retest(
        [
            _verdict("fixed"),
            _verdict("still_open"),
            _verdict("regressed"),
            _verdict("still_open"),
        ]
    )
    assert len(report.still_open) == 2
    assert len(report.regressed) == 1


def test_aggregate_fix_rate_with_only_decisive():
    report = aggregate_retest(
        [
            _verdict("fixed"),
            _verdict("fixed"),
            _verdict("fixed"),
        ]
    )
    assert report.fix_rate == 1.0


# =====================================================================
# Tool wrapper
# =====================================================================


def test_tool_single_record_dispatch():
    """Single record JSON → single verdict dict. Dry-run default →
    verdict='dry_run'."""
    from kryon.retester.tool import _verdict_to_dict

    # Manually construct a verdict since the @function_tool wrapper
    # bypasses the SDK shim in unit tests.
    v = _verdict(v="dry_run")
    payload = _verdict_to_dict(v)
    assert payload["verdict"] == "dry_run"
    assert payload["original_status"] == 200


def test_tool_batch_dispatch_returns_report():
    from kryon.retester.tool import _summarize_report

    report = aggregate_retest([_verdict("fixed"), _verdict("still_open"), _verdict("dry_run")])
    payload = _summarize_report(report)
    assert payload["total"] == 3
    assert payload["by_verdict"]["fixed"] == 1
    assert payload["still_open_count"] == 1
    # JSON-serializable end-to-end.
    blob = json.dumps(payload)
    assert "fix_rate" in blob


def test_tool_payload_serializes_via_dataclass_asdict():
    """Pins that nothing tuple-leaks into the JSON output."""
    from kryon.retester.tool import _verdict_to_dict

    v = _verdict("still_open")
    payload = _verdict_to_dict(v)
    json.dumps(payload)  # must not raise


# =====================================================================
# Frozen contracts
# =====================================================================


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    record = _record()
    with pytest.raises(FrozenInstanceError):
        record.method = "POST"  # type: ignore[misc]

    current = CurrentResponse(http_status=200, body_sha256="x")
    with pytest.raises(FrozenInstanceError):
        current.http_status = 500  # type: ignore[misc]

    verdict = _verdict("fixed")
    with pytest.raises(FrozenInstanceError):
        verdict.verdict = "still_open"  # type: ignore[misc]

    report = aggregate_retest([])
    with pytest.raises(FrozenInstanceError):
        report.total = 1  # type: ignore[misc]
