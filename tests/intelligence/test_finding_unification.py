"""Tests for the unified Finding model — verification_level + needs_verification
now live on intelligence.models.Finding (previously dropped when engage-pipeline
findings crossed into this model, which blocked program metrics)."""

from __future__ import annotations

import json

from kryon.intelligence.models import Finding, Severity


def _finding(**kw) -> Finding:
    base = dict(title="t", description="d", severity=Severity.HIGH, affected_asset="h")
    base.update(kw)
    return Finding(**base)


def test_defaults_are_backward_compatible():
    """Findings without the new fields default to confirmed/not-needing-review."""
    f = _finding()
    assert f.verification_level == "confirmed"
    assert f.needs_verification is False
    assert f.is_validated_exploitable is True


def test_verification_level_roundtrips_through_json():
    """The anti-FP band survives model_dump_json -> Finding(**...) (persistence)."""
    f = _finding(verification_level="heuristic", needs_verification=True)
    restored = Finding(**json.loads(f.model_dump_json()))
    assert restored.verification_level == "heuristic"
    assert restored.needs_verification is True


def test_is_validated_exploitable_gating():
    assert _finding(verification_level="confirmed", needs_verification=False).is_validated_exploitable
    assert not _finding(verification_level="heuristic").is_validated_exploitable
    assert not _finding(verification_level="inferred").is_validated_exploitable
    assert not _finding(verification_level="confirmed", needs_verification=True).is_validated_exploitable


def test_accepts_field_from_dict_like_persisted_record():
    """Simulates reconstructing from a stored finding_json that carries the band."""
    parsed = {
        "title": "SQLi",
        "description": "union-based",
        "severity": "critical",
        "affected_asset": "10.0.0.1",
        "verification_level": "confirmed",
        "needs_verification": False,
    }
    f = Finding(**parsed)
    assert f.is_validated_exploitable is True
    assert f.severity == Severity.CRITICAL
