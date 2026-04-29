"""Tests for kryon.learning.guide_scorer (F77.G.4 — Guide gate)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from kryon.learning.guide_scorer import (
    GUIDE_DEFAULT_THRESHOLD,
    GUIDE_NATURALNESS_WEIGHT,
    GUIDE_RELEVANCE_WEIGHT,
    GuideScore,
    score_draft,
    score_naturalness,
    score_relevance,
)


@dataclass(frozen=True)
class _FakeDraft:
    """Test double with the same shape as `SkillDraft` (name, body, frontmatter)."""

    name: str = "test-draft"
    body: str = ""
    frontmatter: dict[str, Any] = field(default_factory=dict)


_GOOD_BODY = """\
## Pre-flight
Verify the target host is in scope and the engagement letter is signed.

## Steps
1. Run `nmap -sV -sC -T4 {ctx.target}` to enumerate services.
2. Run `nuclei_scan` against discovered HTTP services.
3. Capture and triage findings.

## Detection
This playbook detects exposed admin panels and outdated middleware on
Apache-fronted targets. Findings are written to ~/.kryon/findings/.

## Output
A markdown report with severity-tagged findings.
"""


def _good_draft(**overrides: Any) -> _FakeDraft:
    fm = {
        "name": "good-draft",
        "required_tools": ["nmap", "nuclei_scan"],
        "triggers": {"tech": ["apache"]},
    }
    fm.update(overrides.pop("frontmatter", {}))
    return _FakeDraft(
        name=overrides.pop("name", "good-draft"),
        body=overrides.pop("body", _GOOD_BODY),
        frontmatter=fm,
    )


# ---------- score_relevance ----------


class TestScoreRelevance:
    def test_clean_draft_scores_full_relevance(self) -> None:
        score, reasons = score_relevance(_good_draft())
        assert score == 1.0
        assert reasons == []

    def test_missing_required_tool_in_body_penalizes(self) -> None:
        body = "## Steps\n1. Just walk around the host.\n"
        score, reasons = score_relevance(
            _good_draft(body=body),
        )
        assert score < 1.0
        assert any("required_tools not referenced" in r for r in reasons)

    def test_empty_required_tools_penalizes(self) -> None:
        score, reasons = score_relevance(
            _good_draft(frontmatter={"required_tools": []}),
        )
        assert score < 1.0
        assert any("empty required_tools" in r for r in reasons)

    def test_no_playbook_section_penalizes(self) -> None:
        body = "Some prose with no markdown headers explaining anything.\n"
        # Mention required tools to isolate the section penalty.
        body += "We use nmap and nuclei_scan.\n"
        score, reasons = score_relevance(_good_draft(body=body))
        assert score < 1.0
        assert any("no Steps/Playbook/Detection" in r for r in reasons)

    def test_empty_body_zeroes_relevance(self) -> None:
        score, reasons = score_relevance(_good_draft(body=""))
        assert score == 0.0
        assert any("body is empty" in r for r in reasons)

    def test_partial_tools_missing_proportional_penalty(self) -> None:
        """Missing 1 of 2 tools penalizes less than missing 2 of 2."""
        fm = {"required_tools": ["nmap", "nuclei_scan"]}
        score_one_missing, _ = score_relevance(
            _FakeDraft(body="## Steps\nUse nmap.", frontmatter=fm),
        )
        score_both_missing, _ = score_relevance(
            _FakeDraft(body="## Steps\nDo something.", frontmatter=fm),
        )
        assert score_one_missing > score_both_missing


# ---------- score_naturalness ----------


class TestScoreNaturalness:
    def test_clean_draft_scores_full_naturalness(self) -> None:
        score, reasons = score_naturalness(_good_draft())
        assert score == 1.0
        assert reasons == []

    def test_too_short_body_penalizes(self) -> None:
        score, reasons = score_naturalness(_good_draft(body="too short"))
        assert score < 1.0
        assert any("too short" in r for r in reasons)

    def test_too_long_body_penalizes(self) -> None:
        score, reasons = score_naturalness(_good_draft(body="x" * 25_000))
        assert score < 1.0
        assert any("suspiciously long" in r for r in reasons)

    def test_high_placeholder_density_penalizes(self) -> None:
        body = "## Steps\n" + "TODO TODO TODO XXXX {INSERT_HERE}\n" * 12
        score, reasons = score_naturalness(_good_draft(body=body))
        assert score < 1.0
        assert any("placeholder density" in r for r in reasons)

    def test_low_placeholder_count_does_not_penalize(self) -> None:
        body = _GOOD_BODY + "\n<!-- TODO: revisit threshold next quarter -->\n"
        score, _ = score_naturalness(_good_draft(body=body))
        # One TODO in a 600-char body is normal documentation, not a stub.
        assert score == 1.0

    def test_duplicate_lines_penalize(self) -> None:
        body = "## Steps\n" + "Run the scan.\n" * 20
        score, reasons = score_naturalness(_good_draft(body=body))
        assert score < 1.0
        assert any("duplicate lines" in r for r in reasons)

    def test_empty_code_block_penalizes(self) -> None:
        body = _GOOD_BODY + "\n\n```bash\n```\n"
        score, reasons = score_naturalness(_good_draft(body=body))
        assert score < 1.0
        assert any("empty/stub code block" in r for r in reasons)

    def test_stub_only_code_block_penalizes(self) -> None:
        body = _GOOD_BODY + "\n\n```python\n# ...\n```\n"
        score, reasons = score_naturalness(_good_draft(body=body))
        assert score < 1.0
        assert any("empty/stub code block" in r for r in reasons)

    def test_empty_body_zeroes_naturalness(self) -> None:
        score, reasons = score_naturalness(_good_draft(body=""))
        assert score == 0.0
        assert reasons == ["naturalness: empty body"]


# ---------- score_draft (combined) ----------


class TestScoreDraft:
    def test_clean_draft_passes_default_threshold(self) -> None:
        result = score_draft(_good_draft())
        assert isinstance(result, GuideScore)
        assert result.relevance == 1.0
        assert result.naturalness == 1.0
        assert result.combined == 1.0
        assert result.passes()
        assert result.reasons == ()

    def test_combined_uses_documented_weights(self) -> None:
        # Custom asymmetric draft: full naturalness, partial relevance.
        # Empty required_tools knocks 0.30 off relevance → 0.70.
        d = _good_draft(frontmatter={"required_tools": []})
        result = score_draft(d)
        assert result.relevance == pytest.approx(0.70)
        assert result.naturalness == 1.0
        expected = (
            GUIDE_RELEVANCE_WEIGHT * 0.70 + GUIDE_NATURALNESS_WEIGHT * 1.0
        )
        assert result.combined == pytest.approx(expected)

    def test_empty_draft_fails_gate(self) -> None:
        result = score_draft(_FakeDraft(body="", frontmatter={}))
        assert result.combined == 0.0
        assert not result.passes()

    def test_loop_artifact_draft_fails_gate(self) -> None:
        """A draft that's a generative loop (repeated nonsense + no
        section + missing tools) must NOT pass."""
        body = "TODO TODO TODO\n" * 30  # 30 × dup + heavy placeholders
        result = score_draft(_FakeDraft(
            body=body,
            frontmatter={"required_tools": ["nmap"]},
        ))
        assert result.combined < GUIDE_DEFAULT_THRESHOLD
        assert not result.passes()
        # Reasons should cite multiple symptoms, not just one.
        assert len(result.reasons) >= 2

    def test_passes_with_custom_threshold(self) -> None:
        """An operator can tighten the gate with a stricter threshold."""
        d = _good_draft(frontmatter={"required_tools": []})
        result = score_draft(d)
        assert result.passes(0.5)
        assert not result.passes(0.95)

    def test_reasons_aggregate_from_both_axes(self) -> None:
        body = "x" * 50  # too short → naturalness reason
        d = _FakeDraft(body=body, frontmatter={"required_tools": []})
        result = score_draft(d)
        relevance_reasons = [r for r in result.reasons if r.startswith("relevance:")]
        naturalness_reasons = [r for r in result.reasons if r.startswith("naturalness:")]
        assert relevance_reasons
        assert naturalness_reasons


# ---------- Edge / robustness ----------


class TestRobustness:
    def test_handles_none_body(self) -> None:
        @dataclass
        class _NoneBody:
            name: str = "x"
            body: Any = None
            frontmatter: dict[str, Any] = field(default_factory=dict)

        # Should not raise.
        result = score_draft(_NoneBody())
        assert result.combined == 0.0

    def test_handles_none_frontmatter(self) -> None:
        @dataclass
        class _NoneFm:
            name: str = "x"
            body: str = _GOOD_BODY
            frontmatter: Any = None

        result = score_draft(_NoneFm())
        # Body is good, frontmatter empty → relevance penalized but naturalness ok.
        assert result.naturalness == 1.0
        assert result.relevance < 1.0

    def test_required_tools_with_uppercase(self) -> None:
        """Tool names are case-insensitive in the body match."""
        body = "## Steps\nUse Nmap and NUCLEI_SCAN to check.\n"
        d = _FakeDraft(
            body=body,
            frontmatter={"required_tools": ["NMAP", "Nuclei_Scan"]},
        )
        rel, _ = score_relevance(d)
        # No "missing tool" penalty even though casing doesn't match.
        assert rel >= 0.80  # may have other small penalties but not the tools one
