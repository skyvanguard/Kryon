"""F138 — Auto-promote tests."""

from __future__ import annotations

from pathlib import Path

from kryon.learning.auto_promote import (
    PromotionDecision,
    PromotionResult,
    auto_promote_drafts,
    evaluate_draft,
    promote_draft,
)

# ---------------------------------------------------------------------------
# evaluate_draft
# ---------------------------------------------------------------------------


def test_evaluate_passes_when_all_thresholds_met(monkeypatch):
    monkeypatch.delenv("KRYON_AUTO_PROMOTE_WILSON_MIN", raising=False)
    monkeypatch.delenv("KRYON_AUTO_PROMOTE_REUSABILITY_MIN", raising=False)
    d = evaluate_draft(draft_name="x", wilson_lower_bound=0.8, reusability_score=4)
    assert d.promote is True
    assert "all thresholds met" in d.reasons[0]


def test_evaluate_fails_low_wilson():
    d = evaluate_draft(draft_name="x", wilson_lower_bound=0.5, reusability_score=10)
    assert d.promote is False
    assert any("Wilson" in r for r in d.reasons)


def test_evaluate_fails_low_reusability():
    d = evaluate_draft(draft_name="x", wilson_lower_bound=0.9, reusability_score=1)
    assert d.promote is False
    assert any("reusability" in r for r in d.reasons)


def test_evaluate_fails_evaluator_block():
    d = evaluate_draft(draft_name="x", wilson_lower_bound=0.9, reusability_score=5, evaluator_passed=False)
    assert d.promote is False
    assert any("evaluator" in r for r in d.reasons)


def test_evaluate_respects_env_thresholds(monkeypatch):
    monkeypatch.setenv("KRYON_AUTO_PROMOTE_WILSON_MIN", "0.9")
    monkeypatch.setenv("KRYON_AUTO_PROMOTE_REUSABILITY_MIN", "10")
    d = evaluate_draft(draft_name="x", wilson_lower_bound=0.8, reusability_score=5)
    assert d.promote is False


# ---------------------------------------------------------------------------
# promote_draft (file move)
# ---------------------------------------------------------------------------


def test_promote_moves_file(tmp_path):
    drafts = tmp_path / "drafts"
    playbooks = tmp_path / "playbooks"
    drafts.mkdir()
    f = drafts / "skill-x.md"
    f.write_text("# skill x", encoding="utf-8")

    ok, dest = promote_draft(draft_path=f, playbooks_dir=playbooks)

    assert ok is True
    assert (playbooks / "skill-x.md").exists()
    assert not f.exists()


def test_promote_missing_draft_returns_error(tmp_path):
    ok, msg = promote_draft(draft_path=tmp_path / "nope.md", playbooks_dir=tmp_path / "p")
    assert ok is False
    assert "missing" in msg


def test_promote_refuses_overwrite(tmp_path):
    drafts = tmp_path / "d"
    playbooks = tmp_path / "p"
    drafts.mkdir()
    playbooks.mkdir()
    f = drafts / "skill.md"
    f.write_text("draft", encoding="utf-8")
    (playbooks / "skill.md").write_text("existing", encoding="utf-8")

    ok, msg = promote_draft(draft_path=f, playbooks_dir=playbooks)

    assert ok is False
    assert "exists" in msg


# ---------------------------------------------------------------------------
# auto_promote_drafts integration
# ---------------------------------------------------------------------------


def test_disabled_by_default_returns_no_promotions(tmp_path, monkeypatch):
    monkeypatch.delenv("KRYON_AUTO_PROMOTE_SKILLS", raising=False)
    drafts = tmp_path / "d"
    drafts.mkdir()
    (drafts / "x.md").write_text("x", encoding="utf-8")

    result = auto_promote_drafts(
        drafts_dir=drafts,
        playbooks_dir=tmp_path / "p",
        score_lookup=lambda name: (0.99, 100, True),
    )

    assert result.promoted == []


def test_explicit_enabled_promotes_qualifying_drafts(tmp_path, monkeypatch):
    monkeypatch.delenv("KRYON_AUTO_PROMOTE_WILSON_MIN", raising=False)
    monkeypatch.delenv("KRYON_AUTO_PROMOTE_REUSABILITY_MIN", raising=False)
    drafts = tmp_path / "d"
    playbooks = tmp_path / "p"
    drafts.mkdir()
    (drafts / "good.md").write_text("g", encoding="utf-8")
    (drafts / "bad.md").write_text("b", encoding="utf-8")

    def lookup(name):
        if name == "good":
            return (0.9, 5, True)
        return (0.3, 1, True)

    result = auto_promote_drafts(
        drafts_dir=drafts,
        playbooks_dir=playbooks,
        score_lookup=lookup,
        enabled=True,
    )

    assert len(result.promoted) == 1
    assert any("good.md" in p for p in result.promoted)
    assert len(result.skipped) == 1
    assert result.skipped[0].draft_name == "bad"


def test_env_enabled_works(tmp_path, monkeypatch):
    monkeypatch.setenv("KRYON_AUTO_PROMOTE_SKILLS", "true")
    drafts = tmp_path / "d"
    drafts.mkdir()
    (drafts / "ok.md").write_text("x", encoding="utf-8")
    result = auto_promote_drafts(
        drafts_dir=drafts,
        playbooks_dir=tmp_path / "p",
        score_lookup=lambda name: (0.95, 10, True),
    )
    assert len(result.promoted) == 1


def test_score_lookup_failure_is_recorded(tmp_path):
    drafts = tmp_path / "d"
    drafts.mkdir()
    (drafts / "x.md").write_text("x", encoding="utf-8")

    def bad_lookup(name):
        raise RuntimeError("scorer down")

    result = auto_promote_drafts(
        drafts_dir=drafts,
        playbooks_dir=tmp_path / "p",
        score_lookup=bad_lookup,
        enabled=True,
    )
    assert result.promoted == []
    assert len(result.errored) == 1


def test_missing_drafts_dir_is_no_op(tmp_path):
    result = auto_promote_drafts(
        drafts_dir=tmp_path / "no",
        playbooks_dir=tmp_path / "p",
        score_lookup=lambda n: (1.0, 100, True),
        enabled=True,
    )
    assert result.promoted == []
    assert result.skipped == []
