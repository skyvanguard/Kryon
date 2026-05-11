"""End-to-end integration test for /skill auto detect / status.

Exercises the full Fase 3 flow:
  experiences (stubbed) → pattern_detector → synthesize_from_cluster
  → skill_evaluator → draft_writer → SkillCommand.handle_auto

Stubs both `list_experiences` and the findings store so the test
runs without ChromaDB. The command handlers are invoked directly
(no Rich rendering asserted — we check files on disk + exit codes).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _experience(eid: str, tools: list[str], tech: list[str]) -> dict:
    return {
        "id": eid,
        "outcome": "success",
        "agent_path": ["recon-scout"],
        "target_profile": {"tech": tech, "ports": [80, 443], "host": f"{eid}.x"},
        "chain": [{"tool": t, "args": "", "status": "ok", "output": ""} for t in tools],
        "outcome_signals": {"shell_gained": True},
        "duration_s": 60,
        "created_at": "2026-04-28T17:00:00+00:00",
    }


def _finding(cwe: str, tech: str = "wordpress") -> dict:
    return {
        "id": f"fnd_{cwe}_{tech}",
        "cwe_id": cwe,
        "tech_fingerprint": tech,
        "title": "test",
        "host": "x.example.com",
        "url": "https://x.example.com/api/x",
    }


@pytest.fixture
def isolated_drafts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    target = tmp_path / "drafts"
    monkeypatch.setenv("KRYON_DRAFTS_DIR", str(target))
    return target


@pytest.fixture
def stub_list_experiences(monkeypatch: pytest.MonkeyPatch):
    """Replace `kryon.learning.list_experiences` with a stub."""

    def _stub(experiences: list[dict]):
        from kryon.learning import experiences as exp_mod

        def fake_list_experiences(limit: int = 20) -> list[dict]:
            return experiences

        # Patch both the source location and the re-export path used by the
        # SkillCommand handler (`from kryon.learning import list_experiences`).
        monkeypatch.setattr(exp_mod, "list_experiences", fake_list_experiences)
        # Also patch the alias that `from kryon.learning import list_experiences`
        # resolves to.
        from kryon import learning as learning_mod

        monkeypatch.setattr(
            learning_mod,
            "list_experiences",
            fake_list_experiences,
        )

    return _stub


# ---------- E2E with real handlers ----------


def test_auto_detect_passed_flow_writes_files(
    isolated_drafts: Path,
    stub_list_experiences,
) -> None:
    """3 similar engagements + matching findings → 1 passed draft on disk."""
    from kryon.repl.commands.skill import SkillCommand

    exps = [_experience(f"e{i}", ["nmap", "nuclei_scan"], ["wordpress"]) for i in range(3)]
    stub_list_experiences(exps)

    # Stub findings_library.list → return wordpress SQLi findings.
    # The handler imports it lazily so we patch the module path directly.
    import sys
    import types

    fake_fnd = types.ModuleType("kryon.learning.findings_library")
    fake_fnd.list = lambda: [_finding("CWE-89") for _ in range(5)]  # type: ignore[attr-defined]
    sys.modules["kryon.learning.findings_library"] = fake_fnd
    try:
        cmd = SkillCommand()
        assert cmd.handle_auto(["detect"]) is True
    finally:
        del sys.modules["kryon.learning.findings_library"]

    auto_files = list((isolated_drafts / "_auto").glob("*.md"))
    assert len(auto_files) == 1
    eval_files = list((isolated_drafts / "_auto").glob("*.eval.json"))
    assert len(eval_files) == 1

    report = json.loads(eval_files[0].read_text(encoding="utf-8"))
    assert report["eval_status"] == "passed"
    assert report["findings_evaluated"] == 5
    assert report["findings_passed"] == 5


def test_auto_detect_skipped_flow_writes_to_rejected(
    isolated_drafts: Path,
    stub_list_experiences,
) -> None:
    """Cluster found but no findings corpus → eval skipped → goes to _rejected/."""
    from kryon.repl.commands.skill import SkillCommand

    exps = [_experience(f"e{i}", ["nmap", "nuclei_scan"], ["wordpress"]) for i in range(3)]
    stub_list_experiences(exps)

    # No findings_library → list import fails → empty corpus
    import sys

    sys.modules.pop("kryon.learning.findings_library", None)
    cmd = SkillCommand()
    assert cmd.handle_auto(["detect"]) is True

    rejected = list((isolated_drafts / "_rejected").glob("*.eval.json"))
    assert len(rejected) == 1
    report = json.loads(rejected[0].read_text(encoding="utf-8"))
    assert report["eval_status"] == "skipped"


def test_auto_status_after_detect_lists_outputs(
    isolated_drafts: Path,
    stub_list_experiences,
) -> None:
    """Run detect, then status — should not raise and the dirs exist."""
    from kryon.repl.commands.skill import SkillCommand

    exps = [_experience(f"e{i}", ["nmap", "nuclei_scan"], ["wordpress"]) for i in range(3)]
    stub_list_experiences(exps)

    cmd = SkillCommand()
    cmd.handle_auto(["detect"])
    assert cmd.handle_auto(["status"]) is True


def test_auto_status_with_no_drafts_does_not_crash(isolated_drafts: Path) -> None:
    from kryon.repl.commands.skill import SkillCommand

    cmd = SkillCommand()
    assert cmd.handle_auto(["status"]) is True


def test_auto_unknown_subcommand_returns_false(isolated_drafts: Path) -> None:
    from kryon.repl.commands.skill import SkillCommand

    cmd = SkillCommand()
    assert cmd.handle_auto(["nonsense"]) is False


def test_auto_no_args_defaults_to_status(isolated_drafts: Path) -> None:
    from kryon.repl.commands.skill import SkillCommand

    cmd = SkillCommand()
    # No args → should run status (returns True, no crash).
    assert cmd.handle_auto() is True


# ---------- Promotion path interop ----------


def test_passed_auto_draft_can_be_loaded_via_skill_loader(
    isolated_drafts: Path,
    stub_list_experiences,
) -> None:
    """A draft from /skill auto detect is parseable by SkillLoader so the
    operator can later promote + reload it."""
    from kryon.repl.commands.skill import SkillCommand
    from kryon.skills.loader import _parse_skill_file

    exps = [_experience(f"e{i}", ["nmap", "nuclei_scan"], ["wordpress"]) for i in range(3)]
    stub_list_experiences(exps)

    import sys
    import types

    fake_fnd = types.ModuleType("kryon.learning.findings_library")
    fake_fnd.list = lambda: [_finding("CWE-89") for _ in range(5)]  # type: ignore[attr-defined]
    sys.modules["kryon.learning.findings_library"] = fake_fnd
    try:
        cmd = SkillCommand()
        cmd.handle_auto(["detect"])
    finally:
        del sys.modules["kryon.learning.findings_library"]

    auto_files = list((isolated_drafts / "_auto").glob("*.md"))
    assert auto_files

    skill = _parse_skill_file(auto_files[0])
    assert skill is not None
    assert "nmap" in skill.required_tools
    # Cluster-derived provenance survives the round-trip
    # (the loader doesn't surface _provenance, but the file itself contains it).
    content = auto_files[0].read_text(encoding="utf-8")
    assert "_provenance:" in content
    assert "auto-cluster" in content
