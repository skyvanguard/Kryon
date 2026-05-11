"""TDD contract for skill_evaluator.load_cwe_map_override.

Loads `~/.kryon/cwe_map.yaml` (or env-overridden path) and merges with
the default map. Per-CWE entries in the file REPLACE the default for
that CWE (no within-CWE union). New CWEs in the file extend the map.

Failure modes (missing file, invalid yaml) degrade gracefully — caller
gets the default map back, never an exception.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# ---------- File resolution ----------


def test_load_returns_default_when_no_file_anywhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))            # POSIX
    monkeypatch.setenv("USERPROFILE", str(tmp_path))     # Windows
    monkeypatch.delenv("KRYON_CWE_MAP", raising=False)

    from kryon.learning.skill_evaluator import (
        _DEFAULT_CWE_TO_TOOLS,
        load_cwe_map_override,
    )

    result = load_cwe_map_override()
    # Same content as default — every CWE present, every set unchanged.
    for cwe, tools in _DEFAULT_CWE_TO_TOOLS.items():
        assert result[cwe] == tools


def test_load_uses_explicit_path_when_provided(tmp_path: Path) -> None:
    from kryon.learning.skill_evaluator import load_cwe_map_override

    p = tmp_path / "custom.yaml"
    p.write_text("CWE-9999:\n  - my_custom_tool\n", encoding="utf-8")

    result = load_cwe_map_override(path=p)
    assert "CWE-9999" in result
    assert result["CWE-9999"] == {"my_custom_tool"}


def test_load_uses_env_var_when_no_explicit_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = tmp_path / "env_path.yaml"
    p.write_text("CWE-7777:\n  - banking_internal_scanner\n", encoding="utf-8")
    monkeypatch.setenv("KRYON_CWE_MAP", str(p))

    from kryon.learning.skill_evaluator import load_cwe_map_override

    result = load_cwe_map_override()
    assert "CWE-7777" in result
    assert result["CWE-7777"] == {"banking_internal_scanner"}


def test_load_uses_home_default_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default path: <home>/.kryon/cwe_map.yaml"""
    monkeypatch.delenv("KRYON_CWE_MAP", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    kryon_dir = tmp_path / ".kryon"
    kryon_dir.mkdir()
    (kryon_dir / "cwe_map.yaml").write_text(
        "CWE-DEMO-1:\n  - example_tool\n", encoding="utf-8",
    )

    from kryon.learning.skill_evaluator import load_cwe_map_override

    result = load_cwe_map_override()
    assert "CWE-DEMO-1" in result


def test_explicit_path_takes_precedence_over_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_path = tmp_path / "env.yaml"
    env_path.write_text("CWE-ENV:\n  - env_tool\n", encoding="utf-8")
    monkeypatch.setenv("KRYON_CWE_MAP", str(env_path))

    explicit = tmp_path / "explicit.yaml"
    explicit.write_text("CWE-EXPLICIT:\n  - explicit_tool\n", encoding="utf-8")

    from kryon.learning.skill_evaluator import load_cwe_map_override

    result = load_cwe_map_override(path=explicit)
    assert "CWE-EXPLICIT" in result
    assert "CWE-ENV" not in result  # env was ignored


# ---------- Merge semantics ----------


def test_override_replaces_default_for_same_cwe(tmp_path: Path) -> None:
    """File's CWE-89 ENTRY REPLACES the default — no within-CWE union."""
    p = tmp_path / "override.yaml"
    p.write_text(
        "CWE-89:\n  - my_company_sql_scanner\n",
        encoding="utf-8",
    )

    from kryon.learning.skill_evaluator import load_cwe_map_override

    result = load_cwe_map_override(path=p)
    # Default CWE-89 had nuclei_scan, sqlmap_scan, etc — all gone.
    assert result["CWE-89"] == {"my_company_sql_scanner"}


def test_unmentioned_cwes_keep_default_entries(tmp_path: Path) -> None:
    p = tmp_path / "override.yaml"
    p.write_text("CWE-89:\n  - x\n", encoding="utf-8")

    from kryon.learning.skill_evaluator import (
        _DEFAULT_CWE_TO_TOOLS,
        load_cwe_map_override,
    )

    result = load_cwe_map_override(path=p)
    # CWE-79 wasn't in the file → keeps default tools.
    assert result["CWE-79"] == _DEFAULT_CWE_TO_TOOLS["CWE-79"]


def test_new_cwes_in_file_extend_map(tmp_path: Path) -> None:
    p = tmp_path / "override.yaml"
    p.write_text(
        "CWE-9001:\n  - tool_a\n  - tool_b\n",
        encoding="utf-8",
    )

    from kryon.learning.skill_evaluator import load_cwe_map_override

    result = load_cwe_map_override(path=p)
    assert result["CWE-9001"] == {"tool_a", "tool_b"}


# ---------- Resilience ----------


def test_invalid_yaml_falls_back_to_default(tmp_path: Path) -> None:
    p = tmp_path / "broken.yaml"
    p.write_text("not: valid: yaml: at: all: [\n", encoding="utf-8")

    from kryon.learning.skill_evaluator import (
        _DEFAULT_CWE_TO_TOOLS,
        load_cwe_map_override,
    )

    # Should NOT raise; returns the default map untouched.
    result = load_cwe_map_override(path=p)
    for cwe in _DEFAULT_CWE_TO_TOOLS:
        assert cwe in result


def test_yaml_with_wrong_shape_falls_back(tmp_path: Path) -> None:
    """File parses but doesn't match dict[str, list[str]] shape."""
    p = tmp_path / "wrong_shape.yaml"
    p.write_text("- just\n- a\n- list\n", encoding="utf-8")

    from kryon.learning.skill_evaluator import (
        _DEFAULT_CWE_TO_TOOLS,
        load_cwe_map_override,
    )

    result = load_cwe_map_override(path=p)
    # Default still intact.
    for cwe in _DEFAULT_CWE_TO_TOOLS:
        assert cwe in result


def test_yaml_value_must_be_list(tmp_path: Path) -> None:
    """A CWE entry whose value isn't a list is silently skipped (default kept)."""
    p = tmp_path / "bad_entry.yaml"
    p.write_text(
        "CWE-89: not_a_list\n"
        "CWE-9999:\n  - good_tool\n",
        encoding="utf-8",
    )

    from kryon.learning.skill_evaluator import (
        _DEFAULT_CWE_TO_TOOLS,
        load_cwe_map_override,
    )

    result = load_cwe_map_override(path=p)
    # Bad entry skipped → CWE-89 still has defaults.
    assert result["CWE-89"] == _DEFAULT_CWE_TO_TOOLS["CWE-89"]
    # Good entry still loaded.
    assert result["CWE-9999"] == {"good_tool"}


def test_empty_yaml_returns_default(tmp_path: Path) -> None:
    p = tmp_path / "empty.yaml"
    p.write_text("", encoding="utf-8")

    from kryon.learning.skill_evaluator import (
        _DEFAULT_CWE_TO_TOOLS,
        load_cwe_map_override,
    )

    result = load_cwe_map_override(path=p)
    for cwe in _DEFAULT_CWE_TO_TOOLS:
        assert result[cwe] == _DEFAULT_CWE_TO_TOOLS[cwe]


# ---------- Integration with evaluate_draft_against_corpus ----------


def test_evaluator_auto_loads_override_when_no_explicit_map(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the caller passes cwe_to_tools=None, the evaluator looks
    for an override file. Custom tools listed there satisfy detection."""
    p = tmp_path / "custom.yaml"
    p.write_text(
        "CWE-CUSTOM-1:\n  - my_internal_tool\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("KRYON_CWE_MAP", str(p))

    from kryon.learning.pattern_detector import ChainCluster
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus
    from kryon.learning.skill_synthesizer import SkillDraft

    draft = SkillDraft(
        name="t",
        body="b",
        frontmatter={
            "name": "t",
            "description": "x",
            "triggers": {"tech": [], "ports": [], "keywords": []},
            "priority": 50,
            "required_tools": ["my_internal_tool"],
        },
    )
    cluster = ChainCluster(
        cluster_id="c1",
        member_experience_ids=("e1",),
        representative_chain=("my_internal_tool",),
        representative_profile={"tech": ["banking"]},
        sample_size=3,
        avg_outcome_score=1.0,
    )
    findings = [
        {"id": f"f{i}", "cwe_id": "CWE-CUSTOM-1", "tech_fingerprint": "banking"}
        for i in range(4)
    ]

    rep = evaluate_draft_against_corpus(
        draft=draft, cluster=cluster, findings=findings,
        min_findings_evaluated=3,
    )
    assert rep.eval_status == "passed"


def test_explicit_cwe_to_tools_arg_skips_file_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If caller passes cwe_to_tools=, file is NOT consulted (explicit wins)."""
    p = tmp_path / "should_not_load.yaml"
    p.write_text(
        "CWE-XYZ:\n  - file_tool\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("KRYON_CWE_MAP", str(p))

    from kryon.learning.pattern_detector import ChainCluster
    from kryon.learning.skill_evaluator import evaluate_draft_against_corpus
    from kryon.learning.skill_synthesizer import SkillDraft

    draft = SkillDraft(
        name="t",
        body="b",
        frontmatter={
            "name": "t",
            "description": "x",
            "triggers": {"tech": [], "ports": [], "keywords": []},
            "priority": 50,
            "required_tools": ["explicit_tool"],
        },
    )
    cluster = ChainCluster(
        cluster_id="c1",
        member_experience_ids=("e1",),
        representative_chain=("explicit_tool",),
        representative_profile={"tech": ["x"]},
        sample_size=3,
        avg_outcome_score=1.0,
    )
    findings = [
        {"id": f"f{i}", "cwe_id": "CWE-XYZ", "tech_fingerprint": "x"}
        for i in range(4)
    ]

    # Explicit map ONLY — file should not be consulted.
    rep = evaluate_draft_against_corpus(
        draft=draft, cluster=cluster, findings=findings,
        cwe_to_tools={"CWE-XYZ": {"explicit_tool"}},
        min_findings_evaluated=3,
    )
    # explicit_tool detects CWE-XYZ per the explicit map.
    assert rep.eval_status == "passed"
