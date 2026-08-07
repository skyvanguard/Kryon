"""F77.G.6 — Loader for merge-decider input.

Filesystem-bounded tests: write fixture drafts to tmp_path, then call
`load_existing_for_merge` and assert the resulting ExistingSkill list.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from kryon.learning.merge_loader import (
    _split_name_and_version,
    load_existing_for_merge,
    parse_skill_signature,
)


def _write_draft(
    path: Path,
    *,
    name: str,
    chain: list[str] | None = None,
    tech: list[str] | None = None,
    include_provenance: bool = True,
) -> Path:
    """Write a minimal valid draft frontmatter + body. Used to exercise
    parse_skill_signature without depending on the synthesizer."""
    provenance: dict = {}
    if include_provenance:
        provenance = {
            "cluster_id": "cluster_test",
            "representative_chain": chain or ["nmap", "whatweb"],
            "representative_tech": tech or ["wordpress"],
        }
    fm = {
        "name": name,
        "description": "fixture",
        "triggers": {"tech": tech or [], "ports": [], "keywords": []},
        "priority": 50,
        "required_tools": chain or [],
    }
    if include_provenance:
        fm["_provenance"] = provenance
    path.parent.mkdir(parents=True, exist_ok=True)
    md = f"---\n{yaml.safe_dump(fm, sort_keys=False)}---\n\n# {name}\n\nFixture body."
    path.write_text(md, encoding="utf-8")
    return path


# =====================================================================
# _split_name_and_version
# =====================================================================


def test_split_versionless_name():
    assert _split_name_and_version("pci-dss-audit") == ("pci-dss-audit", 1)


def test_split_versioned_name():
    assert _split_name_and_version("pci-dss-audit.v3") == ("pci-dss-audit", 3)
    assert _split_name_and_version("pci-dss-audit.v10") == ("pci-dss-audit", 10)


def test_split_does_not_treat_non_numeric_suffix_as_version():
    """'audit.vendor' must NOT be parsed as 'audit' v vendor."""
    assert _split_name_and_version("audit.vendor") == ("audit.vendor", 1)


# =====================================================================
# parse_skill_signature
# =====================================================================


def test_parses_valid_draft(tmp_path):
    path = _write_draft(
        tmp_path / "auto_skill.md",
        name="auto_skill",
        chain=["nmap", "whatweb", "sqlmap"],
        tech=["wordpress"],
    )
    sig = parse_skill_signature(path)
    assert sig is not None
    assert sig.name == "auto_skill"
    assert sig.version == 1
    assert sig.representative_chain == ("nmap", "whatweb", "sqlmap")
    assert sig.tech == ("wordpress",)


def test_parses_versioned_draft(tmp_path):
    path = _write_draft(
        tmp_path / "pci-dss-audit.v3.md",
        name="pci-dss-audit.v3",
        chain=["compliance", "report"],
        tech=["linux"],
    )
    sig = parse_skill_signature(path)
    assert sig is not None
    assert sig.name == "pci-dss-audit"
    assert sig.version == 3


def test_skips_draft_without_provenance(tmp_path):
    """Hand-edited drafts that strip _provenance must NOT be picked up
    by the decider — the operator owns them."""
    path = _write_draft(
        tmp_path / "manual.md",
        name="manual",
        include_provenance=False,
    )
    assert parse_skill_signature(path) is None


def test_skips_draft_without_frontmatter(tmp_path):
    """A markdown file without YAML frontmatter is silently ignored."""
    path = tmp_path / "no_frontmatter.md"
    path.write_text("# Just a body, no frontmatter.\n", encoding="utf-8")
    assert parse_skill_signature(path) is None


def test_skips_malformed_frontmatter(tmp_path):
    path = tmp_path / "broken.md"
    path.write_text("---\n: malformed [yaml\n---\n\nbody", encoding="utf-8")
    assert parse_skill_signature(path) is None


def test_skips_unreadable_file(tmp_path):
    """An unreadable file should not crash the loader. We simulate via
    a nonexistent path."""
    assert parse_skill_signature(tmp_path / "does_not_exist.md") is None


def test_falls_back_to_triggers_tech_when_provenance_tech_missing(tmp_path):
    """Older drafts may have only triggers.tech, no representative_tech.
    The loader must read the fallback."""
    fm = {
        "name": "old_draft",
        "description": "x",
        "triggers": {"tech": ["legacy_tech"], "ports": [], "keywords": []},
        "_provenance": {
            "cluster_id": "x",
            "representative_chain": ["nmap"],
            # representative_tech intentionally absent
        },
    }
    path = tmp_path / "old.md"
    path.write_text(f"---\n{yaml.safe_dump(fm)}---\n\nbody", encoding="utf-8")
    sig = parse_skill_signature(path)
    assert sig is not None
    assert sig.tech == ("legacy_tech",)


# =====================================================================
# load_existing_for_merge — directory scanning
# =====================================================================


def test_load_empty_root_returns_empty(tmp_path):
    """No drafts dir → empty list, no crash. Cold start."""
    assert load_existing_for_merge(tmp_path / "nonexistent") == []


def test_load_scans_all_subdirs(tmp_path):
    _write_draft(tmp_path / "_auto" / "a.md", name="a")
    _write_draft(tmp_path / "_rejected" / "b.md", name="b")
    _write_draft(tmp_path / "c.md", name="c")
    existing = load_existing_for_merge(tmp_path)
    names = {e.name for e in existing}
    assert names == {"a", "b", "c"}


def test_load_dedupes_by_base_keeping_highest_version(tmp_path):
    """Same base appears in multiple locations → highest version wins."""
    _write_draft(tmp_path / "_auto" / "pci-dss-audit.md", name="pci-dss-audit")
    _write_draft(
        tmp_path / "pci-dss-audit.v3.md",
        name="pci-dss-audit.v3",
        chain=["new_chain"],
    )
    existing = load_existing_for_merge(tmp_path)
    assert len(existing) == 1
    assert existing[0].name == "pci-dss-audit"
    assert existing[0].version == 3
    assert existing[0].representative_chain == ("new_chain",)


def test_load_silently_skips_drafts_without_provenance(tmp_path):
    """A draft without _provenance still co-exists with valid drafts;
    the loader returns the valid ones and skips the rest."""
    _write_draft(tmp_path / "good.md", name="good")
    _write_draft(tmp_path / "manual.md", name="manual", include_provenance=False)
    existing = load_existing_for_merge(tmp_path)
    assert {e.name for e in existing} == {"good"}
