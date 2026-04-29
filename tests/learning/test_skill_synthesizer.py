"""TDD contract for kryon.learning.skill_synthesizer.

Pure tests — no LLM, no DB. The synthesizer turns one engagement
experience into a draft markdown skill ready for human review.
"""

from __future__ import annotations

from typing import Any

import pytest


# ---------- Helpers ----------


def _experience(
    *,
    outcome: str = "success",
    tech: list[str] | None = None,
    ports: list[int] | None = None,
    chain: list[dict[str, Any]] | None = None,
    host: str = "victim.example.com",
) -> dict:
    """Build a complete experience dict matching what add_experience consumes."""
    return {
        "id": "eng_test_abc",
        "created_at": "2026-04-28T17:00:00+00:00",
        "target_profile": {
            "host": host,
            "resolved_ip": "10.0.0.1",
            "ports": ports if ports is not None else [22, 80, 443],
            "services": {"80": "http", "443": "https"},
            "tech": tech if tech is not None else ["wordpress", "nginx"],
            "os_hint": "linux",
        },
        "chain": chain if chain is not None else [
            {"tool": "nmap", "args": "-sV", "status": "ok", "output": "open: 80,443"},
            {"tool": "whatweb", "args": "https://x", "status": "ok", "output": "wp"},
            {"tool": "nuclei_scan", "args": "x", "status": "ok", "output": "1 finding"},
        ],
        "outcome": outcome,
        "outcome_signals": {
            "shell_gained": outcome == "success",
            "directories_found": 5,
            "cve_confirmed": ["CVE-2023-1234"] if outcome != "fail" else [],
        },
        "agent_path": ["recon-scout"],
        "duration_s": 240,
        "summary": f"audit {host} → {outcome}",
    }


# ---------- Outcome filter ----------


def test_recon_only_outcome_returns_none() -> None:
    """A pure-recon engagement has no actionable pattern to encode."""
    from kryon.learning.skill_synthesizer import synthesize_draft

    assert synthesize_draft(_experience(outcome="recon-only")) is None


def test_fail_outcome_returns_none() -> None:
    from kryon.learning.skill_synthesizer import synthesize_draft

    assert synthesize_draft(_experience(outcome="fail")) is None


def test_success_outcome_yields_draft() -> None:
    from kryon.learning.skill_synthesizer import synthesize_draft

    draft = synthesize_draft(_experience(outcome="success"))
    assert draft is not None


def test_partial_outcome_yields_draft() -> None:
    from kryon.learning.skill_synthesizer import synthesize_draft

    draft = synthesize_draft(_experience(outcome="partial"))
    assert draft is not None


def test_min_outcome_can_be_tightened_to_success_only() -> None:
    """Operator may want stricter quality bar — drafts only on success."""
    from kryon.learning.skill_synthesizer import synthesize_draft

    assert synthesize_draft(_experience(outcome="partial"), min_outcome="success") is None
    assert synthesize_draft(_experience(outcome="success"), min_outcome="success") is not None


# ---------- Chain quality filter ----------


def test_empty_chain_returns_none_even_on_success() -> None:
    """Without tool calls there's nothing worth encoding."""
    from kryon.learning.skill_synthesizer import synthesize_draft

    assert synthesize_draft(_experience(chain=[])) is None


def test_single_tool_chain_returns_none() -> None:
    """One tool call doesn't demonstrate a pattern. Need >= 2 to draft."""
    from kryon.learning.skill_synthesizer import synthesize_draft

    chain = [{"tool": "nmap", "args": "x", "status": "ok", "output": "open"}]
    assert synthesize_draft(_experience(chain=chain)) is None


# ---------- Naming ----------


def test_draft_name_includes_tech_and_draft_marker() -> None:
    from kryon.learning.skill_synthesizer import synthesize_draft

    draft = synthesize_draft(_experience(tech=["wordpress"]))
    assert draft is not None
    assert "wordpress" in draft.name.lower()
    assert "draft" in draft.name.lower()


def test_draft_name_falls_back_when_no_tech() -> None:
    """No tech detected → use a generic prefix so the operator can rename."""
    from kryon.learning.skill_synthesizer import synthesize_draft

    draft = synthesize_draft(_experience(tech=[]))
    assert draft is not None
    assert "draft" in draft.name.lower()


def test_draft_name_is_kebab_case_filesystem_safe() -> None:
    from kryon.learning.skill_synthesizer import synthesize_draft

    draft = synthesize_draft(_experience(tech=["WordPress", "OpenSSH"]))
    assert draft is not None
    # No spaces, no slashes, no upper case.
    assert " " not in draft.name
    assert "/" not in draft.name
    assert draft.name == draft.name.lower()


# ---------- Frontmatter ----------


def test_frontmatter_includes_provenance() -> None:
    from kryon.learning.skill_synthesizer import synthesize_draft

    exp = _experience()
    draft = synthesize_draft(exp)
    assert draft is not None
    prov = draft.frontmatter.get("_provenance")
    assert isinstance(prov, dict)
    assert prov["experience_id"] == "eng_test_abc"
    assert "synthesized_at" in prov
    assert prov["chain_len"] == 3
    assert prov["outcome"] == "success"


def test_frontmatter_triggers_use_profile_tech_and_ports() -> None:
    from kryon.learning.skill_synthesizer import synthesize_draft

    draft = synthesize_draft(_experience(
        tech=["wordpress", "php"], ports=[80, 443, 8080],
    ))
    assert draft is not None
    triggers = draft.frontmatter["triggers"]
    assert set(triggers["tech"]) == {"wordpress", "php"}
    # Ports preserved (within reason — cap exists)
    assert 80 in triggers["ports"]
    assert 443 in triggers["ports"]


def test_frontmatter_priority_is_intermediate() -> None:
    """Drafts ship at priority 50 — between generic (10-12) and core
    domain skills. Operator can hand-edit when promoting."""
    from kryon.learning.skill_synthesizer import synthesize_draft

    draft = synthesize_draft(_experience())
    assert draft is not None
    assert draft.frontmatter["priority"] == 50


def test_frontmatter_required_tools_subset_of_chain() -> None:
    """The draft only requires tools that actually appeared in the chain."""
    from kryon.learning.skill_synthesizer import synthesize_draft

    draft = synthesize_draft(_experience(chain=[
        {"tool": "nmap", "args": "", "status": "ok", "output": ""},
        {"tool": "nuclei_scan", "args": "", "status": "ok", "output": ""},
    ]))
    assert draft is not None
    required = set(draft.frontmatter["required_tools"])
    assert {"nmap", "nuclei_scan"} <= required


def test_frontmatter_caps_ports_to_avoid_overmatching() -> None:
    """If profile has 30 ports, don't blast all of them as triggers."""
    from kryon.learning.skill_synthesizer import synthesize_draft

    draft = synthesize_draft(_experience(ports=list(range(8000, 8030))))
    assert draft is not None
    assert len(draft.frontmatter["triggers"]["ports"]) <= 5


# ---------- Body ----------


def test_body_describes_phases_from_chain() -> None:
    from kryon.learning.skill_synthesizer import synthesize_draft

    draft = synthesize_draft(_experience())
    assert draft is not None
    # Body mentions each tool in chain order
    assert "nmap" in draft.body
    assert "whatweb" in draft.body
    assert "nuclei_scan" in draft.body


def test_body_mentions_target_class_and_outcome() -> None:
    from kryon.learning.skill_synthesizer import synthesize_draft

    draft = synthesize_draft(_experience(outcome="success", tech=["wordpress"]))
    assert draft is not None
    assert "wordpress" in draft.body.lower()
    # Outcome should be referenced so the human reviewer knows why it qualified.
    assert "success" in draft.body.lower()


# ---------- Markdown output ----------


def test_to_markdown_starts_with_frontmatter_delimiter() -> None:
    from kryon.learning.skill_synthesizer import synthesize_draft

    draft = synthesize_draft(_experience())
    assert draft is not None
    md = draft.to_markdown()
    assert md.startswith("---\n")
    # YAML block closes before body.
    assert "\n---\n" in md[4:]


def test_to_markdown_is_round_trippable_by_skill_loader(tmp_path) -> None:
    """The crucial integration: the draft must parse correctly with the
    same loader Kryon uses for production skills."""
    from kryon.learning.skill_synthesizer import synthesize_draft
    from kryon.skills.loader import _parse_skill_file

    draft = synthesize_draft(_experience())
    assert draft is not None

    md_path = tmp_path / f"{draft.name}.md"
    md_path.write_text(draft.to_markdown(), encoding="utf-8")

    loaded = _parse_skill_file(md_path)
    assert loaded is not None
    assert loaded.name == draft.name
    assert loaded.priority == 50
    # Tool names from the chain became required_tools
    assert "nmap" in loaded.required_tools


# ---------- Counter / uniqueness ----------


def test_two_drafts_from_same_profile_get_distinct_names(tmp_path) -> None:
    """If the operator already promoted v1 of a draft, v2 from a fresh
    engagement shouldn't collide. Caller passes existing_names to bump."""
    from kryon.learning.skill_synthesizer import synthesize_draft

    d1 = synthesize_draft(_experience(tech=["wordpress"]))
    assert d1 is not None
    d2 = synthesize_draft(
        _experience(tech=["wordpress"]),
        existing_names={d1.name},
    )
    assert d2 is not None
    assert d2.name != d1.name
