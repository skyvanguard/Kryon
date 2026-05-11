"""TDD contract for skill_synthesizer.synthesize_from_cluster.

Frontmatter is 100% deterministic — derived from the cluster's modal
chain + union profile. Body is LLM-assisted when an `llm_caller` is
provided AND the output passes the tool-name validation gate; otherwise
falls back to the same templated body Fase 1 uses (adapted to clusters).
"""

from __future__ import annotations

from typing import Any, Callable

import pytest


def _cluster(
    *,
    cid: str = "cluster_test_001",
    chain: tuple[str, ...] = ("nmap", "whatweb", "nuclei_scan"),
    tech: list[str] | None = None,
    member_ids: tuple[str, ...] = ("e1", "e2", "e3"),
    avg_outcome: float = 0.83,
):
    """Build a ChainCluster without going through detect_recurrent_chains."""
    from kryon.learning.pattern_detector import ChainCluster

    return ChainCluster(
        cluster_id=cid,
        member_experience_ids=member_ids,
        representative_chain=chain,
        representative_profile={
            "tech": tech if tech is not None else ["wordpress"],
            "ports": [80, 443],
            "sample_hosts": ["alpha.example.com", "beta.example.com"],
        },
        sample_size=len(member_ids),
        avg_outcome_score=avg_outcome,
    )


# ---------- Without LLM (deterministic body) ----------


def test_returns_skill_draft_with_deterministic_body() -> None:
    from kryon.learning.skill_synthesizer import synthesize_from_cluster

    draft = synthesize_from_cluster(_cluster())
    assert draft is not None
    # Body must mention each tool from the chain.
    for tool in ("nmap", "whatweb", "nuclei_scan"):
        assert tool in draft.body


def test_frontmatter_required_tools_match_chain() -> None:
    from kryon.learning.skill_synthesizer import synthesize_from_cluster

    draft = synthesize_from_cluster(_cluster(chain=("recon", "exploit", "exfil")))
    assert set(draft.frontmatter["required_tools"]) == {"recon", "exploit", "exfil"}


def test_frontmatter_triggers_from_cluster_profile() -> None:
    from kryon.learning.skill_synthesizer import synthesize_from_cluster

    draft = synthesize_from_cluster(_cluster(tech=["wordpress", "php"]))
    triggers = draft.frontmatter["triggers"]
    assert set(triggers["tech"]) == {"wordpress", "php"}


def test_frontmatter_priority_is_drafts_tier() -> None:
    from kryon.learning.skill_synthesizer import synthesize_from_cluster

    draft = synthesize_from_cluster(_cluster())
    assert draft.frontmatter["priority"] == 50


def test_provenance_includes_cluster_id_and_members() -> None:
    from kryon.learning.skill_synthesizer import synthesize_from_cluster

    draft = synthesize_from_cluster(_cluster(cid="cluster_xyz", member_ids=("a", "b", "c", "d")))
    prov = draft.frontmatter["_provenance"]
    assert prov["cluster_id"] == "cluster_xyz"
    assert set(prov["member_experience_ids"]) == {"a", "b", "c", "d"}
    assert prov["sample_size"] == 4
    assert prov["source"] == "auto-cluster"


# ---------- With LLM ----------


def test_uses_llm_body_when_caller_returns_clean_output() -> None:
    """LLM output that mentions only valid tools is accepted as the body."""
    from kryon.learning.skill_synthesizer import synthesize_from_cluster

    def fake_llm(prompt: str) -> str:
        return "## Discovery\n\nUse `nmap` first, then chain `whatweb` and `nuclei_scan`.\nAlways respect rate limits."

    draft = synthesize_from_cluster(_cluster(), llm_caller=fake_llm)
    assert "Always respect rate limits" in draft.body


def test_falls_back_to_deterministic_body_when_llm_raises() -> None:
    from kryon.learning.skill_synthesizer import synthesize_from_cluster

    def boom(prompt: str) -> str:
        raise RuntimeError("ollama is offline")

    draft = synthesize_from_cluster(_cluster(), llm_caller=boom)
    # Deterministic body: still contains tool names + cluster context.
    assert draft is not None
    assert "nmap" in draft.body
    assert "whatweb" in draft.body


def test_falls_back_when_llm_returns_empty() -> None:
    from kryon.learning.skill_synthesizer import synthesize_from_cluster

    draft = synthesize_from_cluster(
        _cluster(),
        llm_caller=lambda _: "",
    )
    # Empty LLM output → deterministic fallback.
    assert "nmap" in draft.body


def test_rejects_llm_body_that_invents_unknown_tools() -> None:
    """Hallucinated tool names are an audit risk. Reject and fall back."""
    from kryon.learning.skill_synthesizer import synthesize_from_cluster

    def hallucinator(prompt: str) -> str:
        return "Use `nmap` first, then `MAGIC_HACKER_3000` to root the box. Finally `whatweb` for fingerprint."

    draft = synthesize_from_cluster(
        _cluster(chain=("nmap", "whatweb")),
        llm_caller=hallucinator,
    )
    # MAGIC_HACKER_3000 is not in required_tools → body falls back deterministic.
    assert "MAGIC_HACKER_3000" not in draft.body


def test_accepts_llm_body_that_only_uses_known_tools() -> None:
    from kryon.learning.skill_synthesizer import synthesize_from_cluster

    def smart(prompt: str) -> str:
        return "Step 1: nmap. Step 2: whatweb. Step 3: confirm with nuclei_scan."

    draft = synthesize_from_cluster(
        _cluster(chain=("nmap", "whatweb", "nuclei_scan")),
        llm_caller=smart,
    )
    assert "Step 1: nmap" in draft.body


# ---------- Naming ----------


def test_name_includes_tech_and_auto_marker() -> None:
    from kryon.learning.skill_synthesizer import synthesize_from_cluster

    draft = synthesize_from_cluster(_cluster(tech=["wordpress"]))
    assert "wordpress" in draft.name.lower()
    assert "auto" in draft.name.lower()


def test_name_avoids_collision_with_existing() -> None:
    from kryon.learning.skill_synthesizer import synthesize_from_cluster

    d1 = synthesize_from_cluster(_cluster(cid="c1", tech=["wp"]))
    d2 = synthesize_from_cluster(
        _cluster(cid="c2", tech=["wp"]),
        existing_names={d1.name},
    )
    assert d1.name != d2.name


def test_name_is_filesystem_safe() -> None:
    from kryon.learning.skill_synthesizer import synthesize_from_cluster

    draft = synthesize_from_cluster(_cluster(tech=["WordPress", "PHP/7.4"]))
    assert " " not in draft.name
    assert "/" not in draft.name
    assert draft.name == draft.name.lower()


# ---------- Round-trip ----------


def test_to_markdown_loads_back_via_skill_loader(tmp_path) -> None:
    from kryon.learning.skill_synthesizer import synthesize_from_cluster
    from kryon.skills.loader import _parse_skill_file

    draft = synthesize_from_cluster(_cluster())
    path = tmp_path / f"{draft.name}.md"
    path.write_text(draft.to_markdown(), encoding="utf-8")

    skill = _parse_skill_file(path)
    assert skill is not None
    assert skill.name == draft.name
    assert skill.priority == 50
    # Tools roundtrip
    assert "nmap" in skill.required_tools
    assert "nuclei_scan" in skill.required_tools


# ---------- LLM prompt construction ----------


def test_llm_caller_receives_cluster_context_in_prompt() -> None:
    """The LLM gets enough info about the cluster to write a useful body."""
    from kryon.learning.skill_synthesizer import synthesize_from_cluster

    captured: list[str] = []

    def capture(prompt: str) -> str:
        captured.append(prompt)
        return ""

    synthesize_from_cluster(
        _cluster(chain=("nmap", "whatweb"), tech=["wordpress"]),
        llm_caller=capture,
    )
    assert len(captured) == 1
    prompt = captured[0]
    # Tools mentioned in prompt
    assert "nmap" in prompt
    assert "whatweb" in prompt
    # Tech mentioned
    assert "wordpress" in prompt.lower()
