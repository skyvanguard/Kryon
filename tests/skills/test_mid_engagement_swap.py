"""F85.D — Mid-engagement skill swap.

`kryon engage` builds the agent before nmap discovery has run, so the
initial skill set is whatever recon-scout / generic playbooks the
loader picks with no target profile. After Phase 1 detects device
families (proxmox, fortigate, linux, windows_ad), the orchestrator
should re-rank skills against that profile and hot-swap them on the
agent before Phase 2c invokes the LLM.

These tests assert that:

  - ``SkillLoader.match(profile={"tech": ["fortigate"]})`` returns
    fortigate-audit ranked above recon-scout (priority 10 < 12).
  - ``update_agent_skills(agent, new_skills)`` mutates the agent
    in-place — its ``tools``, ``instructions`` and ``_active_skills``
    attrs update without resetting conversation history.
  - The combined flow (engage helper invocation) is non-fatal when
    skill matching raises; the engagement continues with the original
    skill set.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


def test_match_fortigate_profile_prefers_fortigate_audit():
    """When the operator passes a FortiGate target profile, the
    fortigate-audit skill (priority 10, tech=['fortigate']) must
    rank above recon-scout (priority 12, tech=[])."""
    from kryon.skills.loader import SkillLoader

    loader = SkillLoader()
    skills = loader.match(profile={"tech": ["fortigate"]}, user_msg="fortigate audit")

    # We don't assert exact contents because the playbook set may grow,
    # but fortigate-audit must appear and must be ranked at-or-above
    # the generic recon-scout when both are in the result set.
    names = [s.name for s in skills]
    assert "fortigate-audit" in names, f"expected fortigate-audit in {names}"

    if "recon-scout" in names:
        fgt_idx = names.index("fortigate-audit")
        rec_idx = names.index("recon-scout")
        assert fgt_idx < rec_idx, (
            f"fortigate-audit ({fgt_idx}) should rank above recon-scout ({rec_idx}); full order: {names}"
        )


def test_match_proxmox_profile_pulls_proxmox_audit():
    """Detected Proxmox VE family should surface proxmox-audit.md."""
    from kryon.skills.loader import SkillLoader

    loader = SkillLoader()
    skills = loader.match(profile={"tech": ["proxmox"]}, user_msg="proxmox audit")

    names = [s.name for s in skills]
    assert "proxmox-audit" in names, f"expected proxmox-audit in {names}"


def test_match_with_generic_intent_returns_skills():
    """A generic intent string should still return a usable skill set
    (the base playbooks with empty triggers always match plus any
    keyword-triggered playbooks that the intent fires)."""
    from kryon.skills.loader import SkillLoader

    loader = SkillLoader()
    skills = loader.match(profile={}, user_msg="audit this network")

    # The "always-match" base skills (those with empty triggers) must
    # surface even when neither profile nor keyword hints fire.
    assert len(skills) > 0


def test_update_agent_skills_preserves_history():
    """Hot-swap must mutate ``instructions``, ``tools``, and
    ``_active_skills`` in-place — conversation_history (if present)
    is left alone so the agent can continue mid-conversation."""
    from kryon.skills.unified_agent import update_agent_skills

    # Minimal stub agent — only the attrs update_agent_skills touches.
    agent = MagicMock()
    agent.instructions = "OLD INSTRUCTIONS"
    agent.tools = ["old_tool_1", "old_tool_2"]
    agent.conversation_history = ["msg1", "msg2"]  # MUST NOT be touched
    agent._skill_loader = None

    # Build a fake skill that won't pull in real tools
    fake_skill = MagicMock()
    fake_skill.name = "fake-skill"
    fake_skill.body = "Do the thing."
    fake_skill.required_tools = []

    update_agent_skills(agent, [fake_skill])

    assert agent.instructions != "OLD INSTRUCTIONS"
    assert "fake-skill" in agent.instructions
    # _active_skills must reflect the swap
    assert agent._active_skills == [fake_skill]
    # conversation_history is untouched
    assert agent.conversation_history == ["msg1", "msg2"]


def test_engage_helper_falls_back_when_swap_fails(monkeypatch):
    """If `update_agent_skills` raises mid-engagement, the helper logs
    the failure and continues with whatever skill set the agent was
    built with — the engagement must NOT crash."""
    import kryon.cli.engage as engage_mod

    # Make the agent loader return a stub. We use a plain object
    # (not MagicMock) because MagicMock auto-creates ``_skill_loader``
    # as a truthy mock, which short-circuits the SkillLoader() branch
    # in update_agent_skills.
    class _FakeAgent:
        tools = []
        instructions = "base"
        _skill_loader = None

    fake_agent = _FakeAgent()

    fake_loader = MagicMock()
    # Raise when match() is called so we exercise the except branch
    fake_loader.match.side_effect = RuntimeError("loader exploded")

    monkeypatch.setattr(
        "kryon.agents.get_agent_by_name",
        lambda *_a, **_kw: fake_agent,
    )
    monkeypatch.setattr(
        "kryon.skills.loader.SkillLoader",
        lambda: fake_loader,
    )

    # Stub Runner.run so we don't actually call an LLM
    async def fake_run(*_a, **_kw):
        return MagicMock(final_output="")

    monkeypatch.setattr(
        "kryon.sdk.agents.run.Runner.run",
        fake_run,
    )

    console = MagicMock()
    obs, findings = engage_mod._invoke_agent_deepening(
        console,
        target="1.2.3.4",
        scope="1.2.3.4",
        findings=[],
        families=["fortigate"],
    )

    # No crash; deepening returned empty payloads. The "skipped"
    # message must have been printed via console.print.
    assert obs == [] or isinstance(obs, list)
    assert isinstance(findings, list)
    # Confirm we hit the swap-failure path
    printed_args = [c.args[0] for c in console.print.call_args_list if c.args]
    assert any("skill swap skipped" in str(a) for a in printed_args), f"expected swap-skipped log; got: {printed_args}"
