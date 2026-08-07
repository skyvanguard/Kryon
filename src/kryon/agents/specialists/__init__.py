"""Focused sub-agent specialists, delegated to via Agent.as_tool().

The unified Kryon agent stays the orchestrator and DELEGATES well-scoped
sub-tasks to these specialists (the agent-as-tool pattern, like Claude Code's
Task tool): each runs its own loop in ISOLATED context with a tight prompt +
narrow toolset and returns only its distilled result. This keeps the
orchestrator's context clean (the specialist's noisy exploration can't pollute
it) and avoids one monolithic master prompt — WITHOUT reintroducing the removed
33 legacy per-name agents. Start small (SAST) and add specialists only when a
bench shows they help.
"""

from kryon.agents.specialists.sast_agent import create_sast_specialist, sast_review_tool

__all__ = ["create_sast_specialist", "sast_review_tool"]
