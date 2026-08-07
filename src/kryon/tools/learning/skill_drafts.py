"""Skill-draft tools (agentic gap #5) — the self-improvement loop, agent-facing.

Kryon's learning loop auto-writes a skill draft to ``~/.kryon/drafts/`` after a
successful engagement (F1). Promoting one was only possible via ``/skill
promote`` (a human operator command). These tools expose the read + promote
steps so the agent can close its own learning loop: see what it learned, and
stage the drafts worth keeping.

Safety: promotion writes to ``playbooks/_drafts/`` (staging), NOT the live
catalog — the operator still reviews before a skill ships. Draft names are
validated by ``draft_writer`` (path-traversal-guarded) and the write target is
re-checked here. Read-only listing is always safe.
"""

from __future__ import annotations

import re
from pathlib import Path

from kryon.sdk.agents import function_tool


def _staging_dir() -> Path:
    """playbooks/_drafts/ — where promoted drafts land for operator review."""
    import kryon.skills.loader as _loader

    return Path(_loader.__file__).resolve().parent / "playbooks" / "_drafts"


def _summary(content: str) -> str:
    """Pull a one-line summary from a draft (frontmatter description or 1st line)."""
    m = re.search(r'^description:\s*"?(.+?)"?\s*$', content, re.MULTILINE)
    if m:
        return m.group(1).strip()[:140]
    for ln in content.splitlines():
        s = ln.strip()
        if s and not s.startswith("---") and not s.startswith("#"):
            return s[:140]
    return "(no summary)"


def _list_impl() -> str:
    from kryon.learning.draft_writer import list_existing_names, read_draft

    names = sorted(list_existing_names())
    if not names:
        return "No skill drafts yet. Kryon auto-synthesizes them after successful engagements."
    lines = [f"# {len(names)} skill draft(s) awaiting review (~/.kryon/drafts/)", ""]
    for n in names:
        lines.append(f"- **{n}** — {_summary(read_draft(n) or '')}")
    lines.append("")
    lines.append("_Promote a good one with promote_skill_draft(name); it lands in staging for review._")
    return "\n".join(lines)


def _promote_impl(name: str) -> str:
    from kryon.learning.draft_writer import delete_draft, read_draft

    content = read_draft(name)
    if content is None:
        return f"No draft named '{name}' (list them with list_skill_drafts)."

    staging = _staging_dir()
    staging.mkdir(parents=True, exist_ok=True)
    target = (staging / f"{name}.md").resolve()
    # Defense-in-depth: draft_writer already rejects unsafe names, but ensure the
    # write target can't escape the staging dir.
    try:
        target.relative_to(staging.resolve())
    except ValueError:
        return f"Refusing unsafe draft name: {name}"
    if target.exists():
        return f"'{name}' is already promoted (staging: {target}). Discard/rename first to re-promote."

    target.write_text(content, encoding="utf-8")
    delete_draft(name)
    return (
        f"Promoted '{name}' to staging: {target}\n"
        "It is NOT live yet — the operator reviews staged drafts before they ship."
    )


@function_tool
def list_skill_drafts() -> str:
    """List the skill drafts Kryon auto-synthesized from past engagements.

    Use this to see what Kryon has *learned* — after a successful hunt/audit it
    writes a reusable skill draft. Returns each draft's name + one-line summary.
    Read-only. Promote the good ones with promote_skill_draft.
    """
    return _list_impl()


@function_tool
def promote_skill_draft(name: str) -> str:
    """Promote an auto-synthesized skill draft to the staging catalog.

    Use this when a draft (from list_skill_drafts) is worth keeping — it moves
    the draft into playbooks/_drafts/ for the operator to review. It does NOT go
    live automatically; a human still approves before it ships.

    Args:
        name: The draft name (without .md), as shown by list_skill_drafts.
    """
    return _promote_impl(name)
