"""Skill synthesizer — turn one engagement experience into a draft skill.

Output is a markdown file (frontmatter + body) ready for human review
in `~/.kryon/drafts/`. The operator can promote it to `playbooks/_drafts/`
via `/skill promote <name>` once they've validated the content.

Design choices:
  * Pure templating — no LLM in v1. The chain + profile + outcome are
    already structured; we just shape them into the standard skill
    layout. LLM-assisted body refinement is reserved for Fase 3.
  * Conservative quality bar: only `success` and `partial` outcomes
    qualify, and only chains with >= 2 tool calls. Below that there's
    nothing distinctive to encode.
  * Filesystem-safe kebab-case names with a counter to avoid collisions
    when the same operator runs the same target class repeatedly.
  * Provenance tracked in frontmatter (`_provenance: {experience_id, ...}`)
    so a draft can always be traced back to the engagement that created it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import yaml


# Ordering of outcome quality. `success` is the strongest signal; `fail`
# carries no actionable pattern.
_OUTCOME_RANK = {
    "fail": 0,
    "recon-only": 1,
    "partial": 2,
    "success": 3,
}

# Default acceptance threshold: a `partial` engagement with CVE confirmation
# or directories found is still worth proposing as a draft.
_DEFAULT_MIN_OUTCOME = "partial"

# Don't drown the loader's matching with every port the target exposed.
_MAX_TRIGGER_PORTS = 5

# A chain shorter than this is too thin to encode as a reusable pattern.
_MIN_CHAIN_LEN = 2


@dataclass(frozen=True)
class SkillDraft:
    """A draft skill ready for review. Immutable so consumers can pass it
    around without worrying about mid-flight mutation."""

    name: str
    body: str
    frontmatter: dict[str, Any] = field(default_factory=dict)

    def to_markdown(self) -> str:
        """Serialize as the standard `---\\nyaml\\n---\\nbody` shape that
        `kryon.skills.loader` parses for production skills."""
        # `default_flow_style=False` → block style (the same shape every
        # other skill in the repo uses).
        yaml_block = yaml.safe_dump(
            self.frontmatter,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        ).rstrip()
        return f"---\n{yaml_block}\n---\n\n{self.body.rstrip()}\n"


def _slugify(token: str) -> str:
    """Lowercase, kebab-case, alphanum-or-dash only."""
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", token).strip("-").lower()
    return cleaned or "x"


def _derive_name(
    profile: dict[str, Any],
    outcome: str,
    existing_names: set[str],
) -> str:
    """Build a kebab-case name unique within `existing_names`.

    Pattern: <primary_tech>-<outcome>-draft-NNN. With no tech detected
    we fall back to `auto-pattern-<outcome>-draft-NNN`.
    """
    tech_list = profile.get("tech") or []
    primary = _slugify(tech_list[0]) if tech_list else "auto-pattern"
    outcome_slug = _slugify(outcome)
    base = f"{primary}-{outcome_slug}-draft"

    # Counter starts at 001 and bumps until we find a free slot.
    for n in range(1, 1000):
        candidate = f"{base}-{n:03d}"
        if candidate not in existing_names:
            return candidate
    # If we somehow have 999 collisions, append the timestamp microseconds
    # so we can never deadlock on naming.
    return f"{base}-{int(datetime.now().timestamp())}"


def _build_required_tools(chain: list[dict[str, Any]]) -> list[str]:
    """Extract unique tool names from the chain in first-seen order."""
    seen: list[str] = []
    for step in chain:
        name = (step.get("tool") or "").strip()
        if name and name not in seen:
            seen.append(name)
    return seen


def _build_keywords(profile: dict[str, Any], outcome: str) -> list[str]:
    """Trigger keywords — tech names + the outcome word so a human
    searching `/skill list` can find the draft via "wordpress" or "rce"."""
    tech_list = [t.lower() for t in (profile.get("tech") or []) if t]
    kws: list[str] = []
    kws.extend(tech_list[:5])
    kws.append(outcome)
    if profile.get("os_hint"):
        kws.append(profile["os_hint"])
    # De-dup, preserve order
    seen = set()
    out: list[str] = []
    for k in kws:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def _build_body(
    experience: dict[str, Any],
    profile: dict[str, Any],
    chain: list[dict[str, Any]],
    outcome: str,
) -> str:
    """Compose a markdown body that walks through the recorded engagement.

    The shape mirrors how `recon-scout` and other production skills are
    structured: short header, target classification, ordered phases, exit
    criteria. The reviewer will inevitably edit it — the goal is to give
    them a complete starting point, not a finished playbook.
    """
    tech_list = profile.get("tech") or []
    tech_blurb = ", ".join(tech_list[:3]) if tech_list else "general targets"
    host = profile.get("host") or "(unspecified host)"
    duration = experience.get("duration_s", 0)
    summary = experience.get("summary") or ""
    signals = experience.get("outcome_signals") or {}

    # Per-tool phase block
    phase_lines: list[str] = []
    for idx, step in enumerate(chain, start=1):
        tool = step.get("tool") or "(unknown)"
        args = (step.get("args") or "").strip()
        status = step.get("status") or "ok"
        args_blurb = f" args=`{args[:80]}`" if args and args != "{}" else ""
        phase_lines.append(
            f"{idx}. **{tool}**{args_blurb} — {status}"
        )

    signal_lines: list[str] = []
    if signals.get("shell_gained"):
        signal_lines.append("- Shell gained ✓")
    if signals.get("flag_found"):
        signal_lines.append("- Flag found ✓")
    cves = signals.get("cve_confirmed") or []
    if cves:
        signal_lines.append(f"- CVEs confirmed: {', '.join(cves)}")
    dirs = signals.get("directories_found") or 0
    if dirs:
        signal_lines.append(f"- {dirs} directories discovered")

    signals_block = "\n".join(signal_lines) if signal_lines else "_(no extracted signals)_"

    return f"""\
> **DRAFT — auto-synthesized from experience.** Review before promoting to
> production. Adjust the chain, error handling, and stop conditions to
> match the target class you actually want this skill to cover.

## Target class

This pattern emerged from auditing **{tech_blurb}** targets. Reference
engagement: `{host}` (duration {duration}s, outcome **{outcome}**).

> {summary}

## Recommended phases

{chr(10).join(phase_lines)}

## Signals observed in the source engagement

{signals_block}

## What the reviewer should check before promoting

- [ ] Tools listed in `required_tools` are still desired (drop any noisy ones).
- [ ] Triggers (tech / ports / keywords) match the target class — not just
      the single host that produced this draft.
- [ ] Body explains *why* each phase runs in the order shown.
- [ ] Stop conditions are explicit (when to bail, what counts as done).
- [ ] No leakage of client-specific identifiers (hosts, IPs, creds).
"""


def synthesize_draft(
    experience: dict[str, Any],
    profile: dict[str, Any] | None = None,
    *,
    min_outcome: str = _DEFAULT_MIN_OUTCOME,
    existing_names: set[str] | None = None,
) -> SkillDraft | None:
    """Turn one engagement into a candidate skill draft.

    Returns:
        SkillDraft when the engagement clears the quality bar, else None.

    Quality bar:
      - outcome rank >= rank(min_outcome)
      - chain length >= 2 tool calls
      - profile or experience must yield SOME tech/host signal (otherwise
        the draft has nothing to trigger on).

    The caller is responsible for:
      - Persisting the markdown (use `draft.to_markdown()`).
      - Ensuring `existing_names` covers what's already on disk so the
        counter doesn't collide.
    """
    outcome = experience.get("outcome", "fail")
    if _OUTCOME_RANK.get(outcome, -1) < _OUTCOME_RANK.get(min_outcome, 99):
        return None

    chain = experience.get("chain") or []
    if len(chain) < _MIN_CHAIN_LEN:
        return None

    # Use the explicit profile if provided, else fall back to the one
    # baked into the experience record.
    effective_profile = profile or experience.get("target_profile") or {}

    name = _derive_name(effective_profile, outcome, existing_names or set())
    description = (experience.get("summary") or f"Auto-synthesized from {outcome} engagement").strip()
    description = description[:200]  # keep frontmatter line bounded

    triggers: dict[str, Any] = {
        "tech": list(effective_profile.get("tech") or []),
        "ports": list((effective_profile.get("ports") or [])[:_MAX_TRIGGER_PORTS]),
        "keywords": _build_keywords(effective_profile, outcome),
    }

    required_tools = _build_required_tools(chain)

    provenance = {
        "experience_id": experience.get("id", ""),
        "synthesized_at": datetime.now(timezone.utc).isoformat(),
        "chain_len": len(chain),
        "outcome": outcome,
        "source_host": effective_profile.get("host", ""),
    }

    frontmatter = {
        "name": name,
        "description": description,
        "triggers": triggers,
        "priority": 50,
        "required_tools": required_tools,
        "_provenance": provenance,
    }

    body = _build_body(experience, effective_profile, chain, outcome)
    return SkillDraft(name=name, body=body, frontmatter=frontmatter)


# ---------------------------------------------------------------------------
# Cluster-based synthesis (Fase 3) — multiple engagements → one draft
# ---------------------------------------------------------------------------


# Two narrow regexes for the LLM hallucination gate. We DON'T flag every
# 4+ char word — that produced too many false positives on common English
# (`first`, `then`, `discovery` etc). Instead we only flag tokens that
# actually look like tool references:
#   1. Backtick-wrapped identifiers (`nmap`, `nuclei_scan`).
#   2. Snake-case identifiers (`run_command`, `MAGIC_HACKER_3000`) — the
#      underscore is the giveaway that this is a tool name, not prose.
_TOOLLIKE_BACKTICK_RE = re.compile(r"`([a-z][a-z0-9_]{2,})`")
_TOOLLIKE_UNDERSCORE_RE = re.compile(r"\b([a-z][a-z0-9]*_[a-z0-9_]+)\b")


def _derive_cluster_name(
    cluster: Any, existing_names: set[str]
) -> str:
    """Build a unique kebab-case name for a cluster-derived draft.

    Pattern: `<primary_tech>-<cid_suffix>-auto-NNN`. The cid_suffix
    keeps clusters with the same tech distinguishable; the counter
    avoids collisions on disk.
    """
    tech = list(cluster.representative_profile.get("tech") or [])
    primary = _slugify(tech[0]) if tech else "auto-pattern"
    cid_suffix = cluster.cluster_id.replace("cluster_", "")[:6]
    base = f"{primary}-{cid_suffix}-auto"

    for n in range(1, 1000):
        candidate = f"{base}-{n:03d}"
        if candidate not in existing_names:
            return candidate
    return f"{base}-{int(datetime.now().timestamp())}"


def _build_cluster_prompt(cluster: Any) -> str:
    """Compose the LLM prompt for body synthesis.

    Strict shape: gives the LLM the cluster facts and a hard constraint
    to use ONLY the listed tool names. Output is just the body — no
    frontmatter, the synthesizer owns that.
    """
    tools = list(cluster.representative_chain)
    tech = list(cluster.representative_profile.get("tech") or [])
    sample_hosts = list(cluster.representative_profile.get("sample_hosts") or [])[:3]

    return (
        "You are drafting one section of a Kryon cybersecurity skill playbook. "
        "Write ONLY the markdown body — no frontmatter, no code-fences, no "
        "preamble. Length: 8 to 25 lines.\n\n"
        f"Target class observed: {', '.join(tech) if tech else 'general targets'}\n"
        f"Sample hosts: {', '.join(sample_hosts) if sample_hosts else '(redacted)'}\n"
        f"Cluster size: {cluster.sample_size} engagements with avg outcome "
        f"score {cluster.avg_outcome_score:.2f} (1.0=success, 0.5=partial).\n\n"
        f"Recommended tool sequence (use ONLY these names — any other tool "
        f"reference WILL be rejected): {' → '.join(tools)}\n\n"
        "Structure: short intro paragraph, then numbered phases referencing "
        "the tools in order, then a short list of stop conditions / red flags."
    )


def _llm_body_is_safe(body: str, allowed_tools: set[str]) -> bool:
    """Reject bodies that reference tool names outside the allowed set.

    Two-pattern detector (narrow on purpose to avoid false positives):
      * Backtick-wrapped identifiers (`nmap`, `nuclei_scan`).
      * Snake-case identifiers anywhere (`run_command`, `MAGIC_TOOL_42`).

    Bare prose words (`first`, `discovery`, `respect`) are NOT flagged —
    only tokens that look syntactically like tool references. Allowed
    tools are matched case-insensitively.
    """
    if not body or len(body.strip()) < 20:
        return False

    body_lower = body.lower()
    allowed = {t.lower() for t in allowed_tools}

    suspicious: set[str] = set()
    for regex in (_TOOLLIKE_BACKTICK_RE, _TOOLLIKE_UNDERSCORE_RE):
        for m in regex.finditer(body_lower):
            tok = m.group(1)
            if tok not in allowed:
                suspicious.add(tok)

    return not suspicious


def synthesize_from_cluster(
    cluster: Any,
    *,
    existing_names: set[str] | None = None,
    llm_caller: Any = None,
) -> SkillDraft:
    """Generate one draft from a multi-engagement cluster.

    Args:
        cluster: ChainCluster from `pattern_detector.detect_recurrent_chains`.
        existing_names: skill names already on disk; used to avoid the
            counter colliding with a previously promoted draft.
        llm_caller: optional callable `(prompt: str) -> str`. When given,
            its output replaces the deterministic body IF the body
            (a) is non-empty and (b) doesn't reference tools outside the
            cluster's chain. Otherwise we silently fall back to the
            template — never let LLM hallucinations make it into a draft.

    Returns:
        SkillDraft. Always non-None — clusters that reach this function
        already passed `pattern_detector`'s qualification checks.
    """
    existing = existing_names or set()
    name = _derive_cluster_name(cluster, existing)

    tech = list(cluster.representative_profile.get("tech") or [])
    ports = list((cluster.representative_profile.get("ports") or [])[:_MAX_TRIGGER_PORTS])
    keywords: list[str] = []
    seen: set[str] = set()
    for token in tech + ["auto-cluster"]:
        t = token.lower()
        if t not in seen:
            seen.add(t)
            keywords.append(t)

    triggers = {"tech": tech, "ports": ports, "keywords": keywords}

    required_tools = list(cluster.representative_chain)

    provenance = {
        "cluster_id": cluster.cluster_id,
        "member_experience_ids": list(cluster.member_experience_ids),
        "sample_size": cluster.sample_size,
        "avg_outcome_score": cluster.avg_outcome_score,
        "source": "auto-cluster",
        "synthesized_at": datetime.now(timezone.utc).isoformat(),
    }

    description = (
        f"Auto-synthesized from {cluster.sample_size} similar engagements "
        f"(avg outcome {cluster.avg_outcome_score:.2f})"
    )[:200]

    frontmatter = {
        "name": name,
        "description": description,
        "triggers": triggers,
        "priority": 50,
        "required_tools": required_tools,
        "_provenance": provenance,
    }

    # Body: try LLM first, validate, fall back if anything's off.
    body = _build_cluster_body_deterministic(cluster)
    if llm_caller is not None:
        try:
            llm_prompt = _build_cluster_prompt(cluster)
            llm_body = llm_caller(llm_prompt) or ""
        except Exception:
            llm_body = ""
        if llm_body and _llm_body_is_safe(llm_body, set(required_tools)):
            body = _wrap_llm_body(llm_body, cluster)

    return SkillDraft(name=name, body=body, frontmatter=frontmatter)


def _build_cluster_body_deterministic(cluster: Any) -> str:
    """Fallback body — same template family as Fase 1, adapted to clusters."""
    tools = list(cluster.representative_chain)
    tech = list(cluster.representative_profile.get("tech") or [])
    sample_hosts = list(cluster.representative_profile.get("sample_hosts") or [])

    phase_lines = [f"{i}. **{tool}**" for i, tool in enumerate(tools, start=1)]

    return f"""\
> **DRAFT — auto-synthesized from cluster {cluster.cluster_id}.** Review
> before promoting. The pattern emerged from {cluster.sample_size}
> engagements (avg outcome score {cluster.avg_outcome_score:.2f}).

## Target class

This pattern matches **{', '.join(tech) if tech else 'general targets'}**.
Sample hosts (from cluster members): {', '.join(sample_hosts[:3]) or '(redacted)'}.

## Recommended phases

{chr(10).join(phase_lines)}

## Reviewer checklist before promoting

- [ ] Validate that the tool sequence still applies to NEW targets — not
      just the hosts that produced the cluster.
- [ ] Tighten triggers if the pattern is more specific than the
      auto-derived tech list suggests.
- [ ] Add stop conditions (when the chain should bail out).
- [ ] Replace `sample_hosts` with placeholder values before sharing.
- [ ] Confirm no client-specific identifiers leaked into the body.
"""


def _wrap_llm_body(llm_body: str, cluster: Any) -> str:
    """Wrap LLM-generated body with a provenance banner so reviewers
    always know it was machine-written."""
    return f"""\
> **DRAFT — LLM-assisted synthesis from cluster {cluster.cluster_id}.**
> Auto-written from {cluster.sample_size} engagements. Review every
> claim — the LLM may compress nuance the operator should restore.

{llm_body.strip()}
"""
