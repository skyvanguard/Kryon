"""
Skill loader — parse markdown playbooks with YAML frontmatter, cache them,
and match them against a target profile.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_DEFAULT_SKILL_DIR = Path(__file__).parent / "playbooks"


def _keyword_matches(keyword: str, user_lower: str) -> bool:
    """Whole-word keyword matcher.

    The legacy `keyword in user_lower` substring match was catastrophic
    for short keywords: `"ad"` (active-directory-recon) matched
    "segurid**ad**", `"fix"` (safe-modification) would match "pre**fix**",
    `"spa"` (browser-exploit) would match "e**spa**ña". Result: random
    skills got loaded for unrelated prompts.

    Whole-word match using `\\b` boundaries restores the intended
    semantics: `"ad"` matches "ad" / "ad-hoc" / "(ad)" but NOT
    "seguridad". Multi-word keywords ("active directory", "auditoría
    web") work the same way — \\b only fires at the outer edges, so the
    whole phrase has to be present.

    Python's `\\b` is Unicode-aware by default in re module, so accented
    keywords ("análisis", "auditoría") match natural Spanish text.
    """
    pattern = r"\b" + re.escape(keyword.lower()) + r"\b"
    return re.search(pattern, user_lower) is not None


@dataclass(frozen=True)
class Skill:
    name: str
    description: str
    triggers: dict[str, list]  # {tech: [], ports: [], keywords: []}
    priority: int
    required_tools: list[str]
    body: str  # markdown content below frontmatter
    source_path: Path
    # Tools this skill explicitly does NOT want available to the agent.
    # Subtracted from the final tool set AFTER ALWAYS_INCLUDE and
    # required_tools are unioned. Used to keep certain tools out of
    # reach even if they're ambient (e.g., hunter skill forbids
    # run_command/execute_code so the model can't use them as a
    # side-channel around run_sandboxed).
    forbidden_tools: tuple = ()  # tuple for frozen dataclass hashability
    # Deterministic tool invocations executed BEFORE the LLM takes
    # control. Output gets injected into the system prompt under
    # `inject_as` keys. Empty tuple = no pre-hooks (default).
    # See kryon.skills.pre_hook_spec for the schema.
    pre_hooks: tuple = ()


def _parse_yaml_simple(text: str) -> dict[str, Any]:
    """Minimal YAML parser for frontmatter — avoids PyYAML dependency.
    Handles: scalars, lists (inline [...] and block - item), nested dicts (one level)."""
    result: dict[str, Any] = {}
    current_key: str | None = None
    current_list: list | None = None
    parent_key: str | None = None  # for one-level nesting (e.g., triggers:)
    parent_dict: dict | None = None

    for line in text.split("\n"):
        if not line.strip() or line.strip().startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        # Block list item: "  - value"
        if stripped.startswith("- ") and current_key is not None:
            target = parent_dict if parent_dict and indent >= 4 else result
            if current_list is None:
                current_list = []
                target[current_key] = current_list
            val = stripped[2:].strip().strip('"').strip("'")
            try:
                val = int(val)
            except (ValueError, TypeError):
                pass
            current_list.append(val)
            continue

        # Key: value
        if ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            current_list = None

            # Detect nesting: indented key under a parent
            if indent >= 2 and parent_key and parent_dict is not None:
                current_key = key
                target = parent_dict
            else:
                # Top-level key — reset nesting
                current_key = key
                parent_key = None
                parent_dict = None
                target = result

            if not val:
                # This key has no inline value — it starts a nested dict or list
                if indent == 0:
                    parent_key = key
                    parent_dict = {}
                    result[key] = parent_dict
                continue

            # Inline list: [a, b, c]
            if val.startswith("[") and val.endswith("]"):
                inner = val[1:-1].strip()
                if not inner:
                    target[key] = []
                else:
                    items = []
                    for item in inner.split(","):
                        item = item.strip().strip('"').strip("'")
                        try:
                            item = int(item)
                        except (ValueError, TypeError):
                            pass
                        items.append(item)
                    target[key] = items
                continue

            # Scalar
            val = val.strip('"').strip("'")
            if val.lower() == "true":
                val = True
            elif val.lower() == "false":
                val = False
            else:
                try:
                    val = int(val)
                except (ValueError, TypeError):
                    pass
            target[key] = val

    return result


def _parse_skill_file(path: Path) -> Skill | None:
    """Parse one .md file into a Skill object."""
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as e:
        logger.warning("Failed to read skill %s: %s", path, e)
        return None

    m = _FRONTMATTER_RE.match(text)
    if not m:
        logger.warning("No frontmatter in %s", path)
        return None

    fm_text = m.group(1)
    fm = _parse_yaml_simple(fm_text)
    body = text[m.end():].strip()

    # Pre-hooks support: opt-in. If the skill declares `pre_hooks:`, we
    # need a YAML parser that handles list-of-dicts (the simple parser
    # does not). Use PyYAML when present; fall back gracefully and skip
    # pre_hooks when it's not — the skill still loads.
    pre_hooks: tuple = ()
    if "pre_hooks:" in fm_text:
        try:
            import yaml  # PyYAML, available in our base deps via transitives

            from kryon.skills.pre_hook_spec import (
                PreHookSchemaError,
                parse_pre_hooks,
            )

            full = yaml.safe_load(fm_text) or {}
            raw_hooks = full.get("pre_hooks")
            try:
                pre_hooks = parse_pre_hooks(
                    raw_hooks,
                    source_dir=str(path.parent),
                )
            except PreHookSchemaError as schema_err:
                logger.warning(
                    "pre_hooks schema error in %s: %s — skipping skill",
                    path, schema_err,
                )
                return None
        except ImportError:
            logger.warning(
                "skill %s declares pre_hooks but PyYAML is not installed — "
                "skill will load WITHOUT pre_hooks", path,
            )
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "Failed to parse pre_hooks in %s: %s — skill will load "
                "WITHOUT pre_hooks", path, e,
            )

    triggers = fm.get("triggers", {})
    if not isinstance(triggers, dict):
        triggers = {}

    return Skill(
        name=fm.get("name", path.stem),
        description=fm.get("description", ""),
        triggers={
            "tech": triggers.get("tech") or [],
            "ports": [int(p) for p in (triggers.get("ports") or [])],
            "keywords": triggers.get("keywords") or [],
        },
        priority=int(fm.get("priority", 50)),
        required_tools=fm.get("required_tools") or [],
        body=body,
        source_path=path,
        forbidden_tools=tuple(fm.get("forbidden_tools") or []),
        pre_hooks=pre_hooks,
    )


class SkillLoader:
    """Loads and matches skill playbooks from markdown files."""

    def __init__(self, skill_dirs: list[Path] | None = None):
        self._dirs = skill_dirs or [_DEFAULT_SKILL_DIR]
        extra = os.environ.get("KRYON_SKILLS_DIR")
        if extra:
            self._dirs.append(Path(extra))
        self._cache: dict[Path, tuple[float, Skill]] = {}

    def scan(self) -> list[Skill]:
        """Parse all .md files in skill directories. Caches by mtime.

        Skips any subdirectory whose name starts with `_` or `.` so that
        `_drafts/`, `_archive/`, and similar staging areas don't pollute
        the live skill registry. Drafts promoted via `/skill promote`
        land in `_drafts/` and become active only after the operator
        moves them to a regular directory.
        """
        skills: list[Skill] = []
        for d in self._dirs:
            if not d.exists():
                continue
            # Recursive scan so subdirectories (e.g. imported/) are picked up
            for md_file in sorted(d.rglob("*.md")):
                # Honour underscore/dot-prefixed parent dirs as "ignored".
                if any(
                    part.startswith(("_", "."))
                    for part in md_file.relative_to(d).parts[:-1]
                ):
                    continue
                mtime = md_file.stat().st_mtime
                cached = self._cache.get(md_file)
                if cached and cached[0] == mtime:
                    skills.append(cached[1])
                    continue
                skill = _parse_skill_file(md_file)
                if skill:
                    self._cache[md_file] = (mtime, skill)
                    skills.append(skill)
        return skills

    def match(
        self,
        profile: dict[str, Any] | None = None,
        user_msg: str = "",
        budget_tokens: int = 6000,
        *,
        ranking: str | None = None,
        experience_loader: Any = None,
    ) -> list[Skill]:
        """Return skills matching the target profile + user message.

        Args:
            profile: optional target profile dict (tech / ports).
            user_msg: free text from the operator.
            budget_tokens: cap on the composed prompt size.
            ranking: "priority" (legacy default), "hybrid" (priority +
                experience-based tie-break), or "score" (pure score —
                experimental, NOT recommended for banking compliance).
                If None, the env var `KRYON_SKILL_RANKING` is consulted;
                if that's absent or invalid, "priority" wins.
            experience_loader: callable returning a list of experience
                dicts. Only invoked under hybrid/score modes. When None,
                the runtime defaults to `kryon.learning.list_experiences`;
                tests inject a stub to avoid ChromaDB.
        """
        all_skills = self.scan()
        if not all_skills:
            return []

        profile = profile or {}
        user_lower = user_msg.lower()
        target_tech = set(t.lower() for t in (profile.get("tech") or []))
        target_ports = set(profile.get("ports") or [])

        scored: list[tuple[int, Skill]] = []
        for skill in all_skills:
            triggers = skill.triggers
            matched = False

            # Keyword match (highest signal). Whole-word — see
            # `_keyword_matches` for why substring is broken.
            if triggers.get("keywords"):
                if any(_keyword_matches(kw, user_lower) for kw in triggers["keywords"]):
                    matched = True

            # Tech match
            if not matched and triggers.get("tech"):
                if target_tech & set(t.lower() for t in triggers["tech"]):
                    matched = True

            # Port match
            if not matched and triggers.get("ports"):
                if target_ports & set(triggers["ports"]):
                    matched = True

            # Base skill (empty triggers) — always matches
            if not triggers.get("tech") and not triggers.get("ports") and not triggers.get("keywords"):
                matched = True

            if matched:
                scored.append((skill.priority, skill))

        # Apply ranking (priority by default; hybrid/score consult experiences).
        effective_ranking = self._resolve_ranking_mode(ranking)
        scored, scores_by_name = self._apply_ranking_with_scores(
            scored, effective_ranking, experience_loader,
        )

        # Accumulate until budget
        selected: list[Skill] = []
        tokens_used = 0
        for _, skill in scored:
            est_tokens = len(skill.body) // 4  # rough estimate
            if tokens_used + est_tokens > budget_tokens:
                break
            selected.append(skill)
            tokens_used += est_tokens

        # Telemetry — best-effort, never raises (selection_telemetry swallows).
        try:
            from kryon.learning.selection_telemetry import log_selection

            candidates_payload = [
                {
                    "name": s.name,
                    "priority": prio,
                    "score": (
                        scores_by_name[s.name]
                        if scores_by_name and s.name in scores_by_name
                        else None
                    ),
                }
                for prio, s in scored
            ]
            log_selection(
                user_msg=user_msg,
                ranking_mode=effective_ranking,
                candidates=candidates_payload,
                selected=[s.name for s in selected],
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("selection telemetry skipped: %s", e)

        return selected

    def _resolve_ranking_mode(self, ranking: str | None) -> str:
        """Resolve final ranking mode: explicit arg > env var > priority."""
        if ranking is None:
            ranking = os.environ.get("KRYON_SKILL_RANKING", "").strip().lower()
        if ranking in ("hybrid", "score"):
            return ranking
        return "priority"

    def _apply_ranking_with_scores(
        self,
        scored: list[tuple[int, Skill]],
        ranking: str,
        experience_loader: Any,
    ) -> tuple[list[tuple[int, Skill]], dict[str, float] | None]:
        """Reorder `scored` per ranking mode; also return per-name scores
        (or None when in priority mode — telemetry then logs score=null).

        Hybrid/score are best-effort: if the experience loader fails
        (chromadb unavailable, schema mismatch, etc.), fall back to
        priority and return None for scores.
        """
        if ranking == "priority":
            return sorted(scored, key=lambda x: x[0]), None

        try:
            experiences = self._load_experiences_for_ranking(experience_loader)
            from kryon.learning.skill_scorer import (
                rank_skills_hybrid,
                rank_skills_score_only,
                score_skills,
            )

            skill_names = [s.name for _, s in scored]
            scores = score_skills(experiences=experiences, skill_names=skill_names)
            pairs = [(s.name, prio) for prio, s in scored]
            ranker = (
                rank_skills_hybrid if ranking == "hybrid" else rank_skills_score_only
            )
            ranked_pairs = ranker(pairs, scores)
            by_name = {s.name: (prio, s) for prio, s in scored}
            ordered = [by_name[name] for name, _ in ranked_pairs]
            scores_by_name = {n: scores[n].confidence_lower for n in scores}
            return ordered, scores_by_name
        except Exception as e:  # noqa: BLE001
            logger.debug("ranking %r failed, falling back to priority: %s", ranking, e)
            return sorted(scored, key=lambda x: x[0]), None

    def _load_experiences_for_ranking(self, experience_loader: Any) -> list[dict]:
        """Resolve which loader to call. Tests inject; runtime uses chromadb."""
        if experience_loader is not None:
            return experience_loader()
        # Default: pull from the experience store. Imports lazily so
        # priority-mode runs never touch chromadb.
        from kryon.learning import list_experiences

        return list_experiences(limit=500)

    def get_by_name(self, name: str) -> Skill | None:
        """Direct lookup by skill name."""
        for skill in self.scan():
            if skill.name == name:
                return skill
        return None

    def required_tool_names(self, skills: list[Skill]) -> set[str]:
        """Union of required_tools across all given skills."""
        names: set[str] = set()
        for skill in skills:
            names.update(skill.required_tools)
        return names

    def forbidden_tool_names(self, skills: list[Skill]) -> set[str]:
        """Union of forbidden_tools — removed from final set even if ambient."""
        names: set[str] = set()
        for skill in skills:
            names.update(skill.forbidden_tools or ())
        return names

    def list_names(self) -> list[str]:
        """Return all available skill names."""
        return [s.name for s in self.scan()]
