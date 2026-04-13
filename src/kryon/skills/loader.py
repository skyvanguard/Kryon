"""
Skill loader — parse markdown playbooks with YAML frontmatter, cache them,
and match them against a target profile.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_DEFAULT_SKILL_DIR = Path(__file__).parent / "playbooks"


@dataclass(frozen=True)
class Skill:
    name: str
    description: str
    triggers: dict[str, list]  # {tech: [], ports: [], keywords: []}
    priority: int
    required_tools: list[str]
    body: str  # markdown content below frontmatter
    source_path: Path


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

    fm = _parse_yaml_simple(m.group(1))
    body = text[m.end():].strip()

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
        """Parse all .md files in skill directories. Caches by mtime."""
        skills: list[Skill] = []
        for d in self._dirs:
            if not d.exists():
                continue
            # Recursive scan so subdirectories (e.g. imported/) are picked up
            for md_file in sorted(d.rglob("*.md")):
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
    ) -> list[Skill]:
        """Return skills matching the target profile + user message,
        sorted by priority, capped by token budget."""
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

            # Keyword match (highest signal)
            if triggers.get("keywords"):
                if any(kw.lower() in user_lower for kw in triggers["keywords"]):
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

        # Sort by priority (lower = first)
        scored.sort(key=lambda x: x[0])

        # Accumulate until budget
        selected: list[Skill] = []
        tokens_used = 0
        for _, skill in scored:
            est_tokens = len(skill.body) // 4  # rough estimate
            if tokens_used + est_tokens > budget_tokens:
                break
            selected.append(skill)
            tokens_used += est_tokens

        return selected

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

    def list_names(self) -> list[str]:
        """Return all available skill names."""
        return [s.name for s in self.scan()]
