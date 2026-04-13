"""
/skill — Manage Kryon skills on-demand.

Subcommands:
  /skill list               → List all local skills
  /skill show <name>        → Display a skill's body
  /skill search <query>     → Search the upstream 754-skill catalog
  /skill import <name>      → Fetch a skill from upstream and install locally
  /skill reload             → Re-scan playbooks/ directory (after manual edits)
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from kryon.repl.commands.base import Command, register_command

console = Console()

UPSTREAM_REPO = "mukul975/Anthropic-Cybersecurity-Skills"
_PLAYBOOKS_DIR = Path(__file__).parent.parent.parent / "skills" / "playbooks"
_IMPORTED_DIR = _PLAYBOOKS_DIR / "imported"


def _fetch_upstream_index() -> list[dict] | None:
    """Download the full 754-skill index via gh CLI."""
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{UPSTREAM_REPO}/contents/index.json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        raw = json.loads(result.stdout)
        content = base64.b64decode(raw["content"]).decode()
        return json.loads(content).get("skills", [])
    except Exception as e:
        console.print(f"[red]Failed to fetch upstream index: {e}[/red]")
        return None


def _fetch_upstream_skill(name: str) -> str | None:
    """Download a single SKILL.md from upstream."""
    try:
        result = subprocess.run(
            [
                "gh",
                "api",
                f"repos/{UPSTREAM_REPO}/contents/skills/{name}/SKILL.md",
                "--jq",
                ".content",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        return base64.b64decode(result.stdout.strip()).decode("utf-8")
    except Exception:
        return None


def _strip_original_frontmatter(content: str) -> tuple[dict, str]:
    """Return (original_frontmatter_dict, body_without_frontmatter)."""
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n", content, re.DOTALL)
    if not match:
        return {}, content
    body = content[match.end():]

    fm: dict = {}
    for line in match.group(1).split("\n"):
        line = line.strip()
        if ":" in line and not line.startswith("-"):
            k, _, v = line.partition(":")
            fm[k.strip()] = v.strip().strip('"').strip("'")
    return fm, body


def _infer_kryon_frontmatter(name: str, original_fm: dict) -> str:
    """Generate Kryon-format frontmatter from the upstream skill metadata."""
    kryon_name = name.replace("_", "-").lower()
    desc = original_fm.get("description", "")[:140].replace('"', "'")
    # Heuristic priority: if it's a detection/defense skill, lower priority (more specific)
    priority = 25 if any(w in name for w in ("detecting-", "hunting-", "analyzing-")) else 20

    # Heuristic keywords from the name
    words = re.findall(r"[a-z]+", name)
    keywords = [w for w in words if len(w) > 3 and w not in {"with", "for", "and", "the", "using"}]

    return f"""name: {kryon_name}
description: "{desc}"
triggers:
  tech: []
  ports: []
  keywords: {json.dumps(keywords[:6])}
priority: {priority}
required_tools:
  - run_command
  - query_knowledge_base"""


class SkillCommand(Command):
    """On-demand skill management."""

    def __init__(self):
        super().__init__(
            name="/skill",
            description="Manage Kryon skills — list, import, search, reload",
            aliases=["/skills"],
        )
        self.add_subcommand("list", "List all local skills", self.handle_list)
        self.add_subcommand("show", "Show a skill's body", self.handle_show)
        self.add_subcommand("search", "Search the upstream skill catalog", self.handle_search)
        self.add_subcommand("import", "Import a skill from upstream", self.handle_import)
        self.add_subcommand("reload", "Re-scan the playbooks directory", self.handle_reload)

    def handle_no_args(self) -> bool:
        return self.handle_list()

    # ------------------------------------------------------------------

    def handle_list(self, args: Optional[list[str]] = None) -> bool:
        from kryon.skills.loader import SkillLoader

        loader = SkillLoader()
        skills = loader.scan()

        table = Table(title=f"Kryon Skills ({len(skills)} loaded)", show_lines=False)
        table.add_column("Name", style="cyan")
        table.add_column("Priority", justify="right")
        table.add_column("Tools", justify="right")
        table.add_column("Triggers", overflow="fold", style="dim")

        for s in sorted(skills, key=lambda x: x.priority):
            triggers = []
            if s.triggers.get("tech"):
                triggers.append("tech:" + ",".join(s.triggers["tech"][:3]))
            if s.triggers.get("ports"):
                triggers.append("ports:" + ",".join(str(p) for p in s.triggers["ports"][:3]))
            kw = s.triggers.get("keywords", [])[:3]
            if kw:
                triggers.append("kw:" + ",".join(kw))
            table.add_row(
                s.name,
                str(s.priority),
                str(len(s.required_tools)),
                " | ".join(triggers) or "(any)",
            )
        console.print(table)
        return True

    def handle_show(self, args: Optional[list[str]] = None) -> bool:
        if not args:
            console.print("[red]Usage: /skill show <name>[/red]")
            return False
        from kryon.skills.loader import SkillLoader

        skill = SkillLoader().get_by_name(args[0])
        if not skill:
            console.print(f"[yellow]No skill with name '{args[0]}'[/yellow]")
            return True
        console.print(Panel(Markdown(skill.body), title=skill.name, border_style="cyan"))
        return True

    def handle_search(self, args: Optional[list[str]] = None) -> bool:
        if not args:
            console.print("[red]Usage: /skill search <query>[/red]")
            return False
        query = " ".join(args).lower()
        console.print(f"[dim]Searching upstream {UPSTREAM_REPO}...[/dim]")
        upstream = _fetch_upstream_index()
        if upstream is None:
            return False

        matches = []
        for s in upstream:
            text = f"{s['name']} {s.get('description','')}".lower()
            if query in text:
                matches.append(s)

        if not matches:
            console.print(f"[yellow]No skills match '{query}'.[/yellow]")
            return True

        table = Table(title=f"Upstream matches for '{query}' ({len(matches)})")
        table.add_column("Name", style="cyan", overflow="fold")
        table.add_column("Description", overflow="fold", style="dim")
        for s in matches[:20]:
            table.add_row(s["name"], s.get("description", "")[:100])
        console.print(table)
        console.print(f"[dim]Install with: [bold]/skill import <name>[/bold][/dim]")
        return True

    def handle_import(self, args: Optional[list[str]] = None) -> bool:
        if not args:
            console.print("[red]Usage: /skill import <upstream-name>[/red]")
            return False
        name = args[0]
        console.print(f"[dim]Fetching {name} from {UPSTREAM_REPO}...[/dim]")
        content = _fetch_upstream_skill(name)
        if not content:
            console.print(f"[red]Failed to fetch '{name}'. Check the name (use /skill search).[/red]")
            return False

        original_fm, body = _strip_original_frontmatter(content)
        kryon_fm = _infer_kryon_frontmatter(name, original_fm)
        kryon_name = name.replace("_", "-").lower()

        _IMPORTED_DIR.mkdir(parents=True, exist_ok=True)
        target = _IMPORTED_DIR / f"{kryon_name}.md"
        if target.exists():
            console.print(f"[yellow]{kryon_name} already installed at {target}[/yellow]")
            return True

        full = f"---\n{kryon_fm}\n---\n\n{body}"
        target.write_text(full, encoding="utf-8")

        console.print(
            Panel(
                f"[bold green]✅ Skill imported[/bold green]\n\n"
                f"[cyan]Name:[/cyan]     {kryon_name}\n"
                f"[cyan]Path:[/cyan]     {target}\n"
                f"[cyan]Body:[/cyan]     {len(body)} chars\n\n"
                f"[dim]Review and edit frontmatter triggers if needed, then:[/dim]\n"
                f"[dim]  /skill reload       (or /flush to restart agent with new skill)[/dim]",
                title="/skill import",
                border_style="green",
            )
        )
        return True

    def handle_reload(self, args: Optional[list[str]] = None) -> bool:
        from kryon.skills.loader import SkillLoader

        loader = SkillLoader()
        loader._cache.clear()  # force re-parse
        skills = loader.scan()
        console.print(f"[green]Reloaded {len(skills)} skills from playbooks/[/green]")
        return True


register_command(SkillCommand())
