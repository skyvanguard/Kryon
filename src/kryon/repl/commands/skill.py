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

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from kryon.repl.commands.base import Command, register_command

console = Console()

UPSTREAM_REPO = "mukul975/Anthropic-Cybersecurity-Skills"
_PLAYBOOKS_DIR = Path(__file__).parent.parent.parent / "skills" / "playbooks"
_IMPORTED_DIR = _PLAYBOOKS_DIR / "imported"
# Promotion target — lives under playbooks/ but starts with "_" so the
# SkillLoader skips it. Drafts staged here are version-controllable but
# not yet active; the operator finishes promotion by moving them out of
# _drafts/ into a regular directory.
_PROMOTED_DRAFTS_DIR = _PLAYBOOKS_DIR / "_drafts"


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
    body = content[match.end() :]

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
        self.add_subcommand("drafts", "List auto-synthesized drafts pending review", self.handle_drafts)
        self.add_subcommand("review", "Preview a draft's body", self.handle_review)
        self.add_subcommand("promote", "Move a draft to playbooks/_drafts/ for staging", self.handle_promote)
        self.add_subcommand("discard", "Delete a draft permanently", self.handle_discard)
        self.add_subcommand("scores", "Show skill leaderboard from past engagements", self.handle_scores)
        self.add_subcommand("auto", "Auto-skill pipeline: 'auto detect' / 'auto status'", self.handle_auto)

    def handle_no_args(self) -> bool:
        return self.handle_list()

    # ------------------------------------------------------------------

    def handle_list(self, args: list[str] | None = None) -> bool:
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

    def handle_show(self, args: list[str] | None = None) -> bool:
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

    def handle_search(self, args: list[str] | None = None) -> bool:
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
            text = f"{s['name']} {s.get('description', '')}".lower()
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
        console.print("[dim]Install with: [bold]/skill import <name>[/bold][/dim]")
        return True

    def handle_import(self, args: list[str] | None = None) -> bool:
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

    def handle_reload(self, args: list[str] | None = None) -> bool:
        from kryon.skills.loader import SkillLoader

        loader = SkillLoader()
        loader._cache.clear()  # force re-parse
        skills = loader.scan()
        console.print(f"[green]Reloaded {len(skills)} skills from playbooks/[/green]")
        return True

    # ------------------------------------------------------------------
    # Drafts (Fase 1 — human-in-the-loop skill review)
    # ------------------------------------------------------------------

    def handle_drafts(self, args: list[str] | None = None) -> bool:
        """List synthesized drafts pending review."""
        try:
            from kryon.learning.draft_writer import (
                get_drafts_dir,
                list_existing_names,
            )
        except Exception as e:
            console.print(f"[red]drafts subsystem unavailable: {e}[/red]")
            return False

        drafts_dir = get_drafts_dir()
        names = sorted(list_existing_names())
        if not names:
            console.print(
                f"[dim]No drafts in {drafts_dir} — they appear here after a "
                f"successful engagement auto-saves an experience.[/dim]"
            )
            return True

        table = Table(
            title=f"Pending drafts ({len(names)}) — {drafts_dir}",
            show_lines=False,
        )
        table.add_column("Name", style="cyan")
        table.add_column("Outcome", style="dim")
        table.add_column("Source experience", style="dim")
        table.add_column("Tech", style="dim", overflow="fold")

        for name in names:
            preview = self._preview_draft_metadata(name)
            table.add_row(
                name,
                preview.get("outcome", "?"),
                preview.get("experience_id", "?"),
                preview.get("tech", "?"),
            )
        console.print(table)
        console.print(
            "[dim]Review with [bold]/skill review <name>[/bold], "
            "promote with [bold]/skill promote <name>[/bold], "
            "or discard with [bold]/skill discard <name>[/bold].[/dim]"
        )
        return True

    def handle_review(self, args: list[str] | None = None) -> bool:
        """Show the full body of a draft."""
        if not args:
            console.print("[red]Usage: /skill review <draft-name>[/red]")
            return False
        try:
            from kryon.learning.draft_writer import read_draft
        except Exception as e:
            console.print(f"[red]drafts subsystem unavailable: {e}[/red]")
            return False

        name = args[0]
        content = read_draft(name)
        if content is None:
            console.print(f"[yellow]No draft '{name}'. List with /skill drafts.[/yellow]")
            return True

        # Strip the frontmatter from the rendered preview so the markdown
        # renderer doesn't choke on YAML.
        body = content
        if content.startswith("---"):
            try:
                _, _yaml, body = content.split("---\n", 2)
            except ValueError:
                pass

        console.print(
            Panel(
                Markdown(body),
                title=f"draft: {name}",
                border_style="yellow",
                subtitle="[dim]/skill promote · /skill discard[/dim]",
            )
        )
        return True

    def handle_promote(self, args: list[str] | None = None) -> bool:
        """Move ~/.kryon/drafts/<name>.md → playbooks/_drafts/<name>.md."""
        if not args:
            console.print("[red]Usage: /skill promote <draft-name>[/red]")
            return False
        try:
            from kryon.learning.draft_writer import (
                delete_draft,
                get_drafts_dir,
                read_draft,
            )
        except Exception as e:
            console.print(f"[red]drafts subsystem unavailable: {e}[/red]")
            return False

        name = args[0]
        content = read_draft(name)
        if content is None:
            console.print(f"[yellow]No draft '{name}'.[/yellow]")
            return True

        _PROMOTED_DRAFTS_DIR.mkdir(parents=True, exist_ok=True)
        target = _PROMOTED_DRAFTS_DIR / f"{name}.md"
        if target.exists():
            console.print(
                f"[yellow]{target} already exists — refusing to overwrite. "
                f"Discard the existing one first or rename the draft.[/yellow]"
            )
            return True

        target.write_text(content, encoding="utf-8")
        delete_draft(name)

        console.print(
            Panel(
                f"[bold green]✅ Promoted to staging[/bold green]\n\n"
                f"[cyan]From:[/cyan]  {get_drafts_dir() / (name + '.md')}\n"
                f"[cyan]To:[/cyan]    {target}\n\n"
                f"[dim]Next steps:[/dim]\n"
                f"[dim]  1. Hand-edit the .md to fit your target class.[/dim]\n"
                f"[dim]  2. Move it OUT of _drafts/ to activate it[/dim]\n"
                f"[dim]     (the loader skips _drafts/ on purpose).[/dim]\n"
                f"[dim]  3. Run /skill reload (or /flush) when ready.[/dim]",
                title="/skill promote",
                border_style="green",
            )
        )
        return True

    def handle_discard(self, args: list[str] | None = None) -> bool:
        if not args:
            console.print("[red]Usage: /skill discard <draft-name>[/red]")
            return False
        try:
            from kryon.learning.draft_writer import delete_draft
        except Exception as e:
            console.print(f"[red]drafts subsystem unavailable: {e}[/red]")
            return False

        name = args[0]
        if delete_draft(name):
            console.print(f"[dim]🗑  draft '{name}' discarded.[/dim]")
        else:
            console.print(f"[yellow]No draft '{name}' to discard.[/yellow]")
        return True

    # ------------------------------------------------------------------
    # Scores leaderboard (Fase 2 — experience-derived ranking)
    # ------------------------------------------------------------------

    def handle_scores(self, args: list[str] | None = None) -> bool:
        """Render a leaderboard of skills by experience-based win rate."""
        try:
            from kryon.learning import list_experiences
            from kryon.learning.skill_scorer import score_skills
        except Exception as e:
            console.print(f"[red]learning subsystem unavailable: {e}[/red]")
            return False

        from kryon.skills.loader import SkillLoader

        try:
            experiences = list_experiences(limit=500)
        except Exception as e:
            console.print(
                f"[yellow]Could not read experience store: {e}[/yellow]\n"
                "[dim]Install the `rag` extra to enable scoring.[/dim]"
            )
            return True

        skills = SkillLoader().scan()
        if not skills:
            console.print("[dim]No skills loaded.[/dim]")
            return True

        scores = score_skills(
            experiences=experiences,
            skill_names=[s.name for s in skills],
        )

        # Sort: cold-starters last; otherwise confidence_lower desc, win_rate desc.
        ranked = sorted(
            scores.values(),
            key=lambda s: (s.sample_size == 0, -s.confidence_lower, -s.win_rate),
        )

        table = Table(
            title=f"Skill leaderboard ({len(experiences)} engagements)",
            show_lines=False,
        )
        table.add_column("Skill", style="cyan")
        table.add_column("n", justify="right")
        table.add_column("S/P/F", justify="right", style="dim")
        table.add_column("Win rate", justify="right")
        table.add_column("95% lower", justify="right")
        table.add_column("Avg chain", justify="right", style="dim")
        table.add_column("Last used", style="dim")

        for s in ranked:
            confidence_marker = "[yellow]·[/yellow]" if s.is_low_confidence else " "
            win_str = f"{s.win_rate * 100:5.1f}%" if s.sample_size else "—"
            conf_str = (
                f"{s.confidence_lower * 100:5.1f}%"
                if not s.is_low_confidence
                else f"[dim]{s.confidence_lower * 100:5.1f}%[/dim]"
            )
            chain_str = f"{s.avg_chain_len:.1f}" if s.sample_size else "—"
            last_str = (s.last_used or "—")[:10]
            table.add_row(
                f"{confidence_marker} {s.skill_name}",
                str(s.sample_size),
                f"{s.success_count}/{s.partial_count}/{s.fail_count}",
                win_str,
                conf_str,
                chain_str,
                last_str,
            )
        console.print(table)
        console.print(
            "[dim]· = low-confidence (sample < 10). Hybrid ranking respects priority first, score within tier.[/dim]"
        )
        return True

    # ------------------------------------------------------------------
    # Auto pipeline (Fase 3 — pattern detection + auto-synthesis)
    # ------------------------------------------------------------------

    def handle_auto(self, args: list[str] | None = None) -> bool:
        """Dispatch /skill auto <detect|status>."""
        sub = args[0].lower() if args else "status"
        if sub == "detect":
            return self._auto_detect()
        if sub == "status":
            return self._auto_status()
        console.print("[red]Usage: /skill auto detect | /skill auto status[/red]")
        return False

    def _auto_detect(self) -> bool:
        """Run pattern_detector → synth → eval pipeline against the corpus."""
        try:
            from kryon.learning import list_experiences
            from kryon.learning.auto_pipeline import run_auto_pipeline
        except Exception as e:
            console.print(f"[red]auto subsystem unavailable: {e}[/red]")
            return False

        # Findings loader (best-effort — depends on chromadb).
        def _load_findings() -> list:
            try:
                from kryon.learning.findings_library import (
                    list as fnd_list,  # type: ignore[attr-defined]
                )

                return fnd_list()
            except Exception:
                return []

        console.print("[dim]Scanning experience corpus for recurring patterns…[/dim]")
        result = run_auto_pipeline(
            experience_loader=lambda: list_experiences(limit=500),
            findings_loader=_load_findings,
        )

        from kryon.learning.draft_writer import get_drafts_dir

        drafts_root = get_drafts_dir()
        console.print(
            Panel(
                f"[bold]Pipeline result[/bold]\n\n"
                f"[cyan]Clusters detected:[/cyan]   {result.clusters_detected}\n"
                f"[cyan]Drafts synthesized:[/cyan]  {result.drafts_synthesized}\n"
                f"[green]Passed eval gate:[/green]    {result.drafts_passed}\n"
                f"[red]Rejected:[/red]            {result.drafts_rejected}\n"
                f"[yellow]Skipped (no corpus):[/yellow] {result.drafts_skipped}\n\n"
                f"[dim]Output dir: {drafts_root}/_auto and {drafts_root}/_rejected[/dim]\n"
                f"[dim]Review with: /skill auto status[/dim]",
                title="/skill auto detect",
                border_style="cyan",
            )
        )
        return True

    def _auto_status(self) -> bool:
        """List drafts produced by previous /skill auto detect runs."""
        try:
            from kryon.learning.draft_writer import get_drafts_dir
        except Exception as e:
            console.print(f"[red]drafts subsystem unavailable: {e}[/red]")
            return False

        drafts_root = get_drafts_dir()
        for sub_label, sub_dir, color in (
            ("Passed (auto)", "_auto", "green"),
            ("Rejected / skipped", "_rejected", "yellow"),
        ):
            d = drafts_root / sub_dir
            md_files = sorted(d.glob("*.md")) if d.is_dir() else []
            if not md_files:
                console.print(f"[dim]{sub_label}: 0 drafts.[/dim]")
                continue

            table = Table(
                title=f"[{color}]{sub_label}[/{color}] — {len(md_files)} drafts",
                show_lines=False,
            )
            table.add_column("Name", style="cyan")
            table.add_column("Eval status", style=color)
            table.add_column("Pass rate", justify="right", style="dim")
            table.add_column("Reason", overflow="fold", style="dim")

            for md in md_files:
                eval_path = md.with_suffix(".eval.json")
                if eval_path.exists():
                    try:
                        report = json.loads(eval_path.read_text(encoding="utf-8"))
                    except Exception:
                        report = {}
                else:
                    report = {}
                table.add_row(
                    md.stem,
                    report.get("eval_status", "?"),
                    (f"{report.get('pass_rate', 0) * 100:.0f}%" if report.get("pass_rate") is not None else "—"),
                    (report.get("reason", "")[:80] or "—"),
                )
            console.print(table)
        console.print("[dim]Promote a passed draft with /skill promote <name> after manual review.[/dim]")
        return True

    @staticmethod
    def _preview_draft_metadata(name: str) -> dict:
        """Cheap peek into a draft's frontmatter for the listing table."""
        try:
            from kryon.learning.draft_writer import read_draft
        except Exception:
            return {}

        content = read_draft(name) or ""
        if not content.startswith("---"):
            return {}
        try:
            import yaml

            _, yaml_block, _ = content.split("---\n", 2)
            fm = yaml.safe_load(yaml_block) or {}
        except Exception:
            return {}

        prov = fm.get("_provenance") or {}
        triggers = fm.get("triggers") or {}
        tech = ",".join((triggers.get("tech") or [])[:3]) or "(any)"
        return {
            "outcome": prov.get("outcome", "?"),
            "experience_id": prov.get("experience_id", "?"),
            "tech": tech,
        }


register_command(SkillCommand())
