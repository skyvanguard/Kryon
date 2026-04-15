"""/allow — manage per-engagement allow-list suppressions (F10.1).

Subcommands:
  /allow list                      Show suppressions in .kryon-allow.yaml
  /allow add <file_glob> [rule]    Interactive add (prompts for reason)
  /allow path                      Print path of YAML + audit log

The allow-list file lives at the nearest repo root (directory with
`.kryon-allow.yaml` or `.git`) relative to the current working directory.
"""
from __future__ import annotations

import getpass
import sys
from pathlib import Path

from kryon.repl.commands.base import Command, register_command


def _find_repo_root() -> Path:
    """Find .kryon-allow.yaml or .git upward from CWD; fall back to CWD."""
    p = Path.cwd().resolve()
    for _ in range(20):
        if (p / ".kryon-allow.yaml").is_file() or (p / ".git").exists():
            return p
        if p.parent == p:
            break
        p = p.parent
    return Path.cwd().resolve()


class AllowCommand(Command):
    """Manage per-engagement allow-list."""

    def __init__(self) -> None:
        super().__init__(
            name="/allow",
            description="Per-engagement allow-list for scanner FPs",
            aliases=[],
        )

    def handle(self, args: list[str] | None = None) -> bool:
        args = args or []
        if not args:
            return self._list()
        sub = args[0].lower()
        if sub == "list":
            return self._list()
        if sub == "path":
            return self._path()
        if sub == "add":
            return self._add(args[1:])
        print(f"unknown subcommand: {sub}")
        print("usage: /allow [list|add <file_glob> [rule_id]|path]")
        return False

    def _list(self) -> bool:
        from kryon.services.allow_list import load
        root = _find_repo_root()
        al = load(root)
        print(f"Repo root: {root}")
        print(f"YAML:      {root}/.kryon-allow.yaml "
              f"({'present' if (root/'.kryon-allow.yaml').is_file() else 'missing'})")
        print(f"Audit:     {root}/.kryon-allow-audit.jsonl "
              f"({'present' if (root/'.kryon-allow-audit.jsonl').is_file() else 'missing'})")
        print(f"Rules:     {len(al.rules)}")
        for i, r in enumerate(al.rules, 1):
            line = f"L{r.line_lo}-{r.line_hi}" if r.line_lo else "any line"
            rule = r.rule_id or "any rule"
            print(f"  [{i}] {r.file_glob:<40} {rule:<30} {line:<15} — {r.reason[:80]}")
            if r.added_by:
                print(f"        added_by: {r.added_by}")
        return True

    def _path(self) -> bool:
        root = _find_repo_root()
        print(f"{root}/.kryon-allow.yaml")
        print(f"{root}/.kryon-allow-audit.jsonl")
        return True

    def _add(self, args: list[str]) -> bool:
        if not args:
            print("usage: /allow add <file_glob> [rule_id]")
            return False
        file_glob = args[0]
        rule_id = args[1] if len(args) > 1 else ""
        # Prompt for reason (required).
        try:
            reason = input("reason (required): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\ncancelled")
            return False
        if not reason:
            print("aborted: reason cannot be empty")
            return False
        try:
            added_by = getpass.getuser()
        except Exception:
            added_by = "unknown"
        from kryon.services.allow_list import add_entry
        root = _find_repo_root()
        yaml_path = add_entry(
            root,
            file_glob=file_glob,
            rule_id=rule_id,
            reason=reason,
            added_by=f"{added_by} (via /allow)",
        )
        print(f"added suppression → {yaml_path}")
        return True


register_command(AllowCommand())
