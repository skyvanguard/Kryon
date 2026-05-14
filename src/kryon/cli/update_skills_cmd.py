"""F147 — ``kryon update-skills`` subcommand."""

from __future__ import annotations

import argparse


def add_update_skills_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(
        "update-skills",
        help="F147 — Pull skill playbooks from an upstream git repo",
    )
    p.add_argument("--from", dest="repo_url", required=True, help="Git repo URL")
    p.add_argument("--branch", default="main")
    p.add_argument("--playbooks-subdir", default="playbooks")
    p.add_argument("--force", action="store_true", help="Overwrite local skills with upstream version")
    p.add_argument("--local-dir", default="", help="Override local playbooks dir")
    return p


def run_update_skills_command(args) -> int:
    from pathlib import Path

    from kryon.skills.updater import update_from_git

    local = Path(args.local_dir) if args.local_dir else None
    result = update_from_git(
        args.repo_url,
        branch=args.branch,
        playbooks_subdir=args.playbooks_subdir,
        local_playbooks_dir=local,
        force=args.force,
    )

    if result.added:
        print(f"added {len(result.added)}:")
        for a in result.added:
            print(f"  + {a}")
    if result.updated:
        print(f"updated {len(result.updated)} (force):")
        for u in result.updated:
            print(f"  * {u}")
    if result.skipped:
        print(f"skipped {len(result.skipped)}:")
        for name, reason in result.skipped:
            print(f"  - {name}  ({reason})")
    if result.failed:
        print(f"failed {len(result.failed)}:")
        for name, err in result.failed:
            print(f"  ! {name}  ({err})")
        return 1
    return 0
