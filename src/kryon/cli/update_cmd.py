"""Fase A — ``kryon update`` — unified detection-feed refresh.

One command that refreshes the update mechanisms that used to live scattered
and manual: nuclei-templates, the ExploitDB CSV, the NVD CVE cache, and
(opt-in) skill playbooks. This is what turns "the container's determinism is
frozen at build time" into "the appliance updates itself before each scan"
(the scheduler drives it via kind="update").

Examples:

    kryon update                              # nuclei + exploitdb + cve-cache
    kryon update --only nuclei,cve-cache
    kryon update --cve-years 2020-2026
    kryon update --all --skills-repo https://github.com/org/kryon-playbooks
"""

from __future__ import annotations

import argparse


def add_update_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(
        "update",
        help="Refresh detection feeds (nuclei templates, ExploitDB, CVE cache, skills)",
    )
    p.add_argument(
        "--only",
        default="",
        help="Comma-separated subset of feeds: nuclei,exploitdb,cve-cache,skills,openvas,cinc,cve-corpus",
    )
    p.add_argument(
        "--all",
        dest="all_feeds",
        action="store_true",
        help="Include opt-in feeds (skills, openvas, cinc, cve-corpus) on top of the defaults",
    )
    p.add_argument(
        "--cve-years",
        default="",
        help='NVD year range for the CVE cache, e.g. "2020-2026" (default: current + previous year)',
    )
    p.add_argument("--skills-repo", default="", help="Git repo URL to pull skill playbooks from")
    p.add_argument("--skills-branch", default="main")
    return p


_ICON = {"ok": "✓", "skipped": "•", "failed": "✗"}


def run_update_command(args) -> int:
    from kryon.services.feed_updater import ALL_FEEDS, DEFAULT_FEEDS, run_updates

    only = getattr(args, "only", "") or ""
    if only:
        feeds = [f.strip() for f in only.split(",") if f.strip()]
    elif getattr(args, "all_feeds", False):
        feeds = list(ALL_FEEDS)
    else:
        feeds = list(DEFAULT_FEEDS)

    results = run_updates(
        feeds,
        cve_years=(getattr(args, "cve_years", "") or None),
        skills_repo=(getattr(args, "skills_repo", "") or None),
        skills_branch=getattr(args, "skills_branch", "main"),
    )

    print(f"kryon update — {len(results)} feed(s):")
    any_failed = False
    for r in results:
        line = f"  {_ICON.get(r.status, '?')} {r.name}: {r.status}"
        if r.detail:
            line += f" — {r.detail}"
        print(line)
        any_failed = any_failed or r.failed
    return 1 if any_failed else 0
