"""F171 — ``kryon update-cve-cache`` subcommand.

Populate the local NVD cache file used by F151's strict mode
(``KRYON_CVE_CACHE_REQUIRED=true``). With the cache populated,
hallucinated CVE IDs that pass the format check but were never
published get rejected.

Examples:

    kryon update-cve-cache --year 2025
    kryon update-cve-cache --years 2020-2026
    kryon update-cve-cache --all
    kryon update-cve-cache --output ~/.kryon/nvd_cache/cves.txt --years 2024-2026

The default cache path follows ``KRYON_CVE_CACHE_PATH`` (env) or
``~/.kryon/nvd_cache/cves.txt`` (home-anchored, stable across cwd). Use
``--output`` to override per invocation.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def add_cve_cache_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser(
        "update-cve-cache",
        help="F171 — Populate the NVD CVE cache used by KRYON_CVE_CACHE_REQUIRED",
    )
    group = p.add_mutually_exclusive_group()
    group.add_argument(
        "--year",
        type=int,
        help="Fetch a single year (e.g. --year 2025)",
    )
    group.add_argument(
        "--years",
        dest="years_range",
        help='Fetch a year range (e.g. --years "2020-2026")',
    )
    group.add_argument(
        "--all",
        dest="all_years",
        action="store_true",
        help="Fetch every year from 1999 to current_year+1",
    )
    p.add_argument(
        "--output",
        dest="output",
        default="",
        help="Override the cache file path",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Per-request HTTP timeout in seconds (default: 60)",
    )
    return p


def run_cve_cache_command(args) -> int:
    from kryon.validation.cve_cache_updater import resolve_years, update_cache

    try:
        years = resolve_years(
            year=getattr(args, "year", None),
            years_range=getattr(args, "years_range", None),
            all_years=getattr(args, "all_years", False),
        )
    except (ValueError, TypeError) as exc:
        # resolve_years int()-parses --year/--years; a malformed value raised an
        # uncaught traceback instead of the clean FATAL message this command uses.
        print(f"FATAL: invalid --year/--years: {exc}", file=sys.stderr)
        return 2
    cache_path = Path(args.output) if args.output else None

    print(f"Fetching {len(years)} year(s): {years[0]}..{years[-1]} (this may take a few minutes)")
    try:
        result = update_cache(years, cache_path=cache_path, timeout=args.timeout)
    except Exception as exc:  # noqa: BLE001 - surface real cause to operator
        print(f"FATAL: cache update failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    print(result.summary())
    if result.errors:
        print("\nErrors (per-year failures did not stop the run):", file=sys.stderr)
        for err in result.errors:
            print(f"  - {err}", file=sys.stderr)
        # Soft failure: partial cache write still happened.
        return 1
    return 0
