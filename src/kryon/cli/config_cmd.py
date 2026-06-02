"""``kryon config`` — dump the effective core configuration (KryonSettings).

Operator-facing: answers "what config is Kryon actually running with?" without
grepping env vars across 100+ call sites. Reads KryonSettings (the single
source of truth) and prints it; the API key is masked.
"""

from __future__ import annotations

import argparse
import json


def add_config_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser("config", help="Show the effective Kryon core configuration")
    p.add_argument("--format", choices=("table", "json"), default="table")
    return p


def run_config_command(args) -> int:
    from kryon.config import settings

    data = settings(refresh=True).redacted_dict()
    if getattr(args, "format", "table") == "json":
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        width = max(len(k) for k in data)
        print("Kryon core configuration (KryonSettings):\n")
        for k, v in data.items():
            print(f"  {k:<{width}}  {v}")
        print("\n(Env overrides: KRYON_* / OPENAI_*. See kryon/config/settings.py.)")
    return 0
