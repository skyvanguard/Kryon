"""F86 — Walkthrough / subset loader for CyberGym.

A walkthrough JSON describes one CVE detection task:

  {
    "slug":           "<short kebab id>",
    "cve_id":         "CVE-2023-12345",
    "project":        "libfoo",
    "repo_url":       "https://github.com/example/libfoo",
    "vuln_commit":    "<sha>",
    "patch_commit":   "<sha>",
    "expected_cwe":   "CWE-79",
    "expected_file":  "src/parser.c",
    "expected_line":  142,
    "source": {
      "type": "git" | "tarball" | "local",
      "ref":  "<url or local path>"
    },
    "category":       "memory_corruption" | "injection" | "auth" | ...,
    "status":         "ready" | "wip" | "planned",
    "wall_budget_seconds": 600
  }

Loader is intentionally schema-strict on the keys the runner needs
("slug", "cve_id", "expected_cwe", "source"). Optional fields default
sensibly when absent so partially-curated walkthroughs don't crash
the loader during bulk runs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

__all__ = [
    "load_walkthrough",
    "load_subset",
    "TaskInvalid",
]


_REQUIRED_KEYS = {"slug", "cve_id", "expected_cwe", "source"}


class TaskInvalid(ValueError):
    """Raised when a walkthrough JSON is missing a key the runner
    cannot fall back from. Carries the offending path for the CLI."""

    def __init__(self, path: Path, missing: set[str]) -> None:
        super().__init__(f"{path.name} missing required keys: {sorted(missing)}")
        self.path = path
        self.missing = missing


def load_walkthrough(path: Path) -> dict[str, Any]:
    """Load and minimally validate a single walkthrough JSON.

    Strict on the runner's contract (`_REQUIRED_KEYS`), permissive on
    everything else. Returns the raw dict — keeps the schema close to
    the source so a curator hand-editing one file doesn't have to
    update the loader."""
    data = json.loads(path.read_text(encoding="utf-8"))
    missing = _REQUIRED_KEYS - data.keys()
    if missing:
        raise TaskInvalid(path, missing)
    return data


def load_subset(manifest_path: Path) -> list[dict[str, Any]]:
    """Read the subset_NN.yaml manifest. Each entry has at minimum
    `slug` + `status`; the rest is freely descriptive for the
    scoreboard.

    The manifest is the *index* of tasks (lightweight, no per-CVE
    detail). The runner pulls full task data from the matching
    walkthrough JSON when it actually executes."""
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    tasks = data.get("tasks") if isinstance(data, dict) else None
    if not isinstance(tasks, list):
        raise TaskInvalid(manifest_path, {"tasks"})
    return tasks
