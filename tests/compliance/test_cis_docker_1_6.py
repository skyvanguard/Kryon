"""Structural tests for CIS Docker Benchmark 1.6 framework (F37)."""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

try:
    _importer = importlib.import_module("kryon.compliance.cis.importer")
    load_framework = _importer.load_framework
except (ImportError, ModuleNotFoundError):
    pytest.skip("compliance/cis not importable", allow_module_level=True)

_YAML = (
    Path(__file__).resolve().parents[2]
    / "src/kryon/compliance/cis/frameworks/cis-docker-1.6.yaml"
)
_ID_RE = re.compile(r"^CIS-DKR-\d+(\.\d+){1,3}$")


@pytest.fixture(scope="module")
def framework():
    return load_framework(_YAML)


def test_loads(framework):
    assert framework.metadata.id == "cis-docker-1.6"


def test_min_checks(framework):
    assert len(framework) >= 50, f"only {len(framework)}"


def test_ids_follow_format(framework):
    for c in framework.checks:
        assert _ID_RE.match(c.id), c.id


def test_sections_covered(framework):
    sections = {c.section.split(".", 1)[0] for c in framework.checks}
    assert {"1", "2", "3", "4", "5"} <= sections


def test_natural_sort(framework):
    from kryon.compliance.runner import _natural_sort_key
    ids = [c.id for c in framework.checks]
    assert ids == sorted(ids, key=_natural_sort_key)


def _check_blob(c) -> str:
    return " ".join(
        (getattr(c, f) or "").lower()
        for f in ("title", "rationale", "remediation", "command")
    )


def test_daemon_config_checks_present(framework):
    """Section 2 (Docker daemon config) must have icc, tls, userns-remap, no-new-privs checks."""
    section_2 = [c for c in framework.checks if c.section.startswith("2")]
    assert len(section_2) >= 15, f"section 2 has only {len(section_2)} checks"

    blob = " ".join(_check_blob(c) for c in section_2)
    for kw in ("icc", "tls", "userns", "no-new-privileges", "live-restore"):
        assert kw in blob, f"section 2 missing keyword {kw!r}"


def test_container_runtime_checks_present(framework):
    """Section 4 (container runtime) must cover --privileged, host-mounts, memory/cpu limits."""
    section_4 = [c for c in framework.checks if c.section.startswith("4")]
    assert len(section_4) >= 8, f"section 4 has only {len(section_4)} checks"

    blob = " ".join(_check_blob(c) for c in section_4)
    for kw in ("privileged", "memory", "read-only", "host pid"):
        assert kw in blob, f"section 4 missing {kw!r}"


def test_critical_controls_exist(framework):
    """At least 2 CRITICAL-level controls for Docker (privileged + exposed daemon)."""
    critical = [c for c in framework.checks if c.severity == "CRITICAL"]
    assert len(critical) >= 2, f"only {len(critical)} CRITICAL controls"


def test_docker_commands_used(framework):
    """Most checks should use docker/inspect/info CLI or file-level inspection."""
    docker_cmds = [
        c for c in framework.checks
        if "docker " in c.command or "dockerd" in c.command or "daemon.json" in c.command
    ]
    assert len(docker_cmds) >= 20, f"expected >=20 docker-based checks, got {len(docker_cmds)}"
