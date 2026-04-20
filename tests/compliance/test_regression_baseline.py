"""Pytest wrapper for the compliance regression harness (F45).

Fails if any registered framework has regressed (fewer checks, severity
downgrade, section emptied, or orphan cross-mapping references) relative
to the committed baseline.
"""

from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_HARNESS_PATH = _REPO / "scripts/compliance/regression_bench.py"
_BASELINE_PATH = _REPO / "tests/compliance/baselines/regression_baseline.json"


@pytest.fixture(scope="module")
def harness():
    """Import the harness as a module from its script path."""
    if not _HARNESS_PATH.exists():
        pytest.skip("regression harness not present")
    spec = importlib.util.spec_from_file_location("_regression_bench", _HARNESS_PATH)
    if spec is None or spec.loader is None:
        pytest.skip("cannot load regression harness spec")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_harness_imports_registered_frameworks(harness):
    """Harness must be able to see at least the expected frameworks."""
    snap = harness.build_snapshot()
    assert snap["totals"]["frameworks"] >= 7, snap["totals"]
    assert snap["totals"]["checks"] >= 300, snap["totals"]


def test_baseline_file_exists():
    assert _BASELINE_PATH.exists(), (
        f"baseline missing at {_BASELINE_PATH}; run: "
        f"python scripts/compliance/regression_bench.py --emit"
    )


def test_no_regression_against_baseline(harness):
    """The core CI assertion: no ratchet-down vs. committed baseline."""
    import json
    baseline = json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))
    current = harness.build_snapshot()
    problems = harness.compare(current, baseline)
    assert problems == [], (
        "Compliance regression detected:\n  - "
        + "\n  - ".join(problems)
        + "\n\nIf intentional, run: python scripts/compliance/regression_bench.py --emit"
    )


def test_no_orphan_cross_mapping_refs(harness):
    """Every framework referenced in CROSS_MAPPINGS or FRAMEWORK_META must
    correspond to an actually-registered YAML."""
    snap = harness.build_snapshot()
    assert snap["orphans"]["cross_mapping"] == [], (
        f"cross-mapping references {snap['orphans']['cross_mapping']} "
        f"not present in any registered framework"
    )
    assert snap["orphans"]["framework_meta"] == [], (
        f"FRAMEWORK_META entries {snap['orphans']['framework_meta']} "
        f"do not match any registered framework YAML"
    )


def test_critical_check_floor(harness):
    """Banking-oriented frameworks must retain a minimum CRITICAL coverage."""
    snap = harness.build_snapshot()
    assert snap["totals"]["critical_checks"] >= 30, (
        f"only {snap['totals']['critical_checks']} CRITICAL checks "
        f"across all frameworks; banking audits need >=30"
    )
