"""The orchestrator must read keys the REAL StrategicPlanner produces.

Regression (T4-C2): orchestrator.py read primary_plan["name"]/["objectives_order"]/
["estimated_time_hours"] — keys the planner never emits — so a KeyError('name')
crashed FASE 0 before any scan, taking down all three autonomous capabilities. The
existing test masked it by mocking the planner with an invented dict shape; this one
runs the REAL planner."""

from __future__ import annotations

import os

os.environ.setdefault("KRYON_RED_TEAM", "true")

from kryon.tools.autonomous.strategic_planner import StrategicPlanner  # noqa: E402


def test_real_planner_produces_the_keys_orchestrator_reads():
    plan = StrategicPlanner().autonomous_mission_planner("10.0.0.5", ["initial_access", "privilege_escalation"])
    pp = plan["primary_plan"]
    # The keys the orchestrator now reads (with .get defaults) exist in the real plan.
    assert "plan_id" in pp
    assert "stages" in pp
    assert "estimated_time" in pp
    # The OLD keys that caused KeyError('name') are NOT there — proves the bug's premise.
    assert "name" not in pp
    assert "objectives_order" not in pp
    assert "estimated_time_hours" not in pp
