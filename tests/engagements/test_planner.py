"""Tests for engagement planner."""

import json

from kryon.engagements.models import Engagement, PhaseType
from kryon.engagements.planner import (
    _generate_default_plan,
    _parse_plan_json,
    _validate_plan,
    create_phases_from_plan,
)


class TestDefaultPlan:
    def test_basic_5day(self):
        e = Engagement(client_name="Test", targets=["10.0.0.0/24"], duration_days=5)
        plan = _generate_default_plan(e)
        assert "days" in plan
        assert len(plan["days"]) >= 4

        types = [p["phase_type"] for d in plan["days"] for p in d["phases"]]
        assert "reconnaissance" in types
        assert "reporting" in types
        # Reporting should be last
        assert plan["days"][-1]["phases"][-1]["phase_type"] == "reporting"

    def test_2day_plan(self):
        e = Engagement(client_name="Test", targets=["10.0.0.1"], duration_days=2)
        plan = _generate_default_plan(e)
        assert len(plan["days"]) >= 2
        assert plan["days"][0]["phases"][0]["phase_type"] == "reconnaissance"

    def test_1day_plan(self):
        e = Engagement(client_name="Test", targets=["10.0.0.1"], duration_days=1)
        plan = _generate_default_plan(e)
        assert len(plan["days"]) >= 1

    def test_10day_plan_has_lateral(self):
        e = Engagement(client_name="Test", targets=["10.0.0.0/16"], duration_days=10)
        plan = _generate_default_plan(e)
        types = [p["phase_type"] for d in plan["days"] for p in d["phases"]]
        assert "lateral_movement" in types


class TestPlanParsing:
    def test_valid_json(self):
        text = json.dumps(
            {
                "days": [
                    {"day": 1, "phases": [{"phase_type": "reconnaissance", "agent_key": "recon_scout"}]},
                ],
                "rationale": "test",
            }
        )
        plan = _parse_plan_json(text)
        assert plan is not None
        assert len(plan["days"]) == 1

    def test_json_in_markdown(self):
        text = '```json\n{"days": [{"day": 1, "phases": [{"phase_type": "reconnaissance", "agent_key": "recon_scout"}]}]}\n```'
        plan = _parse_plan_json(text)
        assert plan is not None

    def test_invalid_json(self):
        assert _parse_plan_json("not json at all") is None

    def test_empty_input(self):
        assert _parse_plan_json("") is None
        assert _parse_plan_json(None) is None

    def test_invalid_phase_type(self):
        plan = {"days": [{"day": 1, "phases": [{"phase_type": "invalid_type", "agent_key": "x"}]}]}
        assert _validate_plan(plan) is None

    def test_auto_fix_agent_key(self):
        plan = {"days": [{"day": 1, "phases": [{"phase_type": "reconnaissance", "agent_key": "wrong_agent"}]}]}
        validated = _validate_plan(plan)
        assert validated is not None
        assert validated["days"][0]["phases"][0]["agent_key"] == "recon_scout"


class TestCreatePhases:
    def test_creates_correct_phases(self):
        e = Engagement(client_name="Test", targets=["10.0.0.1"], duration_days=3)
        plan = _generate_default_plan(e)
        phases = create_phases_from_plan(e, plan)
        assert len(phases) >= 2
        assert all(p.engagement_id == e.id for p in phases)
        assert phases[0].phase_type == PhaseType.RECONNAISSANCE
