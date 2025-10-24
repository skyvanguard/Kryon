"""
Tests for SKYNET Strategic Planning Engine
==========================================

Tests for autonomous mission planning, attack path calculation,
and dynamic plan adjustment capabilities.
"""

import pytest
import time
from skynet.tools.autonomous.strategic_planner import (
    StrategicPlanner,
    plan_autonomous_mission,
    adjust_plan_dynamically,
    calculate_all_attack_paths
)


class TestStrategicPlannerInitialization:
    """Test strategic planner initialization."""

    def test_planner_initialization(self):
        """Test planner initializes correctly."""
        planner = StrategicPlanner()

        assert planner is not None
        assert hasattr(planner, 'attack_paths')
        assert hasattr(planner, 'objective_dependencies')
        assert len(planner.attack_paths) > 0

    def test_attack_path_database(self):
        """Test attack path database has required objectives."""
        planner = StrategicPlanner()

        required_objectives = [
            "initial_access",
            "privilege_escalation",
            "lateral_movement",
            "exfiltrate_data",
            "establish_persistence"
        ]

        for objective in required_objectives:
            assert objective in planner.attack_paths, f"Missing {objective} in attack paths"
            assert len(planner.attack_paths[objective]) > 0, f"No paths defined for {objective}"

    def test_objective_dependencies(self):
        """Test objective dependencies are properly defined."""
        planner = StrategicPlanner()

        # privilege_escalation depends on initial_access
        assert "privilege_escalation" in planner.objective_dependencies
        assert "initial_access" in planner.objective_dependencies["privilege_escalation"]

        # lateral_movement depends on privilege_escalation
        assert "lateral_movement" in planner.objective_dependencies
        assert "privilege_escalation" in planner.objective_dependencies["lateral_movement"]


class TestMissionPlanning:
    """Test autonomous mission planning."""

    def test_basic_mission_planning(self):
        """Test basic mission plan generation."""
        mission_plan = plan_autonomous_mission(
            target_network="192.168.1.0/24",
            objectives=["initial_access", "privilege_escalation"],
            constraints={"max_time_hours": 2}
        )

        assert mission_plan is not None
        assert "primary_plan" in mission_plan
        assert "alternative_plans" in mission_plan
        assert "contingency_plans" in mission_plan

    def test_primary_plan_structure(self):
        """Test primary plan has required structure."""
        mission_plan = plan_autonomous_mission(
            target_network="10.10.10.0/24",
            objectives=["initial_access", "escalate_privileges"],
            constraints={"max_time_hours": 3}
        )

        primary = mission_plan["primary_plan"]

        assert "name" in primary
        assert "objectives_order" in primary
        assert "attack_paths" in primary
        assert "estimated_time_hours" in primary
        assert "success_probability" in primary
        assert "risk_level" in primary
        assert "score" in primary

    def test_alternative_plans_generated(self):
        """Test that 3 alternative plans are generated."""
        mission_plan = plan_autonomous_mission(
            target_network="192.168.1.0/24",
            objectives=["initial_access", "privilege_escalation", "exfiltrate_data"],
            constraints={"max_time_hours": 4}
        )

        # Should have 3 strategies: speed, stealth, balanced
        assert len(mission_plan["alternative_plans"]) >= 2
        assert len(mission_plan["alternative_plans"]) <= 3

    def test_objectives_ordering(self):
        """Test objectives are ordered correctly based on dependencies."""
        mission_plan = plan_autonomous_mission(
            target_network="192.168.1.0/24",
            objectives=["exfiltrate_data", "privilege_escalation", "initial_access"],
            constraints={"max_time_hours": 4}
        )

        objectives_order = mission_plan["primary_plan"]["objectives_order"]

        # initial_access should come before privilege_escalation
        initial_idx = objectives_order.index("initial_access")
        privesc_idx = objectives_order.index("privilege_escalation")
        assert initial_idx < privesc_idx

        # privilege_escalation should come before exfiltrate_data
        exfil_idx = objectives_order.index("exfiltrate_data")
        assert privesc_idx < exfil_idx

    def test_with_resources(self):
        """Test mission planning with resource constraints."""
        mission_plan = plan_autonomous_mission(
            target_network="10.10.0.0/16",
            objectives=["initial_access", "privilege_escalation"],
            constraints={
                "max_time_hours": 2,
                "stealth_level": "high",
                "noise_tolerance": "low"
            },
            resources={
                "agents_available": 1,
                "tools": ["nmap", "metasploit"],
                "bandwidth_mbps": 10
            }
        )

        assert mission_plan["primary_plan"] is not None
        # High stealth should prefer stealthy attack paths
        assert mission_plan["primary_plan"]["risk_level"] in ["low", "medium"]

    def test_stealth_focused_strategy(self):
        """Test stealth-focused strategy selection."""
        mission_plan = plan_autonomous_mission(
            target_network="192.168.1.0/24",
            objectives=["initial_access"],
            constraints={
                "max_time_hours": 8,
                "stealth_level": "high",
                "noise_tolerance": "very_low"
            }
        )

        # Stealth-focused plan should have higher stealth scores
        primary_paths = mission_plan["primary_plan"]["attack_paths"]
        if primary_paths:
            avg_stealth = sum(path.get("stealth_score", 0) for path in primary_paths.values()) / len(primary_paths)
            assert avg_stealth >= 5.0  # Should prefer stealthier paths

    def test_speed_focused_strategy(self):
        """Test speed-focused strategy selection."""
        mission_plan = plan_autonomous_mission(
            target_network="192.168.1.0/24",
            objectives=["initial_access", "privilege_escalation"],
            constraints={
                "max_time_hours": 1,  # Very limited time
                "stealth_level": "low"
            }
        )

        # Speed-focused plan should have lower estimated time
        estimated_time = mission_plan["primary_plan"]["estimated_time_hours"]
        assert estimated_time <= 1.5  # Should respect time constraint


class TestAttackPaths:
    """Test attack path calculation."""

    def test_calculate_initial_access_paths(self):
        """Test calculating paths for initial access."""
        paths = calculate_all_attack_paths(
            objective="initial_access",
            current_access={"level": "external"},
            target_info={"os": "linux"}
        )

        assert len(paths) > 0
        # Should have at least web_exploitation, password_attack paths
        path_names = [p["name"] for p in paths]
        assert any("web" in name or "password" in name or "exploit" in name for name in path_names)

    def test_calculate_privesc_paths(self):
        """Test calculating privilege escalation paths."""
        paths = calculate_all_attack_paths(
            objective="privilege_escalation",
            current_access={"level": "user", "shell": True},
            target_info={"os": "linux", "kernel": "4.15.0"}
        )

        assert len(paths) > 0
        # Should have kernel_exploit, sudo, suid paths
        path_names = [p["name"] for p in paths]
        assert any("kernel" in name or "sudo" in name or "suid" in name for name in path_names)

    def test_attack_path_structure(self):
        """Test attack paths have required structure."""
        paths = calculate_all_attack_paths(
            objective="initial_access",
            current_access={"level": "external"},
            target_info={"os": "linux"}
        )

        for path in paths:
            assert "name" in path
            assert "steps" in path
            assert "estimated_time_minutes" in path
            assert "success_rate" in path
            assert "stealth_score" in path
            assert isinstance(path["steps"], list)
            assert len(path["steps"]) > 0

    def test_path_filtering_by_access(self):
        """Test paths are filtered based on current access."""
        # External access - should only get initial access paths
        external_paths = calculate_all_attack_paths(
            objective="initial_access",
            current_access={"level": "external"},
            target_info={"os": "linux"}
        )

        # User access - should get privilege escalation paths
        user_paths = calculate_all_attack_paths(
            objective="privilege_escalation",
            current_access={"level": "user", "shell": True},
            target_info={"os": "linux"}
        )

        assert len(external_paths) > 0
        assert len(user_paths) > 0


class TestDynamicPlanAdjustment:
    """Test dynamic plan adjustment during execution."""

    def test_basic_plan_adjustment(self):
        """Test basic plan adjustment with progress update."""
        # First create a plan
        initial_plan = plan_autonomous_mission(
            target_network="192.168.1.0/24",
            objectives=["initial_access", "privilege_escalation"],
            constraints={"max_time_hours": 2}
        )

        # Simulate progress
        current_progress = {
            "completed_objectives": ["initial_access"],
            "failed_objectives": [],
            "time_elapsed_hours": 0.5,
            "current_objective": "privilege_escalation"
        }

        adjusted_plan = adjust_plan_dynamically(
            current_plan=initial_plan["primary_plan"],
            current_progress=current_progress
        )

        assert adjusted_plan is not None
        assert "adjusted_plan" in adjusted_plan
        assert "adjustments_made" in adjusted_plan
        assert "reason" in adjusted_plan

    def test_behind_schedule_adjustment(self):
        """Test adjustment when behind schedule."""
        initial_plan = plan_autonomous_mission(
            target_network="192.168.1.0/24",
            objectives=["initial_access", "privilege_escalation", "exfiltrate_data"],
            constraints={"max_time_hours": 2}
        )

        # Simulate being behind schedule
        current_progress = {
            "completed_objectives": [],
            "failed_objectives": [],
            "time_elapsed_hours": 1.5,  # 75% of time used, no objectives completed
            "current_objective": "initial_access",
            "issues": ["behind_schedule"]
        }

        adjusted_plan = adjust_plan_dynamically(
            current_plan=initial_plan["primary_plan"],
            current_progress=current_progress
        )

        # Should have adjustments to speed up
        assert len(adjusted_plan["adjustments_made"]) > 0
        adjustments = adjusted_plan["adjustments_made"]
        assert any("time" in adj["type"] or "speed" in adj["type"] for adj in adjustments)

    def test_new_discoveries_adjustment(self):
        """Test adjustment with new discoveries."""
        initial_plan = plan_autonomous_mission(
            target_network="192.168.1.0/24",
            objectives=["initial_access", "privilege_escalation"],
            constraints={"max_time_hours": 3}
        )

        current_progress = {
            "completed_objectives": ["initial_access"],
            "failed_objectives": [],
            "time_elapsed_hours": 0.8,
            "current_objective": "privilege_escalation"
        }

        # New discoveries
        new_discoveries = {
            "credentials_found": [
                {"username": "admin", "password": "weak123"}
            ],
            "vulnerabilities": ["unpatched_kernel"],
            "additional_services": ["mysql", "rdp"]
        }

        adjusted_plan = adjust_plan_dynamically(
            current_plan=initial_plan["primary_plan"],
            current_progress=current_progress,
            new_discoveries=new_discoveries
        )

        # Should incorporate new discoveries
        assert len(adjusted_plan["adjustments_made"]) > 0
        # Check if credentials were added to plan
        adjustments_text = str(adjusted_plan["adjustments_made"])
        assert "credential" in adjustments_text.lower() or "vulnerab" in adjustments_text.lower()

    def test_repeated_failures_adjustment(self):
        """Test adjustment after repeated failures."""
        initial_plan = plan_autonomous_mission(
            target_network="192.168.1.0/24",
            objectives=["initial_access", "privilege_escalation"],
            constraints={"max_time_hours": 2}
        )

        current_progress = {
            "completed_objectives": [],
            "failed_objectives": ["initial_access", "initial_access"],  # Failed twice
            "time_elapsed_hours": 1.0,
            "current_objective": "initial_access",
            "issues": ["repeated_failure"]
        }

        adjusted_plan = adjust_plan_dynamically(
            current_plan=initial_plan["primary_plan"],
            current_progress=current_progress
        )

        # Should switch to alternative strategy
        assert len(adjusted_plan["adjustments_made"]) > 0
        adjustments = adjusted_plan["adjustments_made"]
        assert any("alternative" in adj["type"] or "strategy" in adj["type"] for adj in adjustments)


class TestPlanRanking:
    """Test plan ranking and scoring."""

    def test_plan_scoring(self):
        """Test plans have valid scores."""
        mission_plan = plan_autonomous_mission(
            target_network="192.168.1.0/24",
            objectives=["initial_access", "privilege_escalation"],
            constraints={"max_time_hours": 2}
        )

        primary_score = mission_plan["primary_plan"]["score"]
        assert 0.0 <= primary_score <= 1.0

        for alt_plan in mission_plan["alternative_plans"]:
            assert 0.0 <= alt_plan["score"] <= 1.0

    def test_primary_plan_highest_score(self):
        """Test primary plan has highest score."""
        mission_plan = plan_autonomous_mission(
            target_network="192.168.1.0/24",
            objectives=["initial_access"],
            constraints={"max_time_hours": 2}
        )

        primary_score = mission_plan["primary_plan"]["score"]

        for alt_plan in mission_plan["alternative_plans"]:
            # Primary should have highest or equal score
            assert primary_score >= alt_plan["score"] - 0.01  # Small tolerance for rounding

    def test_success_probability(self):
        """Test success probabilities are reasonable."""
        mission_plan = plan_autonomous_mission(
            target_network="192.168.1.0/24",
            objectives=["initial_access", "privilege_escalation", "exfiltrate_data"],
            constraints={"max_time_hours": 4}
        )

        success_prob = mission_plan["primary_plan"]["success_probability"]
        assert 0.0 <= success_prob <= 1.0
        # With multiple objectives, success should be moderate
        assert 0.3 <= success_prob <= 0.95


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_single_objective(self):
        """Test planning with single objective."""
        mission_plan = plan_autonomous_mission(
            target_network="192.168.1.0/24",
            objectives=["initial_access"],
            constraints={"max_time_hours": 1}
        )

        assert mission_plan is not None
        assert len(mission_plan["primary_plan"]["objectives_order"]) == 1

    def test_no_constraints(self):
        """Test planning without constraints."""
        mission_plan = plan_autonomous_mission(
            target_network="192.168.1.0/24",
            objectives=["initial_access"]
        )

        assert mission_plan is not None
        assert mission_plan["primary_plan"] is not None

    def test_no_resources(self):
        """Test planning without resource specification."""
        mission_plan = plan_autonomous_mission(
            target_network="192.168.1.0/24",
            objectives=["initial_access", "privilege_escalation"]
        )

        assert mission_plan is not None
        # Should use defaults
        assert mission_plan["primary_plan"]["estimated_time_hours"] > 0

    def test_unknown_objective(self):
        """Test handling of unknown objectives."""
        # Should handle gracefully or skip unknown objectives
        mission_plan = plan_autonomous_mission(
            target_network="192.168.1.0/24",
            objectives=["initial_access", "unknown_objective", "privilege_escalation"]
        )

        # Should still create a plan with known objectives
        assert mission_plan is not None
        objectives_order = mission_plan["primary_plan"]["objectives_order"]
        assert "initial_access" in objectives_order
        assert "privilege_escalation" in objectives_order


class TestPerformance:
    """Test performance of planning operations."""

    def test_planning_performance(self):
        """Test planning completes in reasonable time."""
        start_time = time.time()

        mission_plan = plan_autonomous_mission(
            target_network="192.168.1.0/24",
            objectives=["initial_access", "privilege_escalation", "lateral_movement"],
            constraints={"max_time_hours": 4}
        )

        planning_time = time.time() - start_time

        assert mission_plan is not None
        # Planning should complete in under 1 second
        assert planning_time < 1.0

    def test_large_objective_list(self):
        """Test planning with many objectives."""
        all_objectives = [
            "initial_access",
            "privilege_escalation",
            "lateral_movement",
            "exfiltrate_data",
            "establish_persistence"
        ]

        start_time = time.time()

        mission_plan = plan_autonomous_mission(
            target_network="10.0.0.0/8",
            objectives=all_objectives,
            constraints={"max_time_hours": 8}
        )

        planning_time = time.time() - start_time

        assert mission_plan is not None
        assert len(mission_plan["primary_plan"]["objectives_order"]) == len(all_objectives)
        # Should still complete quickly
        assert planning_time < 2.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
