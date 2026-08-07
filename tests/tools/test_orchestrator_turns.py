"""Tests for configurable max turns in EnterpriseOrchestrator."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from kryon.tools.autonomous.enterprise_orchestrator import EnterpriseOrchestrator


class TestProfileTurns:
    """Verify _PROFILE_TURNS and turn resolution logic."""

    def test_standard_profile_defaults(self):
        orch = EnterpriseOrchestrator(scope="10.0.0.1", profile="standard")
        assert orch._turns == {"recon": 3, "vuln": 3, "exploit": 5}

    def test_deep_profile_defaults(self):
        orch = EnterpriseOrchestrator(scope="10.0.0.1", profile="deep")
        assert orch._turns == {"recon": 5, "vuln": 7, "exploit": 10}

    def test_enterprise_deep_profile_defaults(self):
        orch = EnterpriseOrchestrator(scope="10.0.0.1", profile="enterprise_deep")
        assert orch._turns == {"recon": 7, "vuln": 10, "exploit": 15}

    def test_unknown_profile_falls_back_to_standard(self):
        orch = EnterpriseOrchestrator(scope="10.0.0.1", profile="nonexistent")
        assert orch._turns == {"recon": 3, "vuln": 3, "exploit": 5}

    def test_max_turns_override_applies_to_all_phases(self):
        orch = EnterpriseOrchestrator(scope="10.0.0.1", profile="deep", max_turns_override=20)
        assert orch._turns == {"recon": 20, "vuln": 20, "exploit": 20}

    def test_env_var_overrides_everything(self):
        with patch.dict(os.environ, {"KRYON_ORCHESTRATOR_MAX_TURNS": "25"}):
            orch = EnterpriseOrchestrator(scope="10.0.0.1", profile="deep", max_turns_override=10)
        assert orch._turns == {"recon": 25, "vuln": 25, "exploit": 25}

    def test_env_var_not_set_uses_override(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("KRYON_ORCHESTRATOR_MAX_TURNS", None)
            orch = EnterpriseOrchestrator(scope="10.0.0.1", max_turns_override=12)
        assert orch._turns["vuln"] == 12
        assert orch._turns["exploit"] == 12

    def test_profile_turns_has_increasing_values(self):
        """Profiles should have progressively more turns."""
        profiles = EnterpriseOrchestrator._PROFILE_TURNS
        assert profiles["standard"]["vuln"] < profiles["deep"]["vuln"]
        assert profiles["deep"]["vuln"] < profiles["enterprise_deep"]["vuln"]
        assert profiles["standard"]["exploit"] < profiles["deep"]["exploit"]
        assert profiles["deep"]["exploit"] < profiles["enterprise_deep"]["exploit"]
