"""Wiring tests: autonomous_ctf_solver + run_network_pivot registered under
RED_TEAM and offered by their skills (with V4-Flash available, the heavy
LLM-driven orchestrators are worth exposing to the agent).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from kryon.skills.tool_budget import build_tool_registry
from kryon.tools.autonomous import network_pivot_tool as npt
from kryon.tools.autonomous.network_pivot_tool import _network_pivot_impl

_PLAYBOOKS = Path(__file__).resolve().parents[3] / "src/kryon/skills/playbooks"


def _fm(md_path: Path) -> dict:
    return yaml.safe_load(md_path.read_text(encoding="utf-8").split("---")[1])


# --- registration (RED_TEAM gate) -------------------------------------------


def test_ctf_solver_registered_only_under_red_team(monkeypatch):
    monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
    assert "autonomous_ctf_solver" not in build_tool_registry()

    monkeypatch.setenv("KRYON_RED_TEAM", "true")
    assert "autonomous_ctf_solver" in build_tool_registry()


def test_network_pivot_registered_only_under_red_team(monkeypatch):
    assert npt.run_network_pivot.name == "run_network_pivot"

    monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
    assert "run_network_pivot" not in build_tool_registry()

    monkeypatch.setenv("KRYON_RED_TEAM", "true")
    assert "run_network_pivot" in build_tool_registry()


def test_skills_offer_the_tools():
    assert "autonomous_ctf_solver" in _fm(_PLAYBOOKS / "ctf-master.md")["required_tools"]
    assert "run_network_pivot" in _fm(_PLAYBOOKS / "pentest.md")["required_tools"]


# --- run_network_pivot double gate ------------------------------------------


def test_pivot_empty_entry():
    assert _network_pivot_impl("").startswith("ERROR")


def test_pivot_fire_off(monkeypatch):
    monkeypatch.delenv("KRYON_AUTOSCAN_FIRE", raising=False)
    out = _network_pivot_impl("10.0.0.5", "www-data", ssh_key="/tmp/id_rsa")
    assert "OFF" in out
    assert "audit_target" in out  # points at the read-only alternative


def test_pivot_runs_when_fired(monkeypatch):
    monkeypatch.setenv("KRYON_AUTOSCAN_FIRE", "true")

    captured = {}

    def fake_pivot(*, entry_point_ip, entry_credentials, **k):
        captured["ip"] = entry_point_ip
        captured["creds"] = entry_credentials
        return {"objective_achieved": True, "final_access_level": "root", "pivot_chain": ["10.0.0.5"]}

    import kryon.tools.autonomous.orchestrator as orch

    monkeypatch.setattr(orch, "autonomous_network_pivot", fake_pivot)
    out = _network_pivot_impl("10.0.0.5", "www-data", password="pass", objective="domain_admin")

    assert "Autonomous network pivot" in out
    assert captured["ip"] == "10.0.0.5"
    assert captured["creds"]["username"] == "www-data"
    assert captured["creds"]["password"] == "pass"


def test_pivot_exception_surfaced(monkeypatch):
    monkeypatch.setenv("KRYON_AUTOSCAN_FIRE", "true")

    import kryon.tools.autonomous.orchestrator as orch

    def boom(**k):
        raise RuntimeError("tunnel failed")

    monkeypatch.setattr(orch, "autonomous_network_pivot", boom)
    out = _network_pivot_impl("10.0.0.5", "user", password="p")
    assert out.startswith("ERROR during network pivot")
