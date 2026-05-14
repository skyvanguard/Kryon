"""F136 — Checkpoint tests."""

from __future__ import annotations

from dataclasses import dataclass

from kryon.state.checkpoint import (
    Checkpoint,
    CheckpointPhase,
    build_checkpoint,
    delete_checkpoint,
    list_checkpoints,
    load_checkpoint,
    save_checkpoint,
)


@dataclass
class _F:
    rule_id: str
    severity: str = "MEDIUM"
    host: str = "x"
    message: str = ""
    evidence: str = ""


# ---------------------------------------------------------------------------
# Save + load roundtrip
# ---------------------------------------------------------------------------


def test_save_then_load_roundtrip(tmp_path):
    cp = Checkpoint(
        engagement_id="eng-1",
        target="x.com",
        scope="x.com",
        families=["fortigate"],
        plan_phases=[
            CheckpointPhase(name="recon", status="completed", agent_key="r", max_turns=3),
            CheckpointPhase(name="vuln_scan", status="pending", agent_key="v", max_turns=5),
        ],
        findings=[{"rule_id": "http-plaintext", "host": "x", "severity": "HIGH"}],
        new_findings=[],
        goal={"kind": "recon", "raw": "x", "params": {"min_services": 3}},
        verdict_info=None,
        saved_at="2026-05-14T18:00:00Z",
    )
    written = save_checkpoint(cp, base=tmp_path)
    assert written is not None
    loaded = load_checkpoint("eng-1", base=tmp_path)
    assert loaded is not None
    assert loaded.engagement_id == "eng-1"
    assert len(loaded.plan_phases) == 2
    assert loaded.plan_phases[1].status == "pending"
    assert loaded.findings[0]["rule_id"] == "http-plaintext"
    assert loaded.goal["kind"] == "recon"


def test_load_missing_returns_none(tmp_path):
    assert load_checkpoint("never-saved", base=tmp_path) is None


def test_load_malformed_returns_none(tmp_path):
    (tmp_path / "broken.json").write_text("not json", encoding="utf-8")
    assert load_checkpoint("broken", base=tmp_path) is None


# ---------------------------------------------------------------------------
# first_pending_phase_index
# ---------------------------------------------------------------------------


def test_first_pending_returns_index():
    cp = Checkpoint(
        engagement_id="x",
        target="x",
        scope="x",
        families=[],
        plan_phases=[
            CheckpointPhase(name="recon", status="completed", agent_key="r", max_turns=3),
            CheckpointPhase(name="vuln_scan", status="failed", agent_key="v", max_turns=3),
            CheckpointPhase(name="reporting", status="pending", agent_key="rep", max_turns=2),
        ],
        findings=[],
        new_findings=[],
        goal=None,
        verdict_info=None,
        saved_at="2026-05-14T18:00:00Z",
    )
    assert cp.first_pending_phase_index() == 2


def test_first_pending_returns_none_when_all_decided():
    cp = Checkpoint(
        engagement_id="x",
        target="x",
        scope="x",
        families=[],
        plan_phases=[
            CheckpointPhase(name="r", status="completed", agent_key="r", max_turns=3),
        ],
        findings=[],
        new_findings=[],
        goal=None,
        verdict_info=None,
        saved_at="2026-05-14T18:00:00Z",
    )
    assert cp.first_pending_phase_index() is None


# ---------------------------------------------------------------------------
# build_checkpoint coercion
# ---------------------------------------------------------------------------


def test_build_from_dataclass_findings(tmp_path):
    findings = [_F(rule_id="A"), _F(rule_id="B")]
    cp = build_checkpoint(
        engagement_id="eng",
        target="x",
        scope="x",
        families=[],
        plan_phases=[],
        findings=findings,
        new_findings=[],
    )
    assert len(cp.findings) == 2
    assert cp.findings[0]["rule_id"] == "A"


def test_build_serializes_goal():
    from kryon.tools.autonomous.engagement_goal import EngagementGoal, GoalKind

    goal = EngagementGoal(kind=GoalKind.COMPLIANCE, raw="audit PCI-DSS", params={"framework": "PCI-DSS"})
    cp = build_checkpoint(
        engagement_id="x",
        target="x",
        scope="x",
        families=[],
        plan_phases=[],
        findings=[],
        new_findings=[],
        goal=goal,
    )
    assert cp.goal["kind"] == "compliance"
    assert cp.goal["params"]["framework"] == "PCI-DSS"


def test_build_phase_status_value_unwrapped():
    from kryon.tools.autonomous.pentest_planner import PhaseStatus, PlanPhase

    phases = [PlanPhase(name="recon", agent_key="r", max_turns=3, status=PhaseStatus.COMPLETED)]
    cp = build_checkpoint(
        engagement_id="x",
        target="x",
        scope="x",
        families=[],
        plan_phases=phases,
        findings=[],
        new_findings=[],
    )
    assert cp.plan_phases[0].status == "completed"


# ---------------------------------------------------------------------------
# list + delete
# ---------------------------------------------------------------------------


def test_list_returns_all_checkpoints(tmp_path):
    save_checkpoint(
        build_checkpoint(
            engagement_id="A", target="x", scope="x", families=[], plan_phases=[], findings=[], new_findings=[]
        ),
        base=tmp_path,
    )
    save_checkpoint(
        build_checkpoint(
            engagement_id="B", target="y", scope="y", families=[], plan_phases=[], findings=[], new_findings=[]
        ),
        base=tmp_path,
    )
    cps = list_checkpoints(base=tmp_path)
    ids = {c.engagement_id for c in cps}
    assert ids == {"A", "B"}


def test_delete_removes_file(tmp_path):
    save_checkpoint(
        build_checkpoint(
            engagement_id="A", target="x", scope="x", families=[], plan_phases=[], findings=[], new_findings=[]
        ),
        base=tmp_path,
    )
    assert delete_checkpoint("A", base=tmp_path) is True
    assert load_checkpoint("A", base=tmp_path) is None


def test_delete_missing_returns_false(tmp_path):
    assert delete_checkpoint("nope", base=tmp_path) is False
