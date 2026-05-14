"""F144 — Approval queue tests."""

from __future__ import annotations

from kryon.approval import ApprovalQueue, RiskLevel


def test_load_missing_returns_empty(tmp_path):
    q = ApprovalQueue.load(tmp_path / "no.json")
    assert q.pending == []


def test_request_creates_pending(tmp_path):
    q = ApprovalQueue.load(tmp_path / "q.json")
    action, auto = q.request(
        kind="remediation",
        target="x.com",
        description="disable root login",
        command="ssh root@x sed -i 's/PermitRootLogin yes/no/' /etc/ssh/sshd_config",
        risk_level=RiskLevel.HIGH.value,
    )
    assert auto is False
    assert action.status == "pending"
    assert action.risk_level == "high"


def test_save_and_load_roundtrip(tmp_path):
    path = tmp_path / "q.json"
    q = ApprovalQueue.load(path)
    q.request(kind="x", target="t", description="d", risk_level=RiskLevel.MEDIUM.value)
    q.save()
    q2 = ApprovalQueue.load(path)
    assert len(q2.pending) == 1


def test_auto_approve_low_risk_env(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYON_AUTO_APPROVE_LOW_RISK", "true")
    q = ApprovalQueue.load(tmp_path / "q.json")
    action, auto = q.request(kind="probe", target="x", description="d", risk_level=RiskLevel.LOW.value)
    assert auto is True
    assert action.status == "approved"
    assert action.decided_by == "auto"


def test_auto_approve_does_not_apply_to_high(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYON_AUTO_APPROVE_LOW_RISK", "true")
    q = ApprovalQueue.load(tmp_path / "q.json")
    action, auto = q.request(kind="probe", target="x", description="d", risk_level=RiskLevel.HIGH.value)
    assert auto is False
    assert action.status == "pending"


def test_auto_approve_does_not_apply_to_critical(monkeypatch, tmp_path):
    monkeypatch.setenv("KRYON_AUTO_APPROVE_LOW_RISK", "true")
    q = ApprovalQueue.load(tmp_path / "q.json")
    action, auto = q.request(kind="exploit", target="x", description="d", risk_level=RiskLevel.CRITICAL.value)
    assert auto is False


def test_auto_approve_disabled_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("KRYON_AUTO_APPROVE_LOW_RISK", raising=False)
    q = ApprovalQueue.load(tmp_path / "q.json")
    action, auto = q.request(kind="x", target="t", description="d", risk_level=RiskLevel.LOW.value)
    assert auto is False
    assert action.status == "pending"


def test_approve_explicit(tmp_path, monkeypatch):
    monkeypatch.delenv("KRYON_AUTO_APPROVE_LOW_RISK", raising=False)
    q = ApprovalQueue.load(tmp_path / "q.json")
    action, _ = q.request(kind="x", target="t", description="d", risk_level=RiskLevel.HIGH.value)
    assert q.approve(action.action_id, decided_by="alice") is True
    assert q.is_approved(action.action_id) is True
    refreshed = q.get(action.action_id)
    assert refreshed.decided_by == "alice"


def test_approve_unknown_returns_false(tmp_path):
    q = ApprovalQueue.load(tmp_path / "q.json")
    assert q.approve("no-such-id") is False


def test_reject_records_reason(tmp_path, monkeypatch):
    monkeypatch.delenv("KRYON_AUTO_APPROVE_LOW_RISK", raising=False)
    q = ApprovalQueue.load(tmp_path / "q.json")
    action, _ = q.request(kind="x", target="t", description="d", risk_level=RiskLevel.HIGH.value)
    assert q.reject(action.action_id, reason="out of scope") is True
    refreshed = q.get(action.action_id)
    assert refreshed.status == "rejected"
    assert refreshed.rejection_reason == "out of scope"


def test_mark_executed_after_approval(tmp_path, monkeypatch):
    monkeypatch.delenv("KRYON_AUTO_APPROVE_LOW_RISK", raising=False)
    q = ApprovalQueue.load(tmp_path / "q.json")
    action, _ = q.request(kind="x", target="t", description="d", risk_level=RiskLevel.HIGH.value)
    q.approve(action.action_id)
    assert q.mark_executed(action.action_id) is True
    refreshed = q.get(action.action_id)
    assert refreshed.status == "executed"
    assert q.is_approved(action.action_id) is True  # executed counts as approved


def test_mark_executed_unapproved_returns_false(tmp_path, monkeypatch):
    monkeypatch.delenv("KRYON_AUTO_APPROVE_LOW_RISK", raising=False)
    q = ApprovalQueue.load(tmp_path / "q.json")
    action, _ = q.request(kind="x", target="t", description="d", risk_level=RiskLevel.HIGH.value)
    # Skip approve, try to execute directly → must fail.
    assert q.mark_executed(action.action_id) is False


def test_list_filter_by_status(tmp_path, monkeypatch):
    monkeypatch.delenv("KRYON_AUTO_APPROVE_LOW_RISK", raising=False)
    q = ApprovalQueue.load(tmp_path / "q.json")
    a, _ = q.request(kind="x", target="t", description="d", risk_level=RiskLevel.HIGH.value)
    b, _ = q.request(kind="x", target="u", description="d", risk_level=RiskLevel.HIGH.value)
    q.approve(a.action_id)
    pending = q.list(status="pending")
    approved = q.list(status="approved")
    assert len(pending) == 1 and pending[0].action_id == b.action_id
    assert len(approved) == 1 and approved[0].action_id == a.action_id
