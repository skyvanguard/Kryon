"""Tests for drift alerting (Q2)."""

from __future__ import annotations

from types import SimpleNamespace

from kryon.notifications.drift_alert import build_drift_alert, notify_drift, run_drift_check
from kryon.state.baseline_diff import compute_diff


def _f(rule_id, host, severity="high"):
    return {"rule_id": rule_id, "host": host, "severity": severity, "message": f"{rule_id} issue"}


class _CapturingProvider:
    name = "test"

    def __init__(self):
        self.sent = None

    def send(self, *, subject, body):
        self.sent = (subject, body)
        return SimpleNamespace(provider="test", ok=True, detail="", dry_run=False)


def test_build_alert_summarizes_counts():
    prev = [_f("R1", "h1")]
    curr = [_f("R1", "h1"), _f("R9", "h1", "critical")]  # R9 new
    diff = compute_diff(prev, curr)
    subject, body = build_drift_alert(diff, "10.0.0.1", client="banco_x")
    assert "+1 new" in subject
    assert "banco_x" in subject
    assert "CRITICAL" in body  # worst severity of new
    assert "R9" in body


def test_notify_drift_sends_when_changed():
    diff = compute_diff([_f("R1", "h1")], [_f("R1", "h1"), _f("R2", "h1")])
    provider = _CapturingProvider()
    res = notify_drift(diff, "10.0.0.1", client="c", provider=provider)
    assert res is not None and res.ok
    assert provider.sent is not None
    assert "+1 new" in provider.sent[0]


def test_notify_drift_silent_when_no_changes():
    diff = compute_diff([_f("R1", "h1")], [_f("R1", "h1")])  # identical → no changes
    provider = _CapturingProvider()
    assert notify_drift(diff, "10.0.0.1", provider=provider) is None
    assert provider.sent is None


def test_notify_drift_never_raises_on_provider_error():
    class _Boom:
        def send(self, *, subject, body):
            raise RuntimeError("smtp down")

    diff = compute_diff([], [_f("R1", "h1")])
    # Should swallow the provider error and return None, not propagate.
    assert notify_drift(diff, "t", provider=_Boom()) is None


def test_alert_caps_new_finding_list():
    curr = [_f(f"R{i}", "h1") for i in range(20)]
    diff = compute_diff([], curr)
    _, body = build_drift_alert(diff, "t")
    assert "and 10 more" in body  # 20 new, list capped at 10


# ---------------------------------------------------------------------------
# R3 — run_drift_check warm-up gate (Fase 1)
# ---------------------------------------------------------------------------


def test_warmup_first_run_computes_nothing_and_stays_silent():
    # No baseline file yet → warm-up: don't diff, don't alert, even though
    # every current finding would otherwise look "new".
    provider = _CapturingProvider()
    diff, alerted = run_drift_check(
        [],
        [_f("R1", "h1"), _f("R2", "h1")],
        baseline_existed=False,
        notify_enabled=True,
        target="10.0.0.1",
        provider=provider,
    )
    assert diff is None
    assert alerted is False
    assert provider.sent is None


def test_baseline_present_with_drift_alerts_when_enabled():
    provider = _CapturingProvider()
    diff, alerted = run_drift_check(
        [_f("R1", "h1")],
        [_f("R1", "h1"), _f("R2", "h1")],  # R2 is new drift
        baseline_existed=True,
        notify_enabled=True,
        target="10.0.0.1",
        client="c",
        provider=provider,
    )
    assert diff is not None and diff.has_changes
    assert alerted is True
    assert provider.sent is not None


def test_baseline_present_but_notify_disabled_computes_diff_without_alert():
    provider = _CapturingProvider()
    diff, alerted = run_drift_check(
        [_f("R1", "h1")],
        [_f("R1", "h1"), _f("R2", "h1")],
        baseline_existed=True,
        notify_enabled=False,
        target="10.0.0.1",
        provider=provider,
    )
    assert diff is not None and diff.has_changes  # diff still computed for the report
    assert alerted is False
    assert provider.sent is None  # but no alert fired


def test_baseline_present_no_drift_does_not_alert():
    provider = _CapturingProvider()
    diff, alerted = run_drift_check(
        [_f("R1", "h1")],
        [_f("R1", "h1")],  # identical → stable, no drift
        baseline_existed=True,
        notify_enabled=True,
        target="10.0.0.1",
        provider=provider,
    )
    assert diff is not None and not diff.has_changes
    assert alerted is False
    assert provider.sent is None


def test_empty_baseline_present_treats_new_findings_as_real_drift():
    # The R3 crux: a present-but-empty baseline (previous run was clean) means
    # findings appearing now ARE real drift — must alert, not be swallowed as
    # a "first run".
    provider = _CapturingProvider()
    diff, alerted = run_drift_check(
        [],  # previous run found nothing, but the baseline file existed
        [_f("R1", "h1")],
        baseline_existed=True,
        notify_enabled=True,
        target="10.0.0.1",
        provider=provider,
    )
    assert diff is not None and len(diff.new) == 1
    assert alerted is True
    assert provider.sent is not None
