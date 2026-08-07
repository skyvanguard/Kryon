"""Tests for the active target-health monitor (back-off layer)."""

from __future__ import annotations

from kryon.validation.target_health import TargetHealthMonitor


def test_warming_up_is_healthy():
    m = TargetHealthMonitor(min_samples=5)
    m.record(status_code=200, duration_ms=50)
    a = m.assessment()
    assert a.state == "healthy"
    assert a.backoff_seconds == 0.0


def test_healthy_baseline():
    m = TargetHealthMonitor()
    for _ in range(6):
        m.record(status_code=200, duration_ms=50)
    assert m.assessment().state == "healthy"
    assert m.should_back_off() is False


def test_degraded_on_moderate_error_rate():
    m = TargetHealthMonitor()
    for _ in range(5):
        m.record(status_code=200, duration_ms=50)
    m.record(status_code=500, error=True)
    m.record(status_code=429)  # rate-limited counts as stress
    a = m.assessment()
    assert a.state == "degraded"
    assert a.backoff_seconds > 0


def test_unhealthy_on_high_error_rate():
    m = TargetHealthMonitor()
    for _ in range(5):
        m.record(status_code=200, duration_ms=50)
    for _ in range(5):
        m.record(status_code=503, error=True)
    a = m.assessment()
    assert a.state == "unhealthy"
    assert a.backoff_seconds >= 60.0


def test_degraded_on_latency_spike():
    m = TargetHealthMonitor(latency_factor=3.0)
    for _ in range(5):
        m.record(status_code=200, duration_ms=100)  # baseline ~100ms
    for _ in range(5):
        m.record(status_code=200, duration_ms=500)  # latency climbs
    a = m.assessment()
    assert a.state in ("degraded", "unhealthy")
    assert m.should_back_off() is True
