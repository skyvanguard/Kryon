"""OpenVAS env config — fire gate + runner construction."""

from __future__ import annotations

from kryon.integrations.openvas import config
from kryon.integrations.openvas.config import is_openvas_enabled, runner_from_env


def test_fire_gate_default_off(monkeypatch):
    monkeypatch.delenv("KRYON_OPENVAS_FIRE", raising=False)
    assert is_openvas_enabled() is False


def test_fire_gate_off_explicit(monkeypatch):
    monkeypatch.setenv("KRYON_OPENVAS_FIRE", "false")
    assert is_openvas_enabled() is False


def test_fire_gate_on(monkeypatch):
    monkeypatch.setenv("KRYON_OPENVAS_FIRE", "true")
    assert is_openvas_enabled() is True


def test_fire_gate_accepts_common_truthy(monkeypatch):
    for val in ("1", "yes", "on", "TRUE"):
        monkeypatch.setenv("KRYON_OPENVAS_FIRE", val)
        assert is_openvas_enabled() is True


def test_runner_from_env_builds_callable(monkeypatch):
    monkeypatch.setenv("KRYON_OPENVAS_USER", "admin")
    monkeypatch.setenv("KRYON_OPENVAS_PASSWORD", "secret")
    monkeypatch.setenv("KRYON_OPENVAS_SOCKET", "/run/gvmd/gvmd.sock")
    runner = runner_from_env()
    assert callable(runner)


def test_runner_from_env_bad_timeout_falls_back(monkeypatch):
    monkeypatch.setenv("KRYON_OPENVAS_TIMEOUT", "not-a-number")
    # Should not raise — falls back to the default timeout.
    assert callable(runner_from_env())


def test_runner_from_env_defaults_to_raw_gmp(monkeypatch):
    chosen: dict[str, dict] = {}
    monkeypatch.setattr(config, "gmp_socket_runner", lambda **kw: chosen.setdefault("gmp", kw) or (lambda x: x))
    monkeypatch.setattr(config, "gvm_cli_runner", lambda **kw: chosen.setdefault("cli", kw) or (lambda x: x))
    monkeypatch.delenv("KRYON_OPENVAS_TRANSPORT", raising=False)
    runner_from_env()
    assert "gmp" in chosen and "cli" not in chosen  # raw GMP is the default (zero Greenbone code)


def test_runner_from_env_cli_transport_opt_in(monkeypatch):
    chosen: dict[str, dict] = {}
    monkeypatch.setattr(config, "gmp_socket_runner", lambda **kw: chosen.setdefault("gmp", kw) or (lambda x: x))
    monkeypatch.setattr(config, "gvm_cli_runner", lambda **kw: chosen.setdefault("cli", kw) or (lambda x: x))
    monkeypatch.setenv("KRYON_OPENVAS_TRANSPORT", "cli")
    runner_from_env()
    assert "cli" in chosen and "gmp" not in chosen
