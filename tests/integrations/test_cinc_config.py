"""Cinc Auditor env config — fire gate, profiles, target + auth args."""

from __future__ import annotations

from kryon.integrations.cinc.config import (
    build_ssh_extra_args,
    build_target,
    is_cinc_enabled,
    profiles_from_env,
)


def test_fire_gate_default_off(monkeypatch):
    monkeypatch.delenv("KRYON_CINC_FIRE", raising=False)
    assert is_cinc_enabled() is False


def test_fire_gate_on(monkeypatch):
    monkeypatch.setenv("KRYON_CINC_FIRE", "true")
    assert is_cinc_enabled() is True


def test_profiles_default_devsec(monkeypatch):
    monkeypatch.delenv("KRYON_CINC_PROFILES", raising=False)
    profs = profiles_from_env()
    assert any("ssh-baseline" in p for p in profs)
    assert any("linux-baseline" in p for p in profs)


def test_profiles_override(monkeypatch):
    monkeypatch.setenv("KRYON_CINC_PROFILES", "https://x/nginx-baseline, /local/mysql ")
    assert profiles_from_env() == ["https://x/nginx-baseline", "/local/mysql"]


def test_build_target_ssh():
    assert build_target("10.0.0.5", ssh_user="root") == "ssh://root@10.0.0.5"


def test_build_target_local_when_no_host():
    assert build_target("localhost") == "local://"
    assert build_target("") == "local://"


def test_build_ssh_extra_args():
    args = build_ssh_extra_args(ssh_key="/k.pem", ssh_password="pw", ssh_port=2222)
    assert "-i" in args and "/k.pem" in args
    assert "--password" in args and "pw" in args
    assert "--port" in args and "2222" in args


def test_build_ssh_extra_args_default_port_omitted():
    assert "--port" not in build_ssh_extra_args(ssh_port=22)
