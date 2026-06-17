"""Deterministic web enumeration (directories + vhosts/subdomains).

Pins the ffuf -json record shape captured live (FUZZ is base64-encoded) and the
command construction, so the hybrid phase reliably enumerates content the way a
weak agent couldn't (right wordlist + auto-calibration).
"""

from __future__ import annotations

import base64

from kryon.intelligence.web_enum import (
    DEFAULT_DIR_WORDLIST,
    DEFAULT_VHOST_WORDLIST,
    WebDiscovery,
    build_ffuf_dir_cmd,
    build_ffuf_vhost_cmd,
    parse_ffuf_json,
    run_web_enum,
)


def _ffuf_record(fuzz: str, status: int, length: int, url: str = "http://t/x") -> str:
    b64 = base64.b64encode(fuzz.encode()).decode()
    return (
        f'{{"input":{{"FFUFHASH":"abc","FUZZ":"{b64}"}},"position":1,'
        f'"status":{status},"length":{length},"words":1,"lines":2,"url":"{url}",'
        f'"host":"t"}}'
    )


# ---------------------------------------------------------------------------
# Command construction (pure)
# ---------------------------------------------------------------------------


def test_dir_cmd_uses_FUZZ_calibration_and_json():
    cmd = build_ffuf_dir_cmd("http://creative.thm", "/wl/dirs.txt")
    assert "-u http://creative.thm/FUZZ" in cmd
    assert "-w /wl/dirs.txt" in cmd
    assert "-ac" in cmd  # auto-calibration → filters baseline/404
    assert "-json" in cmd
    assert "-mc " in cmd


def test_dir_cmd_strips_trailing_slash():
    assert "http://t/FUZZ" in build_ffuf_dir_cmd("http://t/", "/wl")


def test_dir_cmd_with_host_header():
    # Bare-IP target with a vhost → fuzz the IP WITH the Host header so we hit the
    # real content, not the 301 redirect.
    cmd = build_ffuf_dir_cmd("http://10.0.0.1", "/wl", host_header="creative.thm")
    assert "-u http://10.0.0.1/FUZZ" in cmd
    assert '-H "Host: creative.thm"' in cmd


def test_vhost_cmd_uses_host_header_and_calibration():
    cmd = build_ffuf_vhost_cmd("http://10.0.0.1", "creative.thm", "/wl/subs.txt")
    assert '-H "Host: FUZZ.creative.thm"' in cmd
    assert "-w /wl/subs.txt" in cmd
    assert "-ac" in cmd
    assert "-json" in cmd


def test_default_wordlists_are_correct_kind():
    # dir wordlist = web-content; vhost wordlist = DNS subdomains. The whole bug
    # was the agent using a dir wordlist for vhosts.
    assert "Web-Content" in DEFAULT_DIR_WORDLIST
    assert "DNS" in DEFAULT_VHOST_WORDLIST and "subdomains" in DEFAULT_VHOST_WORDLIST


# ---------------------------------------------------------------------------
# JSON parsing (pure) — FUZZ is base64
# ---------------------------------------------------------------------------


def test_parse_dir_decodes_base64_fuzz():
    out = _ffuf_record("admin", 301, 178) + "\n" + _ffuf_record("login", 200, 543)
    res = parse_ffuf_json(out, kind="dir")
    assert [(d.value, d.status, d.size) for d in res] == [("admin", 301, 178), ("login", 200, 543)]
    assert all(d.kind == "dir" for d in res)


def test_parse_vhost_builds_fqdn():
    out = _ffuf_record("beta", 200, 1234)
    res = parse_ffuf_json(out, kind="vhost", domain="creative.thm")
    assert res == [WebDiscovery(kind="vhost", value="beta.creative.thm", status=200, size=1234)]


def test_parse_ignores_non_json_and_dedups():
    out = "\n".join(
        [
            "Some ffuf banner line",
            _ffuf_record("admin", 200, 10),
            "::: progress :::",
            _ffuf_record("admin", 200, 10),  # duplicate
            "{not valid json",
        ]
    )
    res = parse_ffuf_json(out, kind="dir")
    assert len(res) == 1 and res[0].value == "admin"


def test_parse_empty_returns_empty():
    assert parse_ffuf_json("", kind="dir") == []


# ---------------------------------------------------------------------------
# Orchestration with injected runner
# ---------------------------------------------------------------------------


def test_run_web_enum_runs_dir_and_vhost():
    calls = []

    def fake_runner(cmd: str, timeout: int) -> str:
        calls.append(cmd)
        if "Host: FUZZ" in cmd:
            return _ffuf_record("beta", 200, 1200)
        return _ffuf_record("admin", 301, 178) + "\n" + _ffuf_record("uploads", 200, 99)

    res = run_web_enum("http://creative.thm", runner=fake_runner)
    kinds = {(d.kind, d.value) for d in res}
    assert ("dir", "admin") in kinds
    assert ("dir", "uploads") in kinds
    assert ("vhost", "beta.creative.thm") in kinds
    assert len(calls) == 2  # one dir, one vhost


def test_run_web_enum_skips_vhost_for_bare_ip():
    calls = []

    def fake_runner(cmd: str, timeout: int) -> str:
        calls.append(cmd)
        return _ffuf_record("admin", 200, 10)

    res = run_web_enum("http://10.67.180.226", runner=fake_runner)
    # No domain → no vhost fuzzing (only the dir pass runs).
    assert len(calls) == 1
    assert all(d.kind == "dir" for d in res)


def test_run_web_enum_ip_with_vhost_uses_host_header_for_dirs():
    # The bug we hit live: a bare-IP target redirects to a vhost. Dir enum must
    # hit the IP WITH the Host header (real content), and vhost enum fuzzes
    # FUZZ.<domain>. Neither depends on /etc/hosts.
    calls = []

    def fake_runner(cmd: str, timeout: int) -> str:
        calls.append(cmd)
        if "Host: FUZZ" in cmd:
            return _ffuf_record("beta", 200, 1)
        return _ffuf_record("admin", 301, 178)  # dir enum (with Host: creative.thm)

    res = run_web_enum("http://10.66.161.85", runner=fake_runner, vhost_domain="creative.thm")

    dir_cmds = [c for c in calls if "Host: FUZZ" not in c]
    vhost_cmds = [c for c in calls if "Host: FUZZ" in c]
    assert any('-H "Host: creative.thm"' in c for c in dir_cmds)  # dirs via Host header
    assert any("Host: FUZZ.creative.thm" in c for c in vhost_cmds)  # subdomain fuzzing
    found = {(d.kind, d.value) for d in res}
    assert ("dir", "admin") in found
    assert ("vhost", "beta.creative.thm") in found


def test_run_web_enum_runner_error_does_not_raise():
    def boom(cmd: str, timeout: int) -> str:
        raise RuntimeError("ffuf crashed")

    assert run_web_enum("http://creative.thm", runner=boom) == []
