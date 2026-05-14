"""F112 — TDD contract for the ffuf wrapper."""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest

from kryon.tools.ffuf.runner import (
    FfufConfig,
    FfufHit,
    FfufResult,
    _build_args,
    _write_default_wordlist,
    embedded_wordlist,
    is_ffuf_available,
    parse_ffuf_json,
    run_ffuf,
)

# =====================================================================
# Embedded wordlist
# =====================================================================


def test_embedded_wordlist_has_high_signal_paths():
    wl = embedded_wordlist()
    assert isinstance(wl, tuple)
    assert len(wl) >= 100
    # Sample of paths that MUST be present
    must_have = {
        ".git",
        ".env",
        "admin/",
        "wp-admin/",
        "phpinfo.php",
        "actuator/heapdump",
        "swagger-ui.html",
        "robots.txt",
        "terraform.tfstate",
        "id_rsa",
        ".aws/credentials",
        "config/database.yml",
    }
    assert must_have <= set(wl)


def test_write_default_wordlist_creates_file():
    path = _write_default_wordlist()
    try:
        assert os.path.isfile(path)
        with open(path) as fh:
            content = fh.read()
        assert ".git" in content
        assert ".env" in content
    finally:
        os.unlink(path)


# =====================================================================
# JSON parser
# =====================================================================


def _ffuf_event(
    url: str = "https://target.com/admin",
    input_val: str = "admin",
    status: int = 200,
    length: int = 1234,
    content_type: str = "text/html",
) -> dict:
    return {
        "url": url,
        "input": {"FUZZ": input_val},
        "status": status,
        "length": length,
        "words": 50,
        "lines": 30,
        "content-type": content_type,
        "duration": 12_000_000,  # 12ms in ns
    }


def test_parse_ffuf_json_basic():
    doc = {
        "results": [
            _ffuf_event(input_val=".git", status=200, length=1234),
            _ffuf_event(input_val=".env", status=200, length=234),
            _ffuf_event(input_val="admin/", status=302, length=0),
        ]
    }
    hits = parse_ffuf_json(json.dumps(doc))
    assert len(hits) == 3
    inputs = {h.input for h in hits}
    assert inputs == {".git", ".env", "admin/"}


def test_parse_ffuf_json_empty():
    assert parse_ffuf_json("") == []
    assert parse_ffuf_json("{}") == []


def test_parse_ffuf_json_malformed():
    assert parse_ffuf_json("not json") == []
    # Valid JSON but wrong shape
    assert parse_ffuf_json('{"results": "not a list"}') == []


def test_parse_ffuf_json_sorts_by_status_then_input():
    doc = {
        "results": [
            _ffuf_event(input_val="zzz", status=200),
            _ffuf_event(input_val="aaa", status=302),
            _ffuf_event(input_val="bbb", status=200),
        ]
    }
    hits = parse_ffuf_json(json.dumps(doc))
    # 200s first (since 200 < 302), then sorted by input
    assert hits[0].input == "bbb"
    assert hits[1].input == "zzz"
    assert hits[2].input == "aaa"


def test_parse_ffuf_json_duration_converted_to_ms():
    doc = {"results": [_ffuf_event()]}
    hits = parse_ffuf_json(json.dumps(doc))
    assert hits[0].response_time_ms == 12


def test_parse_ffuf_json_input_as_string():
    """Some ffuf versions emit input as a string, not a dict."""
    doc = {"results": [{"url": "x", "input": "admin", "status": 200, "length": 100, "words": 1, "lines": 1}]}
    hits = parse_ffuf_json(json.dumps(doc))
    assert hits[0].input == "admin"


# =====================================================================
# Args builder
# =====================================================================


def test_build_args_includes_banca_safe_defaults():
    cfg = FfufConfig(base_url="https://target.com/FUZZ")
    args = _build_args(cfg, "/tmp/out.json", "/tmp/wordlist.txt")
    assert "-noninteractive" in args
    assert "-s" in args
    assert "-of" in args
    assert "json" in args
    # Match status allowlist
    assert "-mc" in args
    mc_idx = args.index("-mc")
    assert "200" in args[mc_idx + 1]
    # Rate limit applied
    assert "-rate" in args
    rate_idx = args.index("-rate")
    assert args[rate_idx + 1] == "10"  # default banca-safe rate


def test_build_args_methods_combined():
    cfg = FfufConfig(base_url="https://target.com/FUZZ", methods=("GET", "POST"))
    args = _build_args(cfg, "/tmp/x.json", "/tmp/w.txt")
    x_idx = args.index("-X")
    assert args[x_idx + 1] == "GET,POST"


def test_build_args_cookies_passed_as_header():
    cfg = FfufConfig(
        base_url="https://target.com/FUZZ",
        cookies=(("session", "abc"), ("csrf", "xyz")),
    )
    args = _build_args(cfg, "/tmp/x.json", "/tmp/w.txt")
    # Find the Cookie header
    cookie_headers = [args[i + 1] for i, a in enumerate(args) if a == "-H" and args[i + 1].startswith("Cookie:")]
    assert len(cookie_headers) == 1
    assert "session=abc" in cookie_headers[0]
    assert "csrf=xyz" in cookie_headers[0]


def test_build_args_custom_headers():
    cfg = FfufConfig(
        base_url="https://target.com/FUZZ",
        headers=(("X-Foo", "bar"),),
    )
    args = _build_args(cfg, "/tmp/x.json", "/tmp/w.txt")
    custom = [args[i + 1] for i, a in enumerate(args) if a == "-H" and args[i + 1].startswith("X-Foo")]
    assert custom == ["X-Foo: bar"]


def test_build_args_user_agent():
    cfg = FfufConfig(base_url="https://target.com/FUZZ")
    args = _build_args(cfg, "/tmp/x.json", "/tmp/w.txt")
    ua_args = [args[i + 1] for i, a in enumerate(args) if a == "-H" and args[i + 1].startswith("User-Agent:")]
    assert ua_args == ["User-Agent: Kryon-Ffuf/1.0 (banca-safe)"]


# =====================================================================
# run_ffuf — uses mocked subprocess
# =====================================================================


def test_run_ffuf_missing_binary():
    cfg = FfufConfig(
        base_url="https://target.com/FUZZ",
        ffuf_binary="ffuf-definitely-not-installed-xyz123",
    )
    result = run_ffuf(cfg)
    assert result.ffuf_missing is True
    assert result.hits == ()


def test_run_ffuf_missing_fuzz_placeholder():
    cfg = FfufConfig(base_url="https://target.com/no-placeholder-here")
    with patch("kryon.tools.ffuf.runner.is_ffuf_available", return_value=True):
        result = run_ffuf(cfg)
    assert result.exit_code == -2
    assert "FUZZ" in result.stderr_excerpt


def test_run_ffuf_parses_subprocess_output(tmp_path):
    """Mock subprocess.run to write a canned JSON output file."""
    canned_doc = {
        "results": [
            _ffuf_event(input_val=".git", status=200, length=234),
            _ffuf_event(input_val="admin/", status=302, length=0),
            _ffuf_event(input_val=".env", status=200, length=512),
        ]
    }

    class _FakeProc:
        stdout = ""
        stderr = ""
        returncode = 0

    def _fake_run(args, **kwargs):
        # args includes "-o /path/to/out.json"; write canned JSON there
        out_idx = args.index("-o")
        out_path = args[out_idx + 1]
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(canned_doc))
        return _FakeProc()

    cfg = FfufConfig(base_url="https://target.com/FUZZ")
    with (
        patch("kryon.tools.ffuf.runner.is_ffuf_available", return_value=True),
        patch("kryon.tools.ffuf.runner.subprocess.run", side_effect=_fake_run),
    ):
        result = run_ffuf(cfg)
    assert result.ffuf_missing is False
    assert len(result.hits) == 3
    inputs = {h.input for h in result.hits}
    assert inputs == {".git", "admin/", ".env"}


def test_run_ffuf_uses_custom_wordlist(tmp_path):
    """Operator-supplied wordlist should be used instead of embedded."""
    wl = tmp_path / "my-wordlist.txt"
    wl.write_text("custom-path\n")
    cfg = FfufConfig(
        base_url="https://target.com/FUZZ",
        wordlist_path=str(wl),
    )

    captured_args: list[list[str]] = []

    class _FakeProc:
        stdout = ""
        stderr = ""
        returncode = 0

    def _capture(args, **kwargs):
        captured_args.append(list(args))
        # Write empty results
        out_idx = args.index("-o")
        with open(args[out_idx + 1], "w") as fh:
            fh.write('{"results":[]}')
        return _FakeProc()

    with (
        patch("kryon.tools.ffuf.runner.is_ffuf_available", return_value=True),
        patch("kryon.tools.ffuf.runner.subprocess.run", side_effect=_capture),
    ):
        result = run_ffuf(cfg)
    assert result.wordlist_used == str(wl)
    w_idx = captured_args[0].index("-w")
    assert captured_args[0][w_idx + 1] == str(wl)


def test_run_ffuf_handles_timeout():
    import subprocess as sp

    cfg = FfufConfig(base_url="https://target.com/FUZZ", overall_timeout_seconds=1)

    def _raise(*args, **kwargs):
        raise sp.TimeoutExpired(cmd="ffuf", timeout=1)

    with (
        patch("kryon.tools.ffuf.runner.is_ffuf_available", return_value=True),
        patch("kryon.tools.ffuf.runner.subprocess.run", side_effect=_raise),
    ):
        result = run_ffuf(cfg)
    assert result.exit_code == -5


def test_run_ffuf_missing_wordlist():
    cfg = FfufConfig(
        base_url="https://target.com/FUZZ",
        wordlist_path="/nonexistent/path/wordlist.txt",
    )
    with patch("kryon.tools.ffuf.runner.is_ffuf_available", return_value=True):
        result = run_ffuf(cfg)
    assert result.exit_code == -4
    assert "wordlist not found" in result.stderr_excerpt


# =====================================================================
# Dataclass guarantees
# =====================================================================


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    h = FfufHit(
        url="x",
        input="x",
        http_status=200,
        content_length=0,
        content_words=0,
        content_lines=0,
    )
    with pytest.raises(FrozenInstanceError):
        h.http_status = 500  # type: ignore[misc]


def test_is_ffuf_available_returns_bool():
    assert isinstance(is_ffuf_available(), bool)
