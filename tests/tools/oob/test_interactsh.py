"""F115.B — TDD contract for the interactsh-client wrapper."""

from __future__ import annotations

import io
import json
from unittest.mock import MagicMock, patch

import pytest

from kryon.tools.oob.interactsh import (
    InteractshConfig,
    InteractshResult,
    _extract_domain_from_line,
    _parse_interaction_line,
    _server_is_public,
    is_interactsh_available,
    run_interactsh_batch,
)

# =====================================================================
# Pure functions
# =====================================================================


@pytest.mark.parametrize(
    "url,expected",
    [
        ("", True),  # empty defaults to public
        ("https://oast.live", True),
        ("https://oast.online/", True),
        ("https://interactsh.com:443", True),
        ("https://my-interactsh.private.lab", False),
        ("https://192.168.1.100:9999", False),
        ("http://localhost:8080", False),
    ],
)
def test_server_is_public(url, expected):
    assert _server_is_public(url) is expected


@pytest.mark.parametrize(
    "line,expected",
    [
        ("[INF] abcd1234.oast.live", "abcd1234.oast.live"),
        ("[abcd1234.my-interactsh.lab]", "abcd1234.my-interactsh.lab"),
        ("[INF] Listing 1 payload for OOB Testing", ""),
        ("", ""),
        ("random log line with no domain", ""),
        ("\x1b[32m[INF] abc.oast.live\x1b[0m", "abc.oast.live"),  # ANSI-stripped
    ],
)
def test_extract_domain_from_line(line, expected):
    assert _extract_domain_from_line(line) == expected


def test_parse_interaction_line_valid():
    evt = {
        "unique-id": "abc1234",
        "protocol": "http",
        "remote-address": "1.2.3.4",
        "timestamp": "2026-05-13T20:00:00Z",
    }
    parsed = _parse_interaction_line(json.dumps(evt))
    assert parsed is not None
    assert parsed.unique_id == "abc1234"
    assert parsed.protocol == "http"
    assert parsed.remote_address == "1.2.3.4"


def test_parse_interaction_line_malformed():
    assert _parse_interaction_line("not json") is None
    assert _parse_interaction_line("") is None
    assert _parse_interaction_line("[1,2,3]") is None  # not a dict


def test_parse_interaction_line_alternate_keys():
    """Newer interactsh-client uses `uniqueID`, `remoteAddress`."""
    evt = {"uniqueID": "abc", "protocol": "dns", "remoteAddress": "5.6.7.8"}
    parsed = _parse_interaction_line(json.dumps(evt))
    assert parsed is not None
    assert parsed.unique_id == "abc"
    assert parsed.protocol == "dns"
    assert parsed.remote_address == "5.6.7.8"


# =====================================================================
# is_interactsh_available
# =====================================================================


def test_is_interactsh_available_returns_bool():
    assert isinstance(is_interactsh_available(), bool)


# =====================================================================
# run_interactsh_batch — banca-safety gates
# =====================================================================


def test_run_batch_missing_binary():
    cfg = InteractshConfig(
        interactsh_binary="interactsh-client-definitely-not-installed-xyz123",
        server_url="https://my-interactsh.lab",  # non-public
    )
    result = run_interactsh_batch(cfg)
    assert result.binary_missing is True
    assert result.interactions == ()


def test_run_batch_public_server_blocked_by_default():
    """Default config (empty server_url) is treated as public and
    blocked unless allow_public_server=True."""
    cfg = InteractshConfig(server_url="")
    with patch("kryon.tools.oob.interactsh.is_interactsh_available", return_value=True):
        result = run_interactsh_batch(cfg)
    assert result.public_server_blocked is True
    assert "PUBLIC" in result.error


def test_run_batch_explicit_oast_blocked_by_default():
    cfg = InteractshConfig(server_url="https://oast.live")
    with patch("kryon.tools.oob.interactsh.is_interactsh_available", return_value=True):
        result = run_interactsh_batch(cfg)
    assert result.public_server_blocked is True


def test_run_batch_allow_public_when_opted_in():
    """allow_public_server=True bypasses the public-server gate."""
    cfg = InteractshConfig(server_url="https://oast.live", allow_public_server=True)
    # We patch Popen so we don't actually spawn anything; just verify
    # the gate didn't block.
    fake_proc = MagicMock()
    fake_proc.stdout = io.StringIO("")
    fake_proc.stderr = io.StringIO("")
    fake_proc.poll.return_value = 0
    fake_proc.returncode = 0
    with (
        patch("kryon.tools.oob.interactsh.is_interactsh_available", return_value=True),
        patch("kryon.tools.oob.interactsh.subprocess.Popen", return_value=fake_proc),
    ):
        result = run_interactsh_batch(cfg)
    # We allowed public; outcome is then governed by the actual run
    # logic, which (no domain produced from empty stdout) → error
    # about missing domain — but NOT a public-server block.
    assert result.public_server_blocked is False


# =====================================================================
# run_interactsh_batch — mocked subprocess
# =====================================================================


def _make_proc_with_stdout(stdout_text: str):
    """Build a fake subprocess.Popen-like object whose stdout streams
    the provided text."""
    proc = MagicMock()
    proc.stdout = io.StringIO(stdout_text)
    proc.stderr = io.StringIO("")
    proc.poll.return_value = None
    proc.returncode = 0
    return proc


def test_run_batch_extracts_domain():
    """When stdout yields the assigned domain, the result captures
    it."""
    stdout = "[INF] Listing 1 payload for OOB Testing\n[INF] abcdef12345.my-interactsh.lab\n"
    fake_proc = _make_proc_with_stdout(stdout)
    cfg = InteractshConfig(
        server_url="https://my-interactsh.lab",
        collect_seconds=0,
        startup_timeout_seconds=2.0,
    )
    with (
        patch("kryon.tools.oob.interactsh.is_interactsh_available", return_value=True),
        patch("kryon.tools.oob.interactsh.subprocess.Popen", return_value=fake_proc),
    ):
        result = run_interactsh_batch(cfg)
    assert result.callback_domain == "abcdef12345.my-interactsh.lab"
    assert result.binary_missing is False
    assert result.public_server_blocked is False


def test_run_batch_parses_interactions():
    """Interaction JSON events after the domain are parsed into
    Interaction records."""
    evt1 = {
        "unique-id": "abcdef12345",
        "protocol": "http",
        "remote-address": "1.2.3.4",
        "timestamp": "2026-05-13T20:00:00Z",
    }
    evt2 = {
        "unique-id": "abcdef99999",
        "protocol": "dns",
        "remote-address": "5.6.7.8",
        "timestamp": "2026-05-13T20:00:01Z",
    }
    stdout = "[INF] abcdef12345.my-interactsh.lab\n" + json.dumps(evt1) + "\n" + json.dumps(evt2) + "\n"
    fake_proc = _make_proc_with_stdout(stdout)
    cfg = InteractshConfig(
        server_url="https://my-interactsh.lab",
        collect_seconds=0,
        startup_timeout_seconds=2.0,
    )
    with (
        patch("kryon.tools.oob.interactsh.is_interactsh_available", return_value=True),
        patch("kryon.tools.oob.interactsh.subprocess.Popen", return_value=fake_proc),
    ):
        result = run_interactsh_batch(cfg)
    assert len(result.interactions) == 2
    protocols = {i.protocol for i in result.interactions}
    assert protocols == {"http", "dns"}


def test_run_batch_invokes_pre_collect_callback():
    """The callback fires AFTER the domain is captured but BEFORE
    we sleep for collect_seconds."""
    stdout = "[INF] my-cid.my-interactsh.lab\n"
    fake_proc = _make_proc_with_stdout(stdout)
    cfg = InteractshConfig(
        server_url="https://my-interactsh.lab",
        collect_seconds=0,
        startup_timeout_seconds=2.0,
    )

    seen: list[str] = []

    def _cb(domain: str) -> None:
        seen.append(domain)

    with (
        patch("kryon.tools.oob.interactsh.is_interactsh_available", return_value=True),
        patch("kryon.tools.oob.interactsh.subprocess.Popen", return_value=fake_proc),
    ):
        run_interactsh_batch(cfg, pre_collect_callback=_cb)
    assert seen == ["my-cid.my-interactsh.lab"]


def test_run_batch_callback_exception_is_swallowed():
    """An exception in the operator's callback shouldn't crash the
    batch run — we still want to collect whatever already arrived."""
    stdout = "[INF] my-cid.my-interactsh.lab\n"
    fake_proc = _make_proc_with_stdout(stdout)
    cfg = InteractshConfig(
        server_url="https://my-interactsh.lab",
        collect_seconds=0,
        startup_timeout_seconds=2.0,
    )

    def _cb_raises(_d: str) -> None:
        raise RuntimeError("operator's probe loop crashed")

    with (
        patch("kryon.tools.oob.interactsh.is_interactsh_available", return_value=True),
        patch("kryon.tools.oob.interactsh.subprocess.Popen", return_value=fake_proc),
    ):
        result = run_interactsh_batch(cfg, pre_collect_callback=_cb_raises)
    # No crash; we got a callback domain
    assert result.callback_domain == "my-cid.my-interactsh.lab"


def test_run_batch_no_domain_extracted():
    """If interactsh-client never prints a domain, we time out and
    return an error."""
    fake_proc = _make_proc_with_stdout("")  # empty stdout
    cfg = InteractshConfig(
        server_url="https://my-interactsh.lab",
        collect_seconds=0,
        startup_timeout_seconds=0.5,  # short
    )
    with (
        patch("kryon.tools.oob.interactsh.is_interactsh_available", return_value=True),
        patch("kryon.tools.oob.interactsh.subprocess.Popen", return_value=fake_proc),
    ):
        result = run_interactsh_batch(cfg)
    assert result.callback_domain == ""
    assert "failed to extract callback domain" in result.error


def test_run_batch_subprocess_failure_to_spawn():
    """FileNotFoundError on Popen → binary_missing."""
    cfg = InteractshConfig(server_url="https://my-interactsh.lab")
    with (
        patch("kryon.tools.oob.interactsh.is_interactsh_available", return_value=True),
        patch("kryon.tools.oob.interactsh.subprocess.Popen", side_effect=FileNotFoundError("nope")),
    ):
        result = run_interactsh_batch(cfg)
    assert result.binary_missing is True
