"""F202.M — _http_get pasa --compressed a curl.

Surface ground truth POC Britimp .106 2026-05-19: el :80 retorno
`Content-Type: text/html; Content-Encoding: gzip; Content-Length: 303`
con body gzip-encoded. Pre-F202.M curl recibia los bytes comprimidos
sin descomprimir -> body markers (Hikvision /doc/page/login.asp,
Vaultwarden title, password-manager signatures, X-Powered-By) NUNCA
matcheaban en hosts que respondian gzip.

Impact: la mitad de las webapps modernas habilitan gzip por default.
Sin --compressed, todos los body-marker checks fallaban silentemente.

F202.M: agregar `--compressed` al curl command de `_http_get`.
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import _http_get


def _captured_cmd_runner():
    """subprocess.run side_effect that captures the command argv for
    inspection. Returns (capture_dict, side_effect_fn)."""
    captured: dict = {}

    def _run(cmd, **kwargs):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(
            cmd, 0,
            stdout="OK\n__HTTPCODE__200",
            stderr="",
        )

    return captured, _run


class TestCompressedFlag:
    def test_curl_invocation_includes_compressed(self):
        captured, runner = _captured_cmd_runner()
        with patch("kryon.cli.engage.subprocess.run", side_effect=runner):
            _http_get("http://example.com/")
        assert "--compressed" in captured["cmd"], (
            f"_http_get must pass --compressed; got {captured['cmd']}"
        )

    def test_compressed_with_k_for_tls(self):
        """Both `-k` (skip cert verify) and `--compressed` must be present."""
        captured, runner = _captured_cmd_runner()
        with patch("kryon.cli.engage.subprocess.run", side_effect=runner):
            _http_get("https://example.com/")
        cmd = captured["cmd"]
        assert "-k" in cmd
        assert "--compressed" in cmd

    def test_compressed_for_https_with_self_signed(self):
        captured, runner = _captured_cmd_runner()
        with patch("kryon.cli.engage.subprocess.run", side_effect=runner):
            _http_get("https://192.168.1.1:8443/", timeout_s=8)
        assert "--compressed" in captured["cmd"]


class TestStillReturnsBodyAndCode:
    """Sanity — F202.M no debe romper el contrato existente."""

    def test_returns_tuple_code_body(self):
        def _run(cmd, **_kw):
            return subprocess.CompletedProcess(
                cmd, 0,
                stdout="hello world\n__HTTPCODE__200",
                stderr="",
            )

        with patch("kryon.cli.engage.subprocess.run", side_effect=_run):
            code, body = _http_get("http://example.com/")
        assert code == 200
        assert "hello world" in body

    def test_failure_returns_zero_empty(self):
        def _run(cmd, **_kw):
            raise FileNotFoundError("curl missing")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_run):
            code, body = _http_get("http://example.com/")
        assert code == 0
        assert body == ""
