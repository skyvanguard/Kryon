"""T4-M12: flag/parse fixes in registered red-team API tools.
- medusa: -T is concurrent-hosts, not a connection timeout.
- jwt_tool: bare -T hangs (interactive), bare -Q queries the DB (not decode).
- api_fuzzer: empty-body responses misparsed the status code as the body.
"""

from __future__ import annotations

import json
import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

from kryon.tools.api_attacks import api_fuzzer, jwt_tool, medusa


def test_medusa_no_timeout_as_dash_T(monkeypatch):
    seen = {}

    def fake_run(command, ctf=None, timeout=None):
        seen["cmd"] = command
        seen["timeout"] = timeout
        return "ACCOUNT FOUND"

    monkeypatch.setattr(medusa, "run_command", fake_run)
    medusa.medusa_attack._raw_fn(target="10.0.0.5", service="ssh", username="root", password="x", timeout=30)
    assert " -T " not in f" {seen['cmd']} "  # timeout must NOT be emitted as -T
    assert seen["timeout"] >= 900  # bounded as process timeout instead


def test_jwt_forge_no_bare_dash_T(monkeypatch):
    seen = {}
    monkeypatch.setattr(jwt_tool, "run_command", lambda command, ctf=None: seen.setdefault("cmd", command))
    jwt_tool.jwt_forge._raw_fn(token="eyJ.a.b", algorithm="HS256")
    # a trailing bare -T (interactive tamper) would hang the subprocess
    assert not seen["cmd"].rstrip().endswith("-T")
    assert " -T " not in seen["cmd"]


def test_jwt_decode_no_dash_Q(monkeypatch):
    seen = {}
    monkeypatch.setattr(jwt_tool, "run_command", lambda command, ctf=None: seen.setdefault("cmd", command))
    jwt_tool.jwt_decode._raw_fn(token="eyJ.a.b")
    assert "-Q" not in seen["cmd"]  # -Q queries the DB, not a plain decode


def test_api_fuzzer_parses_empty_body_status(monkeypatch):
    # Empty body + 500 status: curl -w yields "\n500". Must parse status=500 (not 0).
    monkeypatch.setattr(api_fuzzer, "_run_cmd", lambda cmd, timeout=15: "\n500")
    out = json.loads(api_fuzzer.fuzz_api_endpoint._raw_fn(url="http://x/api", payload_types="sqli"))
    assert out["anomalies"], "a 500 with empty body must be flagged"
    assert out["anomalies"][0]["status_code"] == "500"
