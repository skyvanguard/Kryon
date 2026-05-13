"""F87.2 — TDD contract for the BOLA detector.

Coverage groups:
  - is_object_leveled_path_param heuristic (id, *Id, *_id, uuid, etc.)
  - plan_probes filters (GET only, security required, deterministic)
  - Risk classification (top-level vs nested vs deprecated)
  - Verdict heuristic (200+body, 200+empty, 401/403, 404, 5xx)
  - Banca-safety: dry-run default; only-GET enforced; fire gate
    requires BOTH env + arg; hard cap on ids.
  - URL substitution edge cases (multiple path params, missing
    placeholder).
  - Correlator aggregation.
"""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import patch

import pytest

from kryon.tools.api.bola_detector import (
    DEFAULT_MAX_IDS_PER_ENDPOINT,
    BOLACandidate,
    BOLAFinding,
    _classify_response,
    _substitute_path,
    correlate_findings,
    execute_probe,
    is_object_leveled_path_param,
    plan_probes,
)
from kryon.tools.api.openapi_importer import (
    AuthScheme,
    Endpoint,
    OpenAPISpec,
    OpenAPIVersion,
    Parameter,
)


def _param(
    name: str,
    in_: str = "path",
    required: bool = True,
    schema_type: str | None = "string",
) -> Parameter:
    return Parameter(name=name, in_=in_, required=required, schema_type=schema_type)


def _endpoint(
    path: str,
    *,
    method: str = "get",
    parameters: tuple[Parameter, ...] = (),
    security: tuple[dict[str, tuple[str, ...]], ...] = ({"bearerAuth": ()},),
    deprecated: bool = False,
    operation_id: str | None = None,
) -> Endpoint:
    return Endpoint(
        path=path,
        method=method,
        operation_id=operation_id,
        parameters=parameters,
        security=security,
        deprecated=deprecated,
    )


def _spec(endpoints: tuple[Endpoint, ...]) -> OpenAPISpec:
    return OpenAPISpec(
        version=OpenAPIVersion(raw="3.0.0", major=3, minor=0),
        endpoints=endpoints,
    )


# =====================================================================
# is_object_leveled_path_param heuristic
# =====================================================================


@pytest.mark.parametrize(
    "name,expected",
    [
        ("id", True),
        ("ID", True),
        ("uuid", True),
        ("guid", True),
        ("accountId", True),
        ("customer_id", True),
        ("userID", True),
        ("transactionUUID", True),
        # Negatives
        ("page", False),
        ("cursor", False),
        ("limit", False),
        ("category", False),
        ("name", False),
    ],
)
def test_id_param_heuristic(name: str, expected: bool):
    p = _param(name)
    assert is_object_leveled_path_param(p) is expected


def test_query_string_id_is_not_path_object_leveled():
    """A `?id=` query parameter is a different finding class (param
    pollution) — the BOLA planner deliberately scopes to path
    parameters only."""
    p = _param("id", in_="query")
    assert is_object_leveled_path_param(p) is False


# =====================================================================
# plan_probes — filters + ordering
# =====================================================================


def test_planner_picks_get_with_id_param():
    spec = _spec(
        (
            _endpoint(
                "/accounts/{accountId}",
                parameters=(_param("accountId"),),
            ),
        )
    )
    candidates = plan_probes(spec)
    assert len(candidates) == 1
    c = candidates[0]
    assert c.endpoint_path == "/accounts/{accountId}"
    assert c.path_parameter == "accountId"
    assert c.method == "get"


def test_planner_skips_non_get_methods():
    """DELETE /accounts/{id} would also be BOLA-vulnerable but
    requires a different consent model — must NOT appear in v1."""
    spec = _spec(
        (
            _endpoint(
                "/accounts/{accountId}",
                method="delete",
                parameters=(_param("accountId"),),
            ),
        )
    )
    assert plan_probes(spec) == []


def test_planner_skips_endpoints_without_security():
    """A truly public endpoint isn't BOLA — it's exposing by design."""
    spec = _spec(
        (
            _endpoint(
                "/public/{id}",
                parameters=(_param("id"),),
                security=(),
            ),
        )
    )
    assert plan_probes(spec) == []


def test_planner_skips_endpoints_without_id_params():
    """A GET /accounts (list endpoint) has no path id → not BOLA-target."""
    spec = _spec((_endpoint("/accounts"),))
    assert plan_probes(spec) == []


def test_planner_includes_all_id_params_when_multiple():
    """Nested resources have two id params — both worth probing."""
    spec = _spec(
        (
            _endpoint(
                "/users/{userId}/accounts/{accountId}",
                parameters=(_param("userId"), _param("accountId")),
            ),
        )
    )
    candidates = plan_probes(spec)
    assert {c.path_parameter for c in candidates} == {"userId", "accountId"}


def test_planner_ordering_is_deterministic():
    spec = _spec(
        (
            _endpoint("/b/{id}", parameters=(_param("id"),)),
            _endpoint("/a/{id}", parameters=(_param("id"),)),
        )
    )
    paths = [c.endpoint_path for c in plan_probes(spec)]
    assert paths == ["/a/{id}", "/b/{id}"]


def test_planner_records_security_scheme_names():
    spec = _spec(
        (
            _endpoint(
                "/accounts/{accountId}",
                parameters=(_param("accountId"),),
                security=({"bearerAuth": ()}, {"oauth2": ("read:accounts",)}),
            ),
        )
    )
    c = plan_probes(spec)[0]
    assert c.security_scheme_names == ("bearerAuth", "oauth2")


# =====================================================================
# Risk classification
# =====================================================================


def test_risk_high_for_top_level_resource():
    spec = _spec(
        (
            _endpoint(
                "/accounts/{accountId}",
                parameters=(_param("accountId"),),
            ),
        )
    )
    assert plan_probes(spec)[0].risk == "high"


def test_risk_medium_for_nested_resource():
    spec = _spec(
        (
            _endpoint(
                "/users/{userId}/accounts/{accountId}",
                parameters=(_param("userId"), _param("accountId")),
            ),
        )
    )
    candidates = plan_probes(spec)
    # Both candidates inherit the endpoint-level risk.
    assert all(c.risk == "medium" for c in candidates)


def test_risk_low_for_deprecated():
    spec = _spec(
        (
            _endpoint(
                "/accounts/{accountId}",
                parameters=(_param("accountId"),),
                deprecated=True,
            ),
        )
    )
    assert plan_probes(spec)[0].risk == "low"


# =====================================================================
# Verdict heuristic
# =====================================================================


@pytest.mark.parametrize(
    "status,body,expected",
    [
        (200, '{"id":1,"balance":12345.67,"holder":"Juan Perez"}', "leak_confirmed"),
        (200, "{}", "leak_suspected"),
        (200, "", "leak_suspected"),
        (401, "Unauthorized", "protected"),
        (403, "Forbidden", "protected"),
        (404, "Not found", "ambiguous"),
        (500, "boom", "error"),
        (418, "I'm a teapot", "ambiguous"),
    ],
)
def test_classify_response(status, body, expected):
    assert _classify_response(status, body) == expected


# =====================================================================
# execute_probe — banca-safety gates
# =====================================================================


def test_dry_run_default_returns_dry_run_verdict():
    """fire=False (default) MUST never hit the network."""
    candidate = BOLACandidate(
        endpoint_path="/accounts/{accountId}",
        method="get",
        path_parameter="accountId",
        parameter_type="uuid",
        security_scheme_names=("bearerAuth",),
        operation_id=None,
        risk="high",
    )
    with patch("kryon.tools.api.bola_detector.urlopen") as mock_open:
        finding = execute_probe(
            candidate,
            base_url="https://api.example.com",
            token="t",
            id_to_test="00000000-0000-0000-0000-000000000001",
            fire=False,
        )
    assert finding.verdict == "dry_run"
    assert finding.http_status is None
    mock_open.assert_not_called()


def test_fire_true_but_env_unset_stays_dry_run(monkeypatch):
    """Arg alone is not enough — env gate must be flipped too."""
    monkeypatch.delenv("KRYON_BOLA_FIRE", raising=False)
    candidate = BOLACandidate(
        endpoint_path="/accounts/{id}",
        method="get",
        path_parameter="id",
        parameter_type=None,
        security_scheme_names=(),
        operation_id=None,
        risk="high",
    )
    with patch("kryon.tools.api.bola_detector.urlopen") as mock_open:
        finding = execute_probe(
            candidate,
            base_url="https://api.example.com",
            token="t",
            id_to_test="123",
            fire=True,
        )
    assert finding.verdict == "dry_run"
    mock_open.assert_not_called()


def test_non_get_method_refuses_with_banca_safety_message():
    """Even when fire gates are both set, a non-GET candidate must be
    rejected — the planner shouldn't produce these but defensive."""
    candidate = BOLACandidate(
        endpoint_path="/accounts/{id}",
        method="delete",  # not allowed
        path_parameter="id",
        parameter_type=None,
        security_scheme_names=(),
        operation_id=None,
        risk="high",
    )
    finding = execute_probe(
        candidate,
        base_url="https://api.example.com",
        token="t",
        id_to_test="123",
        fire=True,
    )
    assert finding.verdict == "error"
    assert "GET" in (finding.error or "")


def test_live_fire_executes_when_both_gates_set(monkeypatch):
    """Both env + arg set → live HTTP. Mock the urlopen to avoid an
    actual network call but verify it was invoked with the right URL."""
    monkeypatch.setenv("KRYON_BOLA_FIRE", "true")

    candidate = BOLACandidate(
        endpoint_path="/accounts/{accountId}",
        method="get",
        path_parameter="accountId",
        parameter_type="uuid",
        security_scheme_names=("bearerAuth",),
        operation_id=None,
        risk="high",
    )

    class _FakeResp:
        status = 200

        def read(self):
            return b'{"id": 1, "balance": 12345.67, "name": "Juan"}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("kryon.tools.api.bola_detector.urlopen", return_value=_FakeResp()) as mock_open:
        finding = execute_probe(
            candidate,
            base_url="https://api.example.com",
            token="t-12345",
            id_to_test="other-acct-9",
            fire=True,
        )
    assert mock_open.called
    req = mock_open.call_args[0][0]
    # Path substitution happens.
    assert req.full_url == "https://api.example.com/accounts/other-acct-9"
    # Authorization header attached.
    assert req.get_header("Authorization") == "Bearer t-12345"
    assert finding.verdict == "leak_confirmed"
    assert finding.http_status == 200
    # Body fingerprint surfaced, body sha256 hex-encoded.
    assert "balance" in finding.body_fingerprint
    assert finding.body_sha256 and len(finding.body_sha256) == 64


def test_http_error_4xx_is_recorded(monkeypatch):
    """An HTTPError on 401 should produce a 'protected' verdict, not
    propagate as a Python exception."""
    monkeypatch.setenv("KRYON_BOLA_FIRE", "true")
    from urllib.error import HTTPError

    candidate = BOLACandidate(
        endpoint_path="/accounts/{accountId}",
        method="get",
        path_parameter="accountId",
        parameter_type=None,
        security_scheme_names=(),
        operation_id=None,
        risk="high",
    )

    err = HTTPError("http://example", 401, "Unauthorized", {}, None)
    with patch("kryon.tools.api.bola_detector.urlopen", side_effect=err):
        finding = execute_probe(
            candidate,
            base_url="https://api.example.com",
            token="t",
            id_to_test="x",
            fire=True,
        )
    assert finding.verdict == "protected"
    assert finding.http_status == 401


def test_network_error_classified_as_error(monkeypatch):
    monkeypatch.setenv("KRYON_BOLA_FIRE", "true")
    from urllib.error import URLError

    candidate = BOLACandidate(
        endpoint_path="/accounts/{accountId}",
        method="get",
        path_parameter="accountId",
        parameter_type=None,
        security_scheme_names=(),
        operation_id=None,
        risk="high",
    )
    with patch("kryon.tools.api.bola_detector.urlopen", side_effect=URLError("dns")):
        finding = execute_probe(
            candidate,
            base_url="https://api.example.com",
            token="t",
            id_to_test="x",
            fire=True,
        )
    assert finding.verdict == "error"
    assert finding.error and "URLError" in finding.error


# =====================================================================
# URL substitution
# =====================================================================


def test_substitute_path_replaces_only_target_placeholder():
    candidate = BOLACandidate(
        endpoint_path="/users/{userId}/accounts/{accountId}",
        method="get",
        path_parameter="accountId",
        parameter_type=None,
        security_scheme_names=(),
        operation_id=None,
        risk="medium",
    )
    url = _substitute_path("https://api.example.com", candidate, "ACC-9")
    # userId is left untouched.
    assert url == "https://api.example.com/users/{userId}/accounts/ACC-9"


def test_substitute_path_strips_trailing_slash():
    candidate = BOLACandidate(
        endpoint_path="/a/{id}",
        method="get",
        path_parameter="id",
        parameter_type=None,
        security_scheme_names=(),
        operation_id=None,
        risk="high",
    )
    url = _substitute_path("https://api.example.com/", candidate, "9")
    assert url == "https://api.example.com/a/9"


# =====================================================================
# correlate_findings
# =====================================================================


def _finding(verdict: str, risk: str = "high") -> BOLAFinding:
    c = BOLACandidate(
        endpoint_path="/x/{id}",
        method="get",
        path_parameter="id",
        parameter_type=None,
        security_scheme_names=(),
        operation_id=None,
        risk=risk,
    )
    return BOLAFinding(candidate=c, id_tested="t", verdict=verdict)


def test_correlator_counts_by_verdict():
    summary = correlate_findings(
        [
            _finding("leak_confirmed"),
            _finding("leak_confirmed"),
            _finding("protected"),
            _finding("dry_run"),
        ]
    )
    assert summary.total_probes == 4
    assert summary.by_verdict == {"leak_confirmed": 2, "protected": 1, "dry_run": 1}
    assert len(summary.confirmed_leaks) == 2


def test_correlator_counts_by_risk():
    summary = correlate_findings(
        [
            _finding("leak_confirmed", "high"),
            _finding("leak_confirmed", "medium"),
            _finding("protected", "high"),
        ]
    )
    assert summary.by_risk == {"high": 2, "medium": 1}


def test_correlator_empty():
    summary = correlate_findings([])
    assert summary.total_probes == 0
    assert summary.by_verdict == {}
    assert summary.confirmed_leaks == ()


# =====================================================================
# Frozen
# =====================================================================


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    c = BOLACandidate(
        endpoint_path="/x/{id}",
        method="get",
        path_parameter="id",
        parameter_type=None,
        security_scheme_names=(),
        operation_id=None,
        risk="high",
    )
    with pytest.raises(FrozenInstanceError):
        c.risk = "low"  # type: ignore[misc]
    f = _finding("dry_run")
    with pytest.raises(FrozenInstanceError):
        f.verdict = "x"  # type: ignore[misc]


# =====================================================================
# Tool wrapper end-to-end (via helpers; @function_tool wraps the callable)
# =====================================================================


def test_tool_wrapper_dry_run_summarizes_findings():
    """End-to-end: parse_openapi → plan_probes → dry-run probes →
    correlator → JSON summary. No HTTP traffic, no env gates."""
    import json

    from kryon.tools.api.bola_tool import _summarize

    spec_doc = {
        "openapi": "3.0.0",
        "info": {"title": "x", "version": "1"},
        "paths": {
            "/accounts/{accountId}": {
                "get": {
                    "operationId": "getAccount",
                    "parameters": [
                        {
                            "name": "accountId",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {"200": {"description": "ok"}},
                    "security": [{"bearerAuth": []}],
                }
            }
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"}
            }
        },
    }
    from kryon.tools.api.openapi_importer import parse_openapi

    spec = parse_openapi(spec_doc)
    candidates = plan_probes(spec)
    findings = [
        execute_probe(
            c,
            base_url="https://example.com",
            token="t",
            id_to_test="other-9",
            fire=False,
        )
        for c in candidates
    ]
    summary = _summarize(findings)
    assert summary["summary"]["total_probes"] == 1
    assert summary["summary"]["by_verdict"] == {"dry_run": 1}
    assert summary["findings"][0]["endpoint"] == "/accounts/{accountId}"
    assert summary["findings"][0]["verdict"] == "dry_run"
    # Must serialize cleanly.
    assert json.dumps(summary)


def test_tool_wrapper_handles_no_candidate_endpoints():
    """Spec with zero BOLA-shaped endpoints → empty summary, no
    exception. The agent gets a clean "nothing to probe" response
    instead of a crash."""
    from kryon.tools.api.bola_tool import _summarize

    summary = _summarize([])
    assert summary["summary"]["total_probes"] == 0
    assert summary["summary"]["confirmed_leak_count"] == 0
    assert summary["findings"] == []
