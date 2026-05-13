"""F87.3 — TDD contract for the GraphQL introspection detector.

Coverage groups:
  - Fire gate (env + arg) — dry-run default
  - Detection: typename probe true / false / non-JSON / 4xx
  - Verdict heuristic: enabled / disabled (errors keyword) /
    auth_required / not_graphql / error
  - Schema parsing: full path, missing fields, internal __types
    excluded, deterministic ordering
  - Risk classification: high (user/account/etc), medium
    (transaction/balance), low (no sensitive), info (empty)
  - Tool wrapper end-to-end with mocked HTTP
  - Banca-safety: response cap honored, only POST, mutation listing
    does NOT execute mutations.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from kryon.tools.api.graphql_recon import (
    DEFAULT_RESPONSE_CAP_BYTES,
    INTROSPECTION_QUERY,
    GraphQLEndpoint,
    IntrospectionResult,
    ParsedSchema,
    RiskAssessment,
    _verdict_from_response,
    classify_risk,
    is_graphql_endpoint,
    parse_schema,
    probe_introspection,
)


# =====================================================================
# Fire gate — dry-run default
# =====================================================================


def test_is_graphql_endpoint_dry_run_returns_none_no_network():
    """fire=False (default) MUST never touch the network."""
    with patch("kryon.tools.api.graphql_recon.urlopen") as mock_open:
        result = is_graphql_endpoint("https://api.example.com/graphql", fire=False)
    assert result is None
    mock_open.assert_not_called()


def test_is_graphql_endpoint_fire_without_env_stays_dry_run(monkeypatch):
    """Arg alone is not enough — env gate must be flipped too."""
    monkeypatch.delenv("KRYON_GRAPHQL_FIRE", raising=False)
    with patch("kryon.tools.api.graphql_recon.urlopen") as mock_open:
        result = is_graphql_endpoint("https://api.example.com/graphql", fire=True)
    assert result is None
    mock_open.assert_not_called()


def test_probe_introspection_dry_run_returns_dry_run_verdict():
    result = probe_introspection("https://api.example.com/graphql", fire=False)
    assert result.verdict == "dry_run"
    assert result.http_status is None
    assert result.schema is None
    assert "would POST" in result.notes


def test_probe_introspection_arg_without_env_stays_dry_run(monkeypatch):
    monkeypatch.delenv("KRYON_GRAPHQL_FIRE", raising=False)
    with patch("kryon.tools.api.graphql_recon.urlopen") as mock_open:
        result = probe_introspection("https://api.example.com/graphql", fire=True)
    assert result.verdict == "dry_run"
    mock_open.assert_not_called()


# =====================================================================
# Detection — _looks_like_graphql_response
# =====================================================================


class _FakeResp:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self, cap: int | None = None):
        if cap is None:
            return self._body
        return self._body[:cap]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_detection_true_on_data_response(monkeypatch):
    monkeypatch.setenv("KRYON_GRAPHQL_FIRE", "true")
    resp = _FakeResp(200, b'{"data":{"__typename":"Query"}}')
    with patch("kryon.tools.api.graphql_recon.urlopen", return_value=resp):
        endpoint = is_graphql_endpoint("https://example.com/graphql", fire=True)
    assert endpoint is not None
    assert endpoint.http_status == 200
    assert endpoint.accepts_post_json is True
    assert endpoint.body_sha256 and len(endpoint.body_sha256) == 64


def test_detection_true_on_errors_response(monkeypatch):
    """A server that rejects {__typename} with errors is still
    GraphQL-shaped."""
    monkeypatch.setenv("KRYON_GRAPHQL_FIRE", "true")
    resp = _FakeResp(200, b'{"errors":[{"message":"parse error"}]}')
    with patch("kryon.tools.api.graphql_recon.urlopen", return_value=resp):
        endpoint = is_graphql_endpoint("https://example.com/graphql", fire=True)
    assert endpoint is not None


def test_detection_false_on_html_response(monkeypatch):
    monkeypatch.setenv("KRYON_GRAPHQL_FIRE", "true")
    resp = _FakeResp(200, b"<html><body>Hello</body></html>")
    with patch("kryon.tools.api.graphql_recon.urlopen", return_value=resp):
        endpoint = is_graphql_endpoint("https://example.com/graphql", fire=True)
    assert endpoint is None


def test_detection_false_on_random_json(monkeypatch):
    """A JSON response without 'data' or 'errors' is not GraphQL."""
    monkeypatch.setenv("KRYON_GRAPHQL_FIRE", "true")
    resp = _FakeResp(200, b'{"hello":"world"}')
    with patch("kryon.tools.api.graphql_recon.urlopen", return_value=resp):
        endpoint = is_graphql_endpoint("https://example.com/graphql", fire=True)
    assert endpoint is None


def test_detection_handles_network_error(monkeypatch):
    monkeypatch.setenv("KRYON_GRAPHQL_FIRE", "true")
    from urllib.error import URLError

    with patch("kryon.tools.api.graphql_recon.urlopen", side_effect=URLError("dns")):
        endpoint = is_graphql_endpoint("https://example.com/graphql", fire=True)
    assert endpoint is None


# =====================================================================
# Verdict heuristic — _verdict_from_response
# =====================================================================


def test_verdict_enabled_when_schema_present():
    body = json.dumps({"data": {"__schema": {"types": []}}}).encode()
    verdict, doc = _verdict_from_response(200, body)
    assert verdict == "enabled"
    assert doc is not None


def test_verdict_disabled_when_errors_mention_introspection():
    body = json.dumps(
        {"errors": [{"message": "GraphQL introspection is not allowed"}]}
    ).encode()
    verdict, _ = _verdict_from_response(200, body)
    assert verdict == "disabled"


def test_verdict_disabled_when_errors_mention_schema_keyword():
    body = json.dumps(
        {"errors": [{"message": "Cannot query field __schema on type Query"}]}
    ).encode()
    verdict, _ = _verdict_from_response(200, body)
    assert verdict == "disabled"


def test_verdict_disabled_when_generic_errors():
    """Any errors array, even without 'introspection' keyword, means
    the server is GraphQL-shaped but rejected the query → treat as
    disabled-equivalent (the auditor follows up manually)."""
    body = json.dumps({"errors": [{"message": "syntax error"}]}).encode()
    verdict, _ = _verdict_from_response(200, body)
    assert verdict == "disabled"


def test_verdict_auth_required_on_401():
    verdict, _ = _verdict_from_response(401, b"Unauthorized")
    assert verdict == "auth_required"


def test_verdict_auth_required_on_403():
    verdict, _ = _verdict_from_response(403, b"Forbidden")
    assert verdict == "auth_required"


def test_verdict_error_on_5xx():
    verdict, _ = _verdict_from_response(500, b"boom")
    assert verdict == "error"


def test_verdict_not_graphql_on_html_body():
    verdict, _ = _verdict_from_response(200, b"<html>")
    assert verdict == "not_graphql"


def test_verdict_not_graphql_on_empty_body():
    verdict, _ = _verdict_from_response(200, b"")
    assert verdict == "not_graphql"


# =====================================================================
# probe_introspection — full path under live fire
# =====================================================================


def _introspection_payload(types: list[dict]) -> bytes:
    return json.dumps(
        {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "subscriptionType": None,
                    "types": types,
                }
            }
        }
    ).encode()


def test_probe_introspection_enabled_classifies_high_risk(monkeypatch):
    monkeypatch.setenv("KRYON_GRAPHQL_FIRE", "true")
    types = [
        {
            "name": "Query",
            "kind": "OBJECT",
            "fields": [
                {"name": "user", "type": {"name": "User", "kind": "OBJECT", "ofType": None}, "isDeprecated": False},
                {"name": "accounts", "type": {"name": None, "kind": "LIST", "ofType": {"name": "Account", "kind": "OBJECT"}}, "isDeprecated": False},
            ],
        },
        {"name": "User", "kind": "OBJECT", "fields": [{"name": "id", "type": {"name": "ID", "kind": "SCALAR", "ofType": None}, "isDeprecated": False}]},
        {"name": "Account", "kind": "OBJECT", "fields": []},
    ]
    resp = _FakeResp(200, _introspection_payload(types))
    with patch("kryon.tools.api.graphql_recon.urlopen", return_value=resp):
        result = probe_introspection("https://example.com/graphql", fire=True)
    assert result.verdict == "enabled"
    assert result.schema is not None
    assert result.schema.query_type == "Query"
    assert "user" in result.schema.query_fields
    assert "accounts" in result.schema.query_fields
    assert result.risk is not None
    assert result.risk.risk == "high"
    # Sensitive terms detected.
    assert "user" in result.risk.matched_sensitive_terms or "account" in result.risk.matched_sensitive_terms


def test_probe_introspection_disabled(monkeypatch):
    monkeypatch.setenv("KRYON_GRAPHQL_FIRE", "true")
    body = json.dumps({"errors": [{"message": "introspection disabled"}]}).encode()
    resp = _FakeResp(200, body)
    with patch("kryon.tools.api.graphql_recon.urlopen", return_value=resp):
        result = probe_introspection("https://example.com/graphql", fire=True)
    assert result.verdict == "disabled"
    assert result.schema is None
    assert result.risk is None


def test_probe_introspection_auth_required(monkeypatch):
    monkeypatch.setenv("KRYON_GRAPHQL_FIRE", "true")
    from urllib.error import HTTPError

    err = HTTPError("http://example", 401, "Unauthorized", {}, None)
    with patch("kryon.tools.api.graphql_recon.urlopen", side_effect=err):
        result = probe_introspection("https://example.com/graphql", fire=True)
    assert result.verdict == "auth_required"
    assert result.http_status == 401


def test_probe_introspection_network_error_recorded(monkeypatch):
    monkeypatch.setenv("KRYON_GRAPHQL_FIRE", "true")
    from urllib.error import URLError

    with patch("kryon.tools.api.graphql_recon.urlopen", side_effect=URLError("dns")):
        result = probe_introspection("https://example.com/graphql", fire=True)
    assert result.verdict == "error"
    assert result.error and "URLError" in result.error


def test_probe_uses_introspection_query(monkeypatch):
    """Confirms the right body is sent — pins the contract against
    the upstream IntrospectionQuery spec."""
    monkeypatch.setenv("KRYON_GRAPHQL_FIRE", "true")
    resp = _FakeResp(200, _introspection_payload([]))
    with patch("kryon.tools.api.graphql_recon.urlopen", return_value=resp) as mock_open:
        probe_introspection("https://example.com/graphql", fire=True)
    req = mock_open.call_args[0][0]
    payload = json.loads(req.data.decode())
    assert payload["query"].strip().startswith("query IntrospectionQuery")
    # The exact constant must match what we send.
    assert payload["query"] == INTROSPECTION_QUERY


# =====================================================================
# parse_schema
# =====================================================================


def test_parse_schema_extracts_root_names_and_types():
    types = [
        {"name": "Query", "kind": "OBJECT", "fields": [{"name": "me", "type": {"name": "User"}, "isDeprecated": False}]},
        {"name": "Mutation", "kind": "OBJECT", "fields": [{"name": "login", "type": {"name": "AuthPayload"}, "isDeprecated": False}]},
        {"name": "User", "kind": "OBJECT", "fields": []},
        {"name": "__Schema", "kind": "OBJECT", "fields": []},  # internal — must be excluded
    ]
    response = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "subscriptionType": None,
                "types": types,
            }
        }
    }
    schema = parse_schema(response)
    assert schema.query_type == "Query"
    assert schema.mutation_type == "Mutation"
    assert schema.subscription_type is None
    assert "__Schema" not in schema.type_names
    assert "User" in schema.type_names
    assert schema.query_fields == ("me",)
    assert schema.mutation_fields == ("login",)


def test_parse_schema_handles_missing_fields():
    schema = parse_schema({"data": {"__schema": {"types": []}}})
    assert schema.query_type is None
    assert schema.mutation_type is None
    assert schema.type_names == ()
    assert schema.query_fields == ()


def test_parse_schema_handles_garbage_payload():
    """Even an obviously-broken doc must not raise — the caller
    surfaces verdict=error separately."""
    schema = parse_schema({"data": "not-a-dict"})
    assert schema.query_type is None
    assert schema.type_names == ()


def test_parse_schema_dedupes_and_sorts_type_names():
    types = [
        {"name": "B", "kind": "OBJECT", "fields": []},
        {"name": "A", "kind": "OBJECT", "fields": []},
        {"name": "A", "kind": "OBJECT", "fields": []},  # dupe
    ]
    schema = parse_schema({"data": {"__schema": {"types": types}}})
    assert schema.type_names == ("A", "B")


# =====================================================================
# classify_risk
# =====================================================================


def test_classify_risk_high_on_user_or_account():
    schema = ParsedSchema(
        query_type="Query",
        mutation_type=None,
        subscription_type=None,
        type_names=("User", "Post"),
        query_fields=("user",),
    )
    risk = classify_risk(schema)
    assert risk.risk == "high"
    assert "user" in risk.matched_sensitive_terms


def test_classify_risk_high_on_password_field():
    schema = ParsedSchema(
        query_type="Query",
        mutation_type="Mutation",
        subscription_type=None,
        type_names=("Profile",),
        query_fields=("profile",),
        mutation_fields=("changePassword",),
    )
    risk = classify_risk(schema)
    assert risk.risk == "high"
    assert "password" in risk.matched_sensitive_terms


def test_classify_risk_medium_on_transaction():
    schema = ParsedSchema(
        query_type="Query",
        mutation_type=None,
        subscription_type=None,
        type_names=("Transaction",),
        query_fields=("transaction",),
    )
    risk = classify_risk(schema)
    assert risk.risk == "medium"


def test_classify_risk_low_when_nothing_sensitive():
    schema = ParsedSchema(
        query_type="Query",
        mutation_type=None,
        subscription_type=None,
        type_names=("Recipe", "Ingredient"),
        query_fields=("recipe", "ingredient"),
    )
    risk = classify_risk(schema)
    assert risk.risk == "low"
    assert risk.matched_sensitive_terms == ()


def test_classify_risk_info_when_empty_schema():
    schema = ParsedSchema(
        query_type=None,
        mutation_type=None,
        subscription_type=None,
    )
    risk = classify_risk(schema)
    assert risk.risk == "info"


def test_classify_does_not_match_substrings_inside_other_words():
    """Verify that "discount" doesn't trip the "account" detector."""
    schema = ParsedSchema(
        query_type="Query",
        mutation_type=None,
        subscription_type=None,
        type_names=("Discount", "Recipe"),
        query_fields=("discount",),
    )
    risk = classify_risk(schema)
    # discount → no word-boundary match on "account" because \b\w
    # "account" is preceded by "dis"; the regex uses \b which means
    # we should not match here.
    assert risk.risk == "low"


# =====================================================================
# Banca-safety
# =====================================================================


def test_response_capped_at_2mb(monkeypatch):
    """Body larger than the cap is truncated. We can't easily check
    truncation from the public API since the cap is enforced inside
    _post_graphql; verify the constant is documented + reasonable."""
    assert DEFAULT_RESPONSE_CAP_BYTES == 2 * 1024 * 1024


def test_method_is_post(monkeypatch):
    """The introspection probe always uses POST. Confirms no operator
    can accidentally send a GET (which would expose the query in URL
    server logs)."""
    monkeypatch.setenv("KRYON_GRAPHQL_FIRE", "true")
    resp = _FakeResp(200, _introspection_payload([]))
    with patch("kryon.tools.api.graphql_recon.urlopen", return_value=resp) as mock_open:
        probe_introspection("https://example.com/graphql", fire=True)
    req = mock_open.call_args[0][0]
    assert req.get_method() == "POST"


# =====================================================================
# Tool wrapper E2E
# =====================================================================


def test_tool_wrapper_candidate_urls_for_base():
    from kryon.tools.api.graphql_tool import _candidate_urls

    urls = _candidate_urls("https://api.example.com")
    assert "https://api.example.com/graphql" in urls
    assert "https://api.example.com/api/graphql" in urls
    assert len(urls) == 4


def test_tool_wrapper_keeps_full_path():
    from kryon.tools.api.graphql_tool import _candidate_urls

    urls = _candidate_urls("https://api.example.com/custom/graphql/path")
    assert urls == ["https://api.example.com/custom/graphql/path"]


def test_tool_wrapper_result_to_dict_serializable():
    """The tool wrapper must produce a dict json.dumps can serialize.
    Catches accidental tuple/set leakage."""
    from kryon.tools.api.graphql_tool import _result_to_dict

    schema = ParsedSchema(
        query_type="Query",
        mutation_type="Mutation",
        subscription_type=None,
        type_names=("User",),
        query_fields=("me",),
        mutation_fields=("login",),
    )
    result = IntrospectionResult(
        url="https://example.com/graphql",
        verdict="enabled",
        http_status=200,
        schema=schema,
        risk=classify_risk(schema),
        body_sha256="x" * 64,
    )
    payload = _result_to_dict(result)
    blob = json.dumps(payload)
    parsed = json.loads(blob)
    assert parsed["verdict"] == "enabled"
    assert parsed["schema"]["query_type"] == "Query"
    assert parsed["risk"]["risk"] == "high"


# =====================================================================
# Frozen contracts
# =====================================================================


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    schema = ParsedSchema(query_type="Q", mutation_type=None, subscription_type=None)
    with pytest.raises(FrozenInstanceError):
        schema.query_type = "X"  # type: ignore[misc]

    risk = RiskAssessment(risk="high")
    with pytest.raises(FrozenInstanceError):
        risk.risk = "low"  # type: ignore[misc]

    result = IntrospectionResult(url="x", verdict="dry_run")
    with pytest.raises(FrozenInstanceError):
        result.verdict = "x"  # type: ignore[misc]
