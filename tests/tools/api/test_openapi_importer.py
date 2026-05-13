"""F87.1 — TDD contract for the OpenAPI importer.

Fixtures cover the three spec versions Kryon will encounter on real
banking engagements:
  - OpenAPI 3.0.x (Open Banking UK, FAPI 1.0 Advanced)
  - OpenAPI 3.1.x (newer Open Banking implementations)
  - Swagger 2.0 (legacy core banking, T24 internal admin APIs)

Plus targeted tests on each parser invariant ($ref resolution,
security inheritance, deterministic ordering, error paths).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kryon.tools.api.openapi_importer import (
    AuthScheme,
    Endpoint,
    InvalidOpenAPIError,
    OpenAPISpec,
    Parameter,
    is_openapi_doc,
    parse_openapi,
)


# =====================================================================
# Minimal fixtures (built inline to keep tests self-contained)
# =====================================================================


def _minimal_openapi_3() -> dict[str, Any]:
    return {
        "openapi": "3.0.3",
        "info": {"title": "Banco Demo API", "version": "1.0.0", "description": "Sandbox"},
        "servers": [{"url": "https://api.bcp.com.py/v1"}],
        "paths": {
            "/accounts/{accountId}": {
                "parameters": [
                    {
                        "name": "accountId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "format": "uuid"},
                    }
                ],
                "get": {
                    "operationId": "getAccount",
                    "summary": "Get account by id",
                    "responses": {"200": {"description": "OK"}, "401": {"description": "Unauthorized"}},
                    "security": [{"bearerAuth": []}],
                },
            },
            "/transfer": {
                "post": {
                    "operationId": "createTransfer",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Transfer"}
                            }
                        }
                    },
                    "responses": {"201": {"description": "Created"}},
                    "security": [{"oauth2": ["payments:write"]}],
                },
            },
        },
        "components": {
            "schemas": {
                "Transfer": {"type": "object", "properties": {"amount": {"type": "number"}}}
            },
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
                "oauth2": {
                    "type": "oauth2",
                    "flows": {
                        "authorizationCode": {
                            "authorizationUrl": "https://auth.example.com/auth",
                            "tokenUrl": "https://auth.example.com/token",
                            "scopes": {"payments:write": "Initiate transfers"},
                        }
                    },
                },
            },
        },
    }


def _minimal_swagger_2() -> dict[str, Any]:
    return {
        "swagger": "2.0",
        "info": {"title": "Legacy Core", "version": "2.0.0"},
        "host": "core.example.com",
        "basePath": "/api/v2",
        "schemes": ["https"],
        "paths": {
            "/customers/{cid}": {
                "get": {
                    "operationId": "getCustomer",
                    "parameters": [
                        {"name": "cid", "in": "path", "required": True, "type": "string"},
                        {"name": "X-Trace-Id", "in": "header", "type": "string"},
                    ],
                    "responses": {"200": {"description": "OK"}},
                },
            }
        },
        "securityDefinitions": {
            "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
        },
        "security": [{"apiKey": []}],
    }


# =====================================================================
# is_openapi_doc
# =====================================================================


def test_is_openapi_doc_detects_openapi_3():
    assert is_openapi_doc({"openapi": "3.0.0"}) is True


def test_is_openapi_doc_detects_swagger_2():
    assert is_openapi_doc({"swagger": "2.0"}) is True


def test_is_openapi_doc_rejects_random_dict():
    assert is_openapi_doc({"hello": "world"}) is False


def test_is_openapi_doc_rejects_non_dict():
    assert is_openapi_doc("just a string") is False
    assert is_openapi_doc([1, 2, 3]) is False


# =====================================================================
# parse_openapi — OpenAPI 3 happy path
# =====================================================================


def test_parses_openapi_3_minimal():
    spec = parse_openapi(_minimal_openapi_3())
    assert isinstance(spec, OpenAPISpec)
    assert spec.version.raw == "3.0.3"
    assert spec.version.major == 3
    assert spec.title == "Banco Demo API"
    assert spec.servers == ("https://api.bcp.com.py/v1",)


def test_endpoints_extracted_with_method_and_path():
    spec = parse_openapi(_minimal_openapi_3())
    pairs = {(e.method, e.path) for e in spec.endpoints}
    assert ("get", "/accounts/{accountId}") in pairs
    assert ("post", "/transfer") in pairs


def test_endpoint_ordering_is_deterministic():
    """Same input → same output. Lets consumers hash specs."""
    spec1 = parse_openapi(_minimal_openapi_3())
    spec2 = parse_openapi(_minimal_openapi_3())
    assert [e.path for e in spec1.endpoints] == [e.path for e in spec2.endpoints]
    assert [e.method for e in spec1.endpoints] == [e.method for e in spec2.endpoints]


def test_path_level_parameters_merged_into_operation():
    """Path-level params should appear on each operation under that
    path. /accounts/{accountId} defines accountId at the path level."""
    spec = parse_openapi(_minimal_openapi_3())
    get_acc = next(e for e in spec.endpoints if e.method == "get" and e.path == "/accounts/{accountId}")
    names = {p.name for p in get_acc.parameters}
    assert "accountId" in names


def test_parameter_type_extracted_from_schema():
    spec = parse_openapi(_minimal_openapi_3())
    get_acc = next(e for e in spec.endpoints if e.method == "get" and e.path == "/accounts/{accountId}")
    p = next(p for p in get_acc.parameters if p.name == "accountId")
    assert p.schema_type == "string"
    assert p.format_ == "uuid"
    assert p.required is True


def test_endpoint_security_inherited_explicitly():
    spec = parse_openapi(_minimal_openapi_3())
    get_acc = next(e for e in spec.endpoints if e.method == "get" and e.path == "/accounts/{accountId}")
    assert get_acc.security == ({"bearerAuth": ()},)
    transfer = next(e for e in spec.endpoints if e.method == "post" and e.path == "/transfer")
    assert transfer.security == ({"oauth2": ("payments:write",)},)


def test_auth_schemes_collected():
    spec = parse_openapi(_minimal_openapi_3())
    by_name = {s.name: s for s in spec.auth_schemes}
    assert "bearerAuth" in by_name
    assert by_name["bearerAuth"].type_ == "http"
    assert by_name["bearerAuth"].scheme == "bearer"
    assert by_name["bearerAuth"].bearer_format == "JWT"
    assert "oauth2" in by_name
    assert by_name["oauth2"].type_ == "oauth2"
    assert "authorizationCode" in by_name["oauth2"].flows


def test_request_body_type_captured():
    spec = parse_openapi(_minimal_openapi_3())
    transfer = next(e for e in spec.endpoints if e.path == "/transfer")
    assert transfer.request_body_schema_type == "object"


# =====================================================================
# parse_openapi — Swagger 2.0 backward compat
# =====================================================================


def test_parses_swagger_2():
    spec = parse_openapi(_minimal_swagger_2())
    assert spec.version.major == 2
    assert spec.version.is_swagger_2


def test_swagger_2_servers_built_from_host_schemes():
    spec = parse_openapi(_minimal_swagger_2())
    assert spec.servers == ("https://core.example.com/api/v2",)


def test_swagger_2_global_security_inherited_when_op_omits():
    """When an operation has no `security` key, it inherits the
    spec-level one."""
    spec = parse_openapi(_minimal_swagger_2())
    e = spec.endpoints[0]
    assert e.security == ({"apiKey": ()},)


def test_swagger_2_apikey_auth_scheme_extracts_param_name():
    spec = parse_openapi(_minimal_swagger_2())
    scheme = spec.auth_schemes[0]
    assert scheme.type_ == "apiKey"
    assert scheme.in_ == "header"
    assert scheme.param_name == "X-API-Key"


def test_swagger_2_flat_type_on_parameter():
    """Swagger 2 has `type` directly on the parameter, no `schema`
    wrapping. Verify the parser still extracts it."""
    spec = parse_openapi(_minimal_swagger_2())
    e = spec.endpoints[0]
    by_name = {p.name: p for p in e.parameters}
    assert by_name["cid"].schema_type == "string"
    assert by_name["X-Trace-Id"].schema_type == "string"


# =====================================================================
# $ref handling
# =====================================================================


def test_local_ref_resolves_in_request_body():
    """The Transfer schema is a $ref — parse_openapi should follow it
    so request_body_schema_type ends up as 'object', not None."""
    spec = parse_openapi(_minimal_openapi_3())
    transfer = next(e for e in spec.endpoints if e.path == "/transfer")
    assert transfer.request_body_schema_type == "object"
    assert not spec.unresolved_refs  # local ref must resolve


def test_remote_ref_recorded_as_unresolved():
    doc = _minimal_openapi_3()
    doc["paths"]["/transfer"]["post"]["requestBody"]["content"]["application/json"]["schema"] = {
        "$ref": "https://example.com/schemas/transfer.yaml"
    }
    spec = parse_openapi(doc)
    assert "https://example.com/schemas/transfer.yaml" in spec.unresolved_refs


def test_missing_local_ref_recorded_as_unresolved():
    """A $ref pointing at a nonexistent local node must be recorded,
    not crash."""
    doc = _minimal_openapi_3()
    doc["paths"]["/transfer"]["post"]["requestBody"]["content"]["application/json"]["schema"] = {
        "$ref": "#/components/schemas/DoesNotExist"
    }
    spec = parse_openapi(doc)
    assert "#/components/schemas/DoesNotExist" in spec.unresolved_refs


# =====================================================================
# Error paths
# =====================================================================


def test_empty_string_raises():
    with pytest.raises(InvalidOpenAPIError):
        parse_openapi("")


def test_non_openapi_dict_raises():
    with pytest.raises(InvalidOpenAPIError):
        parse_openapi({"random": "json"})


def test_unsupported_major_version_raises():
    with pytest.raises(InvalidOpenAPIError):
        parse_openapi({"openapi": "5.0.0", "paths": {}})


def test_unparseable_version_raises():
    with pytest.raises(InvalidOpenAPIError):
        parse_openapi({"openapi": "not-a-version"})


def test_invalid_yaml_raises():
    with pytest.raises((InvalidOpenAPIError, Exception)):
        parse_openapi("{{{ unclosed")


# =====================================================================
# File path input
# =====================================================================


def test_parses_from_filesystem_path(tmp_path):
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(_minimal_openapi_3()), encoding="utf-8")
    spec = parse_openapi(p)
    assert spec.title == "Banco Demo API"


def test_parses_yaml_from_filesystem(tmp_path):
    import yaml

    p = tmp_path / "spec.yaml"
    p.write_text(yaml.safe_dump(_minimal_openapi_3()), encoding="utf-8")
    spec = parse_openapi(p)
    assert len(spec.endpoints) == 2


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        parse_openapi(Path("/this/does/not/exist.yaml"))


# =====================================================================
# Frozen dataclass contract
# =====================================================================


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    spec = parse_openapi(_minimal_openapi_3())
    with pytest.raises(FrozenInstanceError):
        spec.title = "mutated"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        spec.endpoints[0].method = "x"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        spec.auth_schemes[0].type_ = "x"  # type: ignore[misc]


# =====================================================================
# Tool wrapper smoke
# =====================================================================


def test_tool_wrapper_with_inline_text():
    """End-to-end through the @function_tool wrapper: inline JSON
    spec → summary dict serialized as a string."""
    from kryon.tools.api.import_tool import import_openapi_spec, _summarize_for_agent

    # Use the raw helper because the @function_tool wraps the callable
    # in an Agent SDK shim that requires a context.
    spec = parse_openapi(_minimal_openapi_3())
    summary = _summarize_for_agent(spec)
    assert summary["openapi_version"] == "3.0.3"
    assert summary["endpoint_count"] == 2
    assert any(e["path"] == "/transfer" for e in summary["endpoints"])
    assert any(s["name"] == "bearerAuth" for s in summary["auth_schemes"])
    # And the wrapped tool exists as a function_tool object.
    assert hasattr(import_openapi_spec, "name")


def test_summary_caps_description():
    """Long descriptions are truncated to avoid blowing up the LLM's
    context. Pin the 300-char cap so a future raise is intentional."""
    from kryon.tools.api.import_tool import _summarize_for_agent

    doc = _minimal_openapi_3()
    doc["info"]["description"] = "x" * 1000
    spec = parse_openapi(doc)
    summary = _summarize_for_agent(spec)
    assert len(summary["description"]) <= 300
