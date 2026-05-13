"""F87.1 — OpenAPI / Swagger spec importer.

Parses an OpenAPI 2.0 (Swagger), 3.0, or 3.1 document into typed
dataclasses the rest of F87 can consume:

  * `OpenAPISpec` — top-level container with metadata + endpoints +
    auth schemes.
  * `Endpoint` — one operation (method + path + parameters +
    security requirements + response codes).
  * `Parameter` — a single parameter binding (in: query|path|header
    |body|cookie) with type info + required flag + example.
  * `AuthScheme` — a security definition (basic / bearer / apiKey /
    oauth2 / openIdConnect) — F87.4 FAPI will check these against
    the Open Banking profile.

Design constraints:
  * Stdlib + PyYAML only. PyYAML is already a transitive dep via
    pydantic/openapi-related libs, but we don't import them.
  * JSON and YAML input, accepted as `str` (raw doc), `dict`
    (pre-parsed), or `Path` (filesystem). URL fetching lives in the
    tool wrapper, not the parser — keeps the parser pure for tests.
  * `$ref` resolution is local-only: refs of the form
    `#/components/schemas/Foo` (3.x) or `#/definitions/Foo` (2.0)
    resolve against the doc itself. Remote refs are recorded in the
    `unresolved_refs` set so a curator can decide whether to fetch
    them separately — banca-air-gap-safe default.
  * Bad / missing fields degrade to None or empty collections; the
    parser refuses to load only when the doc lacks BOTH `swagger` and
    `openapi` keys (i.e. it's not an OpenAPI spec at all).

Output is a frozen dataclass tree so consumers (F87.2 BOLA detector,
F87.4 FAPI validator) can cache + compare specs deterministically.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "OpenAPISpec",
    "Endpoint",
    "Parameter",
    "AuthScheme",
    "OpenAPIVersion",
    "parse_openapi",
    "is_openapi_doc",
    "InvalidOpenAPIError",
]


class InvalidOpenAPIError(ValueError):
    """The document is not a valid OpenAPI / Swagger spec."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


# We don't enum-class the version because the spec uses arbitrary
# string versions ("3.0.3", "3.1.0", "2.0"). The major.minor pair is
# enough for branch decisions.
@dataclass(frozen=True)
class OpenAPIVersion:
    raw: str
    major: int  # 2 (Swagger) or 3 (OpenAPI)
    minor: int

    @property
    def is_swagger_2(self) -> bool:
        return self.major == 2

    @property
    def is_openapi_3(self) -> bool:
        return self.major == 3


@dataclass(frozen=True)
class Parameter:
    """One request parameter. `in_` is the binding location."""

    name: str
    in_: str  # "query" | "path" | "header" | "body" | "cookie" | "formData"
    required: bool
    schema_type: str | None = None  # "string" | "integer" | "array" | "object" | ...
    description: str = ""
    example: Any = None
    format_: str | None = None  # "uuid" | "email" | "date-time" | ...


@dataclass(frozen=True)
class AuthScheme:
    """One security definition. Field set varies by `type`:
      basic / http   — only name + type + scheme.
      apiKey         — adds `in_`, `param_name`.
      oauth2         — adds `flows` (raw dict; F87.4 inspects it).
      openIdConnect  — adds `openid_url`.
    """

    name: str  # the key under securityDefinitions / components.securitySchemes
    type_: str  # "basic" | "http" | "apiKey" | "oauth2" | "openIdConnect" | "mutualTLS"
    scheme: str | None = None  # "bearer" for type=http
    bearer_format: str | None = None
    in_: str | None = None  # for apiKey
    param_name: str | None = None  # for apiKey (the actual header/query/cookie name)
    flows: dict[str, Any] = field(default_factory=dict)  # oauth2
    openid_url: str | None = None


@dataclass(frozen=True)
class Endpoint:
    """One operation = method + path + parameters + responses + security."""

    path: str  # "/users/{userId}"
    method: str  # "get" | "post" | "put" | "patch" | "delete" | "options" | "head"
    operation_id: str | None = None
    summary: str = ""
    parameters: tuple[Parameter, ...] = field(default_factory=tuple)
    # Each security requirement is a list of {scheme_name: [scopes...]} —
    # OpenAPI lets an endpoint accept ANY scheme in the list. F87.4
    # validators care about the set of scheme names used.
    security: tuple[dict[str, tuple[str, ...]], ...] = field(default_factory=tuple)
    response_codes: tuple[str, ...] = field(default_factory=tuple)  # ("200", "401", "default")
    request_body_schema_type: str | None = None  # OpenAPI 3.x request body
    deprecated: bool = False


@dataclass(frozen=True)
class OpenAPISpec:
    """Top-level container. Built by `parse_openapi`."""

    version: OpenAPIVersion
    title: str = ""
    api_version: str = ""
    description: str = ""
    servers: tuple[str, ...] = field(default_factory=tuple)
    endpoints: tuple[Endpoint, ...] = field(default_factory=tuple)
    auth_schemes: tuple[AuthScheme, ...] = field(default_factory=tuple)
    unresolved_refs: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}


def is_openapi_doc(doc: dict[str, Any]) -> bool:
    """Cheap shape-check used by callers that need to detect a spec
    before fully parsing it (e.g. content-type sniffing).

    Returns True for both Swagger 2 (`swagger:` key) and OpenAPI 3
    (`openapi:` key). Keeps the parser's hard requirement explicit so
    a missing version key fails noisily instead of producing an empty
    spec downstream.
    """
    if not isinstance(doc, dict):
        return False
    return "openapi" in doc or "swagger" in doc


def _detect_version(doc: dict[str, Any]) -> OpenAPIVersion:
    raw = str(doc.get("openapi") or doc.get("swagger") or "").strip()
    if not raw:
        raise InvalidOpenAPIError("missing both 'openapi' and 'swagger' keys")
    parts = raw.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError) as exc:
        raise InvalidOpenAPIError(f"unparseable version string: {raw!r}") from exc
    if major not in (2, 3):
        raise InvalidOpenAPIError(f"unsupported OpenAPI major version: {major}")
    return OpenAPIVersion(raw=raw, major=major, minor=minor)


def _load_text(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    """Normalize input into a dict.

    - dict: returned as-is.
    - Path: read text from disk, sniff JSON vs YAML.
    - str: sniff JSON vs YAML on the raw string.

    The JSON-first detection lets pure-JSON specs avoid the yaml
    dependency at parse time. Empty input is treated as InvalidOpenAPI."""
    if isinstance(source, dict):
        return source

    if isinstance(source, Path):
        if not source.is_file():
            raise FileNotFoundError(source)
        text = source.read_text(encoding="utf-8")
    elif isinstance(source, str):
        text = source
    else:
        raise TypeError(f"unsupported source type {type(source).__name__}")

    if not text.strip():
        raise InvalidOpenAPIError("empty document")

    # Try JSON first (faster, deterministic), then YAML.
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover - PyYAML is in deps
            raise InvalidOpenAPIError("YAML input requires PyYAML") from exc
        loaded = yaml.safe_load(text)

    if not isinstance(loaded, dict):
        raise InvalidOpenAPIError("top-level document must be a mapping")
    return loaded


def _resolve_ref(ref: str, doc: dict[str, Any], unresolved: list[str]) -> dict[str, Any] | None:
    """Resolve `#/path/to/node` against the doc itself.

    External refs (no leading `#`) are appended to `unresolved` and
    None is returned — the caller decides how to react (typically:
    surface a near-miss in the report rather than block on missing
    remote data).
    """
    if not isinstance(ref, str):
        return None
    if not ref.startswith("#/"):
        unresolved.append(ref)
        return None
    cursor: Any = doc
    for part in ref[2:].split("/"):
        # JSON Pointer escaping: ~1 → /, ~0 → ~
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(cursor, dict) or part not in cursor:
            unresolved.append(ref)
            return None
        cursor = cursor[part]
    return cursor if isinstance(cursor, dict) else None


def _maybe_deref(obj: Any, doc: dict[str, Any], unresolved: list[str]) -> dict[str, Any] | None:
    """If `obj` is a `{"$ref": ...}` mapping, resolve it. Otherwise
    pass through (if it's a dict) or return None."""
    if not isinstance(obj, dict):
        return None
    ref = obj.get("$ref")
    if isinstance(ref, str):
        return _resolve_ref(ref, doc, unresolved)
    return obj


def _parse_parameter(
    raw: dict[str, Any],
    doc: dict[str, Any],
    unresolved: list[str],
) -> Parameter | None:
    """Build one Parameter from raw spec mapping. Handles $ref + the
    OpenAPI-3 quirk where `schema` is nested vs Swagger-2 flat type."""
    resolved = _maybe_deref(raw, doc, unresolved)
    if not resolved:
        return None
    name = resolved.get("name")
    in_ = resolved.get("in")
    if not name or not in_:
        return None

    # Type discovery: 3.x has `schema: {type: ...}`, 2.0 has `type` flat.
    schema_type: str | None = None
    format_: str | None = None
    schema = resolved.get("schema")
    schema = _maybe_deref(schema, doc, unresolved) if isinstance(schema, dict) else None
    if schema:
        st = schema.get("type")
        if isinstance(st, str):
            schema_type = st
        sf = schema.get("format")
        if isinstance(sf, str):
            format_ = sf
    else:
        st = resolved.get("type")
        if isinstance(st, str):
            schema_type = st
        sf = resolved.get("format")
        if isinstance(sf, str):
            format_ = sf

    return Parameter(
        name=str(name),
        in_=str(in_),
        required=bool(resolved.get("required", False)),
        schema_type=schema_type,
        description=str(resolved.get("description") or ""),
        example=resolved.get("example"),
        format_=format_,
    )


def _parse_security_requirement(
    raw_list: Any,
) -> tuple[dict[str, tuple[str, ...]], ...]:
    """OpenAPI security requirement: list of single-key mappings, each
    mapping a scheme name to a list of scopes. We preserve the OR
    semantic (any element in the outer tuple is sufficient)."""
    if not isinstance(raw_list, list):
        return ()
    out: list[dict[str, tuple[str, ...]]] = []
    for entry in raw_list:
        if not isinstance(entry, dict):
            continue
        item: dict[str, tuple[str, ...]] = {}
        for scheme_name, scopes in entry.items():
            if not isinstance(scopes, list):
                scopes = []
            item[str(scheme_name)] = tuple(str(s) for s in scopes)
        if item:
            out.append(item)
    return tuple(out)


def _parse_endpoint(
    path: str,
    method: str,
    raw_op: dict[str, Any],
    path_level_params: list[dict[str, Any]],
    global_security: tuple[dict[str, tuple[str, ...]], ...],
    doc: dict[str, Any],
    unresolved: list[str],
) -> Endpoint:
    """Build one Endpoint. Merges path-level + operation-level
    parameters and falls back to the spec-level security req when
    operation-level isn't overridden."""
    op_params_raw = raw_op.get("parameters") or []
    merged_params_raw = list(path_level_params) + list(op_params_raw)
    parameters = tuple(
        p
        for p in (_parse_parameter(rp, doc, unresolved) for rp in merged_params_raw)
        if p is not None
    )

    # security may be present (override) OR absent (inherit). Empty
    # list at operation level means "no auth" — an explicit
    # different intent than absent.
    if "security" in raw_op:
        security = _parse_security_requirement(raw_op.get("security"))
    else:
        security = global_security

    # OpenAPI 3.x request body — capture top-level type for the
    # `application/json` media type. Pure best-effort.
    request_body_type: str | None = None
    rb = raw_op.get("requestBody")
    rb = _maybe_deref(rb, doc, unresolved) if isinstance(rb, dict) else None
    if rb and isinstance(rb.get("content"), dict):
        for _media_type, media_obj in rb["content"].items():
            if not isinstance(media_obj, dict):
                continue
            schema = _maybe_deref(media_obj.get("schema"), doc, unresolved)
            if schema and isinstance(schema.get("type"), str):
                request_body_type = schema["type"]
                break

    responses = raw_op.get("responses") or {}
    response_codes = tuple(str(k) for k in responses.keys()) if isinstance(responses, dict) else ()

    return Endpoint(
        path=path,
        method=method,
        operation_id=str(raw_op["operationId"]) if isinstance(raw_op.get("operationId"), str) else None,
        summary=str(raw_op.get("summary") or ""),
        parameters=parameters,
        security=security,
        response_codes=response_codes,
        request_body_schema_type=request_body_type,
        deprecated=bool(raw_op.get("deprecated", False)),
    )


def _parse_auth_schemes(
    doc: dict[str, Any], version: OpenAPIVersion
) -> tuple[AuthScheme, ...]:
    """Pull `securityDefinitions` (Swagger 2) or
    `components.securitySchemes` (OpenAPI 3) into typed AuthSchemes."""
    if version.is_swagger_2:
        defs = doc.get("securityDefinitions") or {}
    else:
        comps = doc.get("components") or {}
        defs = comps.get("securitySchemes") or {}
    if not isinstance(defs, dict):
        return ()

    out: list[AuthScheme] = []
    for name, raw in defs.items():
        if not isinstance(raw, dict):
            continue
        type_ = str(raw.get("type") or "").strip()
        if not type_:
            continue
        scheme = AuthScheme(
            name=str(name),
            type_=type_,
            scheme=str(raw["scheme"]) if isinstance(raw.get("scheme"), str) else None,
            bearer_format=str(raw["bearerFormat"]) if isinstance(raw.get("bearerFormat"), str) else None,
            in_=str(raw["in"]) if isinstance(raw.get("in"), str) else None,
            param_name=str(raw["name"]) if isinstance(raw.get("name"), str) else None,
            flows=dict(raw["flows"]) if isinstance(raw.get("flows"), dict) else {},
            openid_url=str(raw["openIdConnectUrl"]) if isinstance(raw.get("openIdConnectUrl"), str) else None,
        )
        out.append(scheme)
    return tuple(out)


def _parse_servers(doc: dict[str, Any], version: OpenAPIVersion) -> tuple[str, ...]:
    """Servers (3.x) or host+schemes+basePath (2.0). Returns base URLs."""
    if version.is_openapi_3:
        raw = doc.get("servers") or []
        return tuple(str(s.get("url")) for s in raw if isinstance(s, dict) and isinstance(s.get("url"), str))
    # 2.0
    host = str(doc.get("host") or "").strip()
    base_path = str(doc.get("basePath") or "").strip()
    schemes = doc.get("schemes") or ["https"]
    if not host:
        return ()
    return tuple(f"{s}://{host}{base_path}" for s in schemes if isinstance(s, str))


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------


def parse_openapi(source: str | Path | dict[str, Any]) -> OpenAPISpec:
    """Parse an OpenAPI / Swagger document into an `OpenAPISpec`.

    `source` can be a raw JSON/YAML string, a Path to a spec on disk,
    or a pre-parsed dict. Network fetching is the tool wrapper's job,
    not this function's — keeps the parser pure for unit testing.
    """
    doc = _load_text(source)
    if not is_openapi_doc(doc):
        raise InvalidOpenAPIError("document is not an OpenAPI / Swagger spec")
    version = _detect_version(doc)

    info = doc.get("info") or {}
    title = str(info.get("title") or "") if isinstance(info, dict) else ""
    api_version = str(info.get("version") or "") if isinstance(info, dict) else ""
    description = str(info.get("description") or "") if isinstance(info, dict) else ""

    unresolved: list[str] = []

    # spec-level security default
    global_security = _parse_security_requirement(doc.get("security"))

    endpoints: list[Endpoint] = []
    paths = doc.get("paths") or {}
    if isinstance(paths, dict):
        for path, raw_path in paths.items():
            if not isinstance(raw_path, dict):
                continue
            path_level_params: list[dict[str, Any]] = []
            raw_pp = raw_path.get("parameters")
            if isinstance(raw_pp, list):
                path_level_params = [p for p in raw_pp if isinstance(p, dict)]
            for method_key, op_raw in raw_path.items():
                if method_key.lower() not in _HTTP_METHODS:
                    continue
                if not isinstance(op_raw, dict):
                    continue
                endpoints.append(
                    _parse_endpoint(
                        path=str(path),
                        method=method_key.lower(),
                        raw_op=op_raw,
                        path_level_params=path_level_params,
                        global_security=global_security,
                        doc=doc,
                        unresolved=unresolved,
                    )
                )

    # Deterministic ordering: path then method. Lets two parses of the
    # same spec produce byte-identical OpenAPISpec instances, useful
    # for caching + diffing.
    endpoints.sort(key=lambda e: (e.path, e.method))

    return OpenAPISpec(
        version=version,
        title=title,
        api_version=api_version,
        description=description,
        servers=_parse_servers(doc, version),
        endpoints=tuple(endpoints),
        auth_schemes=_parse_auth_schemes(doc, version),
        unresolved_refs=tuple(dict.fromkeys(unresolved)),
    )
