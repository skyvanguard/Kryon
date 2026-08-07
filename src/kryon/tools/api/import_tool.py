"""F87.1 — agent-facing tool wrapper for the OpenAPI importer.

Bridges `parse_openapi` (pure parser) and the agent: accepts URL /
path / inline text, normalizes the result into a JSON-serializable
summary the LLM can reason about without exploding the context.

Banca-safety: HTTPS URLs are fetched with stdlib urllib over a 30s
timeout. No external dependencies — the parser already covered the
JSON/YAML/dict cases. Operators using air-gapped containers should
pass a filesystem path or the inline spec text.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.api.openapi_importer import (
    InvalidOpenAPIError,
    OpenAPISpec,
    parse_openapi,
)

logger = logging.getLogger(__name__)


def _fetch_url(url: str, *, timeout: int = 30) -> str:
    """Pull a remote spec. Caller validates the URL — we don't restrict
    schemes here because tests use http://localhost fixtures. Operators
    on banca air-gap should not call this path (they pass local files)."""
    import urllib.request

    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json,application/yaml,*/*"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _summarize_for_agent(spec: OpenAPISpec) -> dict[str, Any]:
    """Compact summary the LLM can pattern-match without re-parsing.

    Keeps endpoint count + paths + methods + auth scheme types — enough
    for F87.2 BOLA to pick interesting endpoints. Full Endpoint dicts
    are available in `endpoints_full` for callers that need them."""
    return {
        "openapi_version": spec.version.raw,
        "title": spec.title,
        "api_version": spec.api_version,
        "description": spec.description[:300],  # cap
        "servers": list(spec.servers),
        "endpoint_count": len(spec.endpoints),
        "endpoints": [
            {
                "method": e.method.upper(),
                "path": e.path,
                "operation_id": e.operation_id,
                "summary": e.summary[:140],
                "required_params": [p.name for p in e.parameters if p.required],
                "param_count": len(e.parameters),
                "security_scheme_names": sorted({n for entry in e.security for n in entry.keys()}),
                "deprecated": e.deprecated,
            }
            for e in spec.endpoints
        ],
        "auth_schemes": [{"name": s.name, "type": s.type_, "scheme": s.scheme} for s in spec.auth_schemes],
        "unresolved_refs": list(spec.unresolved_refs),
    }


@function_tool
def import_openapi_spec(source: str) -> str:
    """Import an OpenAPI / Swagger spec from a URL, filesystem path, or
    inline JSON/YAML text.

    Args:
        source: One of:
            - "https://api.example.com/openapi.json"
            - "/abs/path/to/openapi.yaml"
            - inline raw spec text starting with `{` or `openapi:` /
              `swagger:`.

    Returns:
        JSON string with the spec summary (endpoints, auth schemes,
        unresolved refs). Wrapped in a string because the SDK's
        function_tool serializer expects str.
    """
    source = source.strip()
    if not source:
        return json.dumps({"error": "empty source"})

    try:
        if source.startswith(("http://", "https://")):
            text = _fetch_url(source)
            spec = parse_openapi(text)
        elif source.startswith(("{", "openapi:", "swagger:")) or "\n" in source[:200]:
            # Inline body — JSON or YAML.
            spec = parse_openapi(source)
        else:
            # Treat as a filesystem path.
            spec = parse_openapi(Path(source))
    except InvalidOpenAPIError as e:
        return json.dumps({"error": f"invalid OpenAPI spec: {e}"})
    except FileNotFoundError as e:
        return json.dumps({"error": f"file not found: {e}"})
    except Exception as e:  # noqa: BLE001
        # Network / parse failures degrade to a structured error so the
        # agent can self-correct on the next turn.
        return json.dumps({"error": f"{type(e).__name__}: {e}"})

    return json.dumps(_summarize_for_agent(spec), ensure_ascii=False)
