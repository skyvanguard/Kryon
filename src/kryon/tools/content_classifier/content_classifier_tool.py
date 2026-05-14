"""F116 — agent-facing tool wrapper for the Content Classifier."""

from __future__ import annotations

import base64
import json

from kryon.sdk.agents import function_tool
from kryon.tools.content_classifier.classifier import (
    ContentClassifier,
    ContentInput,
    is_magika_available,
)

__all__ = ["classify_content_bytes", "check_magika_available"]


@function_tool
def check_magika_available() -> str:
    """Return whether the optional Magika dependency is installed."""
    return json.dumps({"available": is_magika_available()})


@function_tool
def classify_content_bytes(config_json: str) -> str:
    """Classify a body. Returns the full Content Classification +
    list of findings.

    Banca-safety: secret values are REDACTED in output (first/last
    4 chars + SHA-256 only).

    Args:
        config_json: {
          content_b64 (required): base64-encoded content bytes,
          source_url (optional): URL where content was fetched,
          content_type_header (optional): Content-Type header value
        }
    """
    try:
        doc = json.loads(config_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(doc, dict):
        return json.dumps({"error": "config_json must be a JSON object"})
    raw_b64 = doc.get("content_b64")
    if not raw_b64:
        return json.dumps({"error": "content_b64 is required"})
    try:
        content = base64.b64decode(raw_b64)
    except Exception as e:
        return json.dumps({"error": f"invalid base64: {e}"})

    inp = ContentInput(
        content=content,
        source_url=str(doc.get("source_url") or ""),
        content_type_header=str(doc.get("content_type_header") or ""),
        content_length=len(content),
    )
    classifier = ContentClassifier()
    classif = classifier.classify(inp)
    return json.dumps(
        {
            "magika_available": classif.magika_available,
            "magika_label": classif.magika_label,
            "heuristic_label": classif.heuristic_label,
            "disguise": {
                "mime_disguise": classif.disguise.mime_disguise,
                "extension_disguise": classif.disguise.extension_disguise,
                "severity": classif.disguise.severity,
                "mime_detail": classif.disguise.mime_detail,
                "extension_detail": classif.disguise.extension_detail,
            },
            "polyglot": {
                "is_polyglot": classif.polyglot,
                "signatures": [{"signature": p.signature, "offset": p.offset} for p in classif.polyglot_indicators],
            },
            "embedded_secrets": [
                {
                    "kind": s.kind,
                    "severity": s.severity,
                    "redacted_preview": s.redacted_preview,
                    "value_sha256": s.value_sha256,
                    "offset": s.matched_at_offset,
                }
                for s in classif.embedded_secrets
            ],
            "threat": {
                "score": classif.threat.score,
                "factors": list(classif.threat.factors),
                "primary_rule": classif.threat.primary_rule,
            },
            "content_sha256": classif.content_sha256,
            "content_entropy": round(classif.content_entropy, 3),
            "content_length": classif.content_length,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "remediation": f.remediation,
                    "source_url": f.source_url,
                    "extra": {k: v for k, v in f.extra},
                }
                for f in classif.findings
            ],
        },
        ensure_ascii=False,
    )
