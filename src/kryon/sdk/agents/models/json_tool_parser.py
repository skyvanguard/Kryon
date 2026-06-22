"""JSON-in-content tool-call parser for local models that emit tool calls as
raw JSON in the message body instead of the OpenAI ``tool_calls`` array.

Some GGUF chat templates (e.g. mradermacher's DeepHat-V1-7B, and Qwen2.5-based
security fine-tunes in general) don't wire the ``--jinja`` tool grammar, so
llama.cpp returns ``tool_calls: null`` and the model writes the call(s) into
``content`` as JSON objects:

    {"name": "run_nmap", "arguments": {"target": "10.10.10.5"}}

Crucially, when the model chains steps it emits **multiple** objects separated
by newlines (NDJSON)::

    {"name": "run_nmap", "arguments": {"target": "10.10.10.5"}}
    {"name": "run_sqlmap", "arguments": {"url": "http://10.10.10.5/login?id=1"}}

The legacy inline fallback (first ``{`` … last ``}``) silently dropped both
calls in that case — exactly the multi-step chaining an offensive agent needs.
This parser scans the body with ``json.JSONDecoder.raw_decode`` so it recovers
every well-formed object, tolerates ``<tool_call>`` wrappers / markdown fences /
prose around the JSON, and ignores braces that live inside string values.

Returns ``None`` (not ``[]``) when no JSON tool call is present so upstream
parsers (Harmony) and downstream handling still get a chance.
"""

from __future__ import annotations

import json
import uuid

# A JSON object is only treated as a tool call when it carries BOTH of these
# keys — keeps the scanner from mistaking incidental JSON (config blobs, sample
# payloads the model is describing) for an invocation.
_NAME_KEY = "name"
_ARGS_KEY = "arguments"


def parse_json_tool_calls(content: str) -> list[dict] | None:
    """Extract one or more ``{"name", "arguments"}`` tool calls from raw text.

    Returns a list of OpenAI-shaped tool-call dicts::

        [{"id": "call_<hex>", "type": "function",
          "function": {"name": "...", "arguments": "<json-str>"}}]

    or ``None`` when no JSON tool call is detected.
    """
    if not content or not content.strip():
        return None

    # Fast path: a tool call always contains the name key. Bail before the
    # scan when the body can't possibly hold one.
    if _NAME_KEY not in content or _ARGS_KEY not in content:
        return None

    decoder = json.JSONDecoder()
    text = content
    n = len(text)
    i = 0
    tool_calls: list[dict] = []

    while i < n:
        brace = text.find("{", i)
        if brace < 0:
            break
        try:
            obj, end = decoder.raw_decode(text, brace)
        except json.JSONDecodeError:
            # Not the start of a valid object (e.g. a `{` inside prose) — step
            # past this brace and keep scanning.
            i = brace + 1
            continue

        if isinstance(obj, dict) and _NAME_KEY in obj and _ARGS_KEY in obj:
            tool_calls.append(_to_openai_tool_call(obj))
        i = end

    return tool_calls or None


def _to_openai_tool_call(obj: dict) -> dict:
    """Convert a ``{"name", "arguments"}`` dict to an OpenAI tool-call dict.

    ``arguments`` is normalized to a JSON-encoded string (the shape the SDK
    converter and the run loop expect). A spurious ``ctf`` argument — which
    some local models hallucinate from benchmark prompts — is stripped, matching
    the legacy inline fallback's behavior.
    """
    name = str(obj.get(_NAME_KEY, ""))
    raw_args = obj.get(_ARGS_KEY)

    # `arguments` MUST normalize to a JSON OBJECT string. A model that emits a scalar
    # (arguments: 99 / null / "x") or a list would otherwise yield args the run loop
    # can't **-unpack — coerce those to an empty object "{}" so schema validation reports
    # missing args cleanly instead of crashing on **args.
    if isinstance(raw_args, dict):
        raw_args.pop("ctf", None)
        args_str = json.dumps(raw_args)
    elif isinstance(raw_args, str):
        try:
            parsed = json.loads(raw_args)
        except (json.JSONDecodeError, ValueError):
            parsed = None
        if isinstance(parsed, dict):
            parsed.pop("ctf", None)
            args_str = json.dumps(parsed)
        elif parsed is None and raw_args.strip().startswith("{"):
            args_str = raw_args  # looks like an object but didn't parse — let the validator surface it
        else:
            args_str = "{}"  # scalar/list payload → not valid tool args
    else:
        args_str = "{}"  # int / list / None — not a valid arguments object

    return {
        "id": f"call_{uuid.uuid4().hex[:8]}",
        "type": "function",
        "function": {"name": name, "arguments": args_str},
    }
