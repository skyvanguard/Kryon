"""F162 — OpenAI Harmony format tool-call parser.

gpt-oss-20b (and any future gpt-oss release) emits tool calls in the
**Harmony** chat format, which differs from the OpenAI Chat Completions
standard. Ollama does not currently translate Harmony output into the
``tool_calls`` array shape that the Kryon SDK expects, so we do the
translation here.

The parser is intentionally string-based (not token-based) because we
receive already-decoded UTF-8 from Ollama via LiteLLM. The official
``openai-harmony`` package operates on tokens and isn't suitable for
this entry point. For our use case (extracting the recipient + JSON
args from each ``<|call|>``-terminated block) a tight regex pass over
the response body is sufficient and avoids the Rust/PyO3 dependency.

Harmony tool-call structure:

    <|start|>assistant<|channel|>(analysis|commentary) to=NAMESPACE.FUNC \
        (<|constrain|>json|<single-token-tag>)?<|message|>{...args...}<|call|>

Notes:
    * ``analysis`` channel is reserved for chain-of-thought AND built-in
      tools (``container``, ``browser``, ``python``). ``commentary`` is
      for developer-defined functions. Both carry tool calls when ``to=``
      is present.
    * ``code`` is an informal short form of ``<|constrain|>json`` emitted
      by gpt-oss-20b on Ollama. We accept either.
    * ``<|call|>`` terminates a tool call; ``<|end|>`` terminates a
      regular message; ``<|return|>`` terminates the final user-visible
      answer. We only collect ``<|call|>``-terminated blocks.
    * NAMESPACE-stripping: ``functions.run_sqlmap`` → ``run_sqlmap``,
      ``container.exec`` → ``exec``. The SDK's tool registry uses bare
      names; we leave it to the run loop to error out on unknown names
      so the model can self-correct.

The parser returns ``None`` (not ``[]``) when no Harmony tool call is
present so that downstream fallback parsers (JSON-in-content, etc.)
still get a chance to handle the response.
"""

from __future__ import annotations

import json
import re
import uuid

# Recipient tokens may include alphanumerics, underscores, and dots
# (for namespace.function). Some Ollama outputs drop the namespace
# entirely, so ``functions.foo`` / ``container.exec`` / bare ``foo``
# are all accepted.
_RECIPIENT = r"[\w][\w.]*"

# Content-type segment between the recipient and ``<|message|>``. The
# canonical Harmony form is ``<|constrain|>TYPE``; gpt-oss-20b on Ollama
# also emits a bare ``code`` token. Both are optional.
_CONSTRAIN = r"(?:\s+<\|constrain\|>\w+|\s+code)?"

_HARMONY_TOOL_CALL_RE = re.compile(
    r"<\|channel\|>(?:analysis|commentary)"
    r"\s+to=(?P<recipient>" + _RECIPIENT + r")" + _CONSTRAIN + r"\s*<\|message\|>(?P<body>.*?)<\|call\|>",
    re.DOTALL,
)


def parse_harmony_tool_calls(content: str) -> list[dict] | None:
    """Parse OpenAI Harmony tool calls from a raw assistant response.

    Returns a list of OpenAI-shaped tool-call dicts:

        [{"id": "call_<hex>", "type": "function",
          "function": {"name": "...", "arguments": "<json-str>"}}]

    or ``None`` when no Harmony-formatted tool call is detected (so
    downstream fallback parsers still trigger).
    """
    if not content or not content.strip():
        return None

    # Fast path: no Harmony tokens at all → bail out without regex work.
    if "<|channel|>" not in content or "<|call|>" not in content:
        return None

    matches = list(_HARMONY_TOOL_CALL_RE.finditer(content))
    if not matches:
        return None

    tool_calls: list[dict] = []
    for m in matches:
        recipient = m.group("recipient")
        body = m.group("body")

        # Namespace-strip: ``foo.bar.baz`` → ``baz``.
        name = recipient.rsplit(".", 1)[-1]

        arguments = _normalize_arguments(body)
        tool_calls.append(
            {
                "id": f"call_{uuid.uuid4().hex[:8]}",
                "type": "function",
                "function": {"name": name, "arguments": arguments},
            }
        )

    return tool_calls or None


def _normalize_arguments(body: str) -> str:
    """Return the arguments as a JSON string.

    OpenAI Chat Completion tool calls require ``arguments`` to be a
    JSON-encoded string, not a parsed dict. If the body is valid JSON,
    we round-trip it through ``json.loads/dumps`` to normalize
    whitespace and verify shape. If it isn't, we preserve the raw text
    so the downstream schema validator surfaces the error to the model
    and the run loop's retry path can self-correct.
    """
    cleaned = body.strip()
    if not cleaned:
        return "{}"

    try:
        parsed = json.loads(cleaned)
    except (json.JSONDecodeError, ValueError):
        return cleaned

    return json.dumps(parsed)
