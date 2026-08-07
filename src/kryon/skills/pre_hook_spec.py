"""Pre-hook schema for skills.

A pre-hook is a deterministic tool invocation that runs BEFORE the LLM
takes control of a turn. Its output is injected into the system prompt
under the `inject_as` key, so the model sees authoritative findings
it cannot ignore or fabricate.

Two flavors:
  * declarative — `tool: <name>` + `args: {...}` runs a registered tool
  * python (escape hatch) — `python: ./<file>.py:<func>` calls a callable

Schema fields (per hook):
  REQUIRED: `tool` xor `python` (mutually exclusive, exactly one)
  OPTIONAL:
    - args: dict[str, Any] = {}
    - inject_as: str = <tool name or python target>
    - required: bool = True (False = on failure, log & continue turn)
    - timeout_s: int = 30 (must be > 0)

Args support template substitution from a SMALL whitelist of context
variables. Anything outside the whitelist is rejected at parse time —
this is the SSTI guard. We never eval expressions; we only substitute
exact-match `{ctx.X}` placeholders.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Whitelist of variables that may appear as `{ctx.X}` in pre-hook args.
# Keep this small. Adding entries is fine; removing breaks contracts.
ALLOWED_TEMPLATE_VARS: frozenset[str] = frozenset(
    {
        "ctx.host",
        "ctx.ssh_user",
        "ctx.ssh_key_path",
        "ctx.ssh_port",
        "ctx.target",
        "ctx.session_id",
        "ctx.client_name",
    }
)

# Match exactly `{ctx.identifier}` and nothing more. The identifier is
# constrained to letters/digits/underscores/dot — no operators, no
# attribute walks, no method calls. Imported by the runner too, so parse-time
# and runtime substitution use ONE regex (no copy-paste drift).
_TEMPLATE_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\}")

# Host/URL/path-safe charset for substituted ctx VALUES. Values get spliced into
# pre_hook commands that may run under a shell, so a value carrying a shell
# metacharacter (; | & $ ` ( ) < > ' " space newline …) IS the command-injection
# vector. Enforced HERE (shared) so both the glue layer (build_turn_ctx) and the
# runtime substitution (pre_hook_runner._substitute_one) reject it regardless of
# which caller assembled the ctx.
_CTX_SAFE_RE = re.compile(r"\A[A-Za-z0-9._:/@\-]*\Z")


def sanitize_ctx_value(value: str) -> str:
    """Return value unchanged if free of shell metacharacters, else "" — the
    hook then substitutes empty and degrades gracefully, never injecting."""
    return value if _CTX_SAFE_RE.match(value or "") else ""


# Path-like sanity for the `python:` escape hatch. Must be a relative
# path under `./`, ending in `.py`, with a callable after `:`.
_PYTHON_PATH_RE = re.compile(r"^\./[A-Za-z0-9_\-./]+\.py:[A-Za-z_][A-Za-z0-9_]*$")

# Allowed top-level keys in a hook dict. Strict schema — typos surface loudly.
_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "tool",
        "python",
        "args",
        "inject_as",
        "required",
        "timeout_s",
    }
)


class PreHookSchemaError(ValueError):
    """Raised on any structural / validation error in a pre_hooks block."""


@dataclass(frozen=True)
class PreHookSpec:
    """One declarative pre-hook. Frozen so consumers can't mutate it."""

    tool: str = ""
    python: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    inject_as: str = ""
    required: bool = True
    timeout_s: int = 30
    # Filesystem directory of the skill markdown that declared this hook.
    # Populated by the loader; needed to resolve `python: ./<file>.py:<func>`
    # relative paths. Empty for declarative-only hooks or when the spec is
    # constructed directly (e.g. in tests via parse_pre_hooks([...])).
    source_dir: str = ""

    def __hash__(self) -> int:
        # dict isn't hashable; JSON-serialize args (sorted) so the spec stays
        # hashable even with LIST-valued args (e.g. args: {hosts: ["{ctx.host}"]}),
        # a shape the schema explicitly supports/documents. tuple(sorted(items))
        # raised "unhashable type: 'list'" the moment an arg value was a list.
        import json

        args_key = json.dumps(self.args, sort_keys=True, default=str) if self.args else ""
        return hash(
            (
                self.tool,
                self.python,
                self.inject_as,
                self.required,
                self.timeout_s,
                self.source_dir,
                args_key,
            )
        )


def _validate_template_string(value: str) -> None:
    """Reject any `{...}` placeholder that's not in ALLOWED_TEMPLATE_VARS.

    Also rejects strings that LOOK like templates but aren't pure {var} —
    i.e. anything containing a brace that isn't a valid placeholder.
    """
    # Find all placeholders that match our strict syntax.
    valid_placeholders = _TEMPLATE_RE.findall(value)
    for var in valid_placeholders:
        if var not in ALLOWED_TEMPLATE_VARS:
            raise PreHookSchemaError(
                f"unknown template variable {{{var}}} (allowed: {', '.join(sorted(ALLOWED_TEMPLATE_VARS))})"
            )

    # Reject any other brace usage. Strip out the valid placeholders and
    # check for residual `{` or `}` — those are SSTI attempts or typos.
    stripped = _TEMPLATE_RE.sub("", value)
    if "{" in stripped or "}" in stripped:
        raise PreHookSchemaError(
            f"invalid template syntax in {value!r} — only "
            "`{ctx.var}` placeholders are allowed (no expressions, no method calls)"
        )


def _validate_arg_value(value: Any) -> None:
    """Scan a value for templates, recursing into lists/dicts so a template
    nested in `args: {hosts: ["{ctx.host}"]}` is validated too (a plain
    isinstance(str) check silently skipped it)."""
    if isinstance(value, str):
        _validate_template_string(value)
    elif isinstance(value, dict):
        for v in value.values():
            _validate_arg_value(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _validate_arg_value(v)


def _validate_args(args: Any) -> dict[str, Any]:
    """Args must be a dict; string values (incl. nested in lists/dicts) are
    scanned for templates."""
    if not isinstance(args, dict):
        raise PreHookSchemaError(f"args must be a dict, got {type(args).__name__}")
    for value in args.values():
        _validate_arg_value(value)
    return dict(args)  # defensive copy


def _validate_python_path(path: str) -> None:
    if not _PYTHON_PATH_RE.match(path):
        raise PreHookSchemaError(
            f"invalid python hook path {path!r} — must match `./<relative_file>.py:<callable>` with no path traversal"
        )
    if ".." in path:
        raise PreHookSchemaError(f"python hook path {path!r} contains path traversal")


def _parse_one(raw: dict[str, Any]) -> PreHookSpec:
    if not isinstance(raw, dict):
        raise PreHookSchemaError(f"each hook must be a dict, got {type(raw).__name__}")

    unknown = set(raw.keys()) - _ALLOWED_KEYS
    if unknown:
        raise PreHookSchemaError(f"unknown field(s) in hook: {sorted(unknown)} (allowed: {sorted(_ALLOWED_KEYS)})")

    tool_raw = raw.get("tool")
    python_raw = raw.get("python")

    # Distinguish "explicit empty string" (typo / mistake) from "key absent".
    if tool_raw is not None and (not isinstance(tool_raw, str) or not tool_raw.strip()):
        raise PreHookSchemaError("tool name must be a non-empty string")
    if python_raw is not None and (not isinstance(python_raw, str) or not python_raw.strip()):
        raise PreHookSchemaError("python target must be a non-empty string")

    tool = (tool_raw or "").strip()
    python = (python_raw or "").strip()

    if tool and python:
        raise PreHookSchemaError("`tool` and `python` are mutually exclusive — pick one")
    if not tool and not python:
        raise PreHookSchemaError("hook must specify either 'tool' or 'python'")

    if python:
        _validate_python_path(python)

    args = _validate_args(raw.get("args", {}))

    inject_as = raw.get("inject_as")
    if inject_as is not None and not isinstance(inject_as, str):
        raise PreHookSchemaError(f"inject_as must be a string, got {type(inject_as).__name__}")
    if not inject_as:
        # Default: the tool name (or python target's callable).
        if tool:
            inject_as = tool
        else:
            inject_as = python.rsplit(":", 1)[-1]

    required = raw.get("required", True)
    if not isinstance(required, bool):
        raise PreHookSchemaError(f"required must be bool, got {type(required).__name__}")

    timeout_s = raw.get("timeout_s", 30)
    if not isinstance(timeout_s, int) or isinstance(timeout_s, bool):
        # bool is a subclass of int — exclude it explicitly.
        raise PreHookSchemaError(f"timeout_s must be an int, got {type(timeout_s).__name__}")
    if timeout_s <= 0:
        raise PreHookSchemaError(f"timeout_s must be positive, got {timeout_s}")

    return PreHookSpec(
        tool=tool,
        python=python,
        args=args,
        inject_as=inject_as,
        required=required,
        timeout_s=timeout_s,
    )


def parse_pre_hooks(
    raw: list[dict[str, Any]] | None,
    source_dir: str = "",
) -> tuple[PreHookSpec, ...]:
    """Parse a frontmatter `pre_hooks:` block into validated specs.

    Args:
        raw: list of dicts from the YAML `pre_hooks:` block.
        source_dir: filesystem directory of the skill markdown that
            declared these hooks. Populated by the loader. Used by the
            runner to resolve `python: ./<file>.py:<func>` paths
            relative to the skill — empty when called from tests with
            direct dicts (then python-hatch hooks fail at runtime if
            they reference files).

    Returns an empty tuple for None / [] / missing input — that's the
    common case for skills without pre-hooks.

    Raises PreHookSchemaError on any structural problem. The caller
    (skill loader) is expected to either propagate the error (loud
    fail at skill load) or skip the offending skill.
    """
    if not raw:
        return ()
    if not isinstance(raw, list):
        raise PreHookSchemaError(f"pre_hooks must be a list, got {type(raw).__name__}")

    parsed: list[PreHookSpec] = []
    seen_inject_as: set[str] = set()
    for idx, item in enumerate(raw):
        try:
            hook = _parse_one(item)
        except PreHookSchemaError as e:
            raise PreHookSchemaError(f"hook[{idx}]: {e}") from None

        if hook.inject_as in seen_inject_as:
            raise PreHookSchemaError(
                f"duplicate inject_as {hook.inject_as!r} at hook[{idx}] — each hook must inject under a unique key"
            )
        seen_inject_as.add(hook.inject_as)

        # Stamp the source dir if provided. Using replace() keeps PreHookSpec
        # frozen (no mutation).
        if source_dir:
            from dataclasses import replace

            hook = replace(hook, source_dir=source_dir)

        parsed.append(hook)

    return tuple(parsed)
