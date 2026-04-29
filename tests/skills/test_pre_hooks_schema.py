"""Golden tests for the pre_hooks schema parser.

Defines the contract for `kryon.skills.pre_hook_spec`:
  - parse_pre_hooks(raw) -> tuple[PreHookSpec, ...]
  - PreHookSpec is a frozen dataclass: tool, args, inject_as, required,
    timeout_s, python (optional escape hatch).

These tests are written FIRST (TDD): the module will be implemented in
Fase 1 to make them pass. Expect ImportError until then.

Schema rules:
  REQUIRED fields per hook: `tool` OR `python` (mutually exclusive).
  OPTIONAL: args (dict, default {}), inject_as (str, default = tool name),
            required (bool, default True), timeout_s (int, default 30).

Validation rules:
  - tool name must be a non-empty string
  - inject_as must be unique across all hooks of one skill
  - timeout_s must be positive int
  - args values that contain `{...}` templates are validated against a
    whitelist: {ctx.host, ctx.ssh_user, ctx.ssh_key_path, ctx.ssh_port,
                ctx.target, ctx.session_id}.
"""

from __future__ import annotations

import pytest

# These imports must work after Fase 1 lands. Tests fail until then.
from kryon.skills.pre_hook_spec import (  # noqa: E402
    PreHookSpec,
    PreHookSchemaError,
    parse_pre_hooks,
    ALLOWED_TEMPLATE_VARS,
)


# ---------- Valid shapes ----------


def test_parse_single_hook_minimal() -> None:
    raw = [
        {"tool": "run_compliance_audit"},
    ]
    hooks = parse_pre_hooks(raw)
    assert len(hooks) == 1
    h = hooks[0]
    assert h.tool == "run_compliance_audit"
    assert h.args == {}
    assert h.inject_as == "run_compliance_audit"  # defaults to tool name
    assert h.required is True
    assert h.timeout_s == 30


def test_parse_single_hook_full() -> None:
    raw = [
        {
            "tool": "run_compliance_audit",
            "args": {"framework": "fortigate", "host": "{ctx.host}"},
            "inject_as": "deterministic_findings",
            "required": True,
            "timeout_s": 60,
        }
    ]
    hooks = parse_pre_hooks(raw)
    assert len(hooks) == 1
    h = hooks[0]
    assert h.tool == "run_compliance_audit"
    assert h.args["framework"] == "fortigate"
    assert h.args["host"] == "{ctx.host}"
    assert h.inject_as == "deterministic_findings"
    assert h.required is True
    assert h.timeout_s == 60


def test_parse_multiple_hooks_ordered() -> None:
    raw = [
        {"tool": "run_compliance_audit", "args": {"framework": "fortigate"}, "inject_as": "compliance"},
        {"tool": "search_vulnerabilities", "args": {"product": "fortios"}, "inject_as": "cves"},
    ]
    hooks = parse_pre_hooks(raw)
    assert len(hooks) == 2
    assert hooks[0].tool == "run_compliance_audit"
    assert hooks[1].tool == "search_vulnerabilities"
    # Order preserved == frontmatter order
    assert hooks[0].inject_as == "compliance"
    assert hooks[1].inject_as == "cves"


def test_parse_hook_with_required_false() -> None:
    """`required: false` means a failure should NOT abort the turn."""
    raw = [{"tool": "search_vulnerabilities", "required": False}]
    hooks = parse_pre_hooks(raw)
    assert hooks[0].required is False


def test_parse_python_hatch() -> None:
    """Escape hatch: `python: ./<file>.py:<func>` is accepted as alternative
    to `tool:`. Implementation lands in Fase 5; schema accepts it now."""
    raw = [
        {"python": "./fortigate-audit.hooks.py:run", "inject_as": "custom"},
    ]
    hooks = parse_pre_hooks(raw)
    assert hooks[0].python == "./fortigate-audit.hooks.py:run"
    assert hooks[0].tool == ""  # tool is empty when python is set
    assert hooks[0].inject_as == "custom"


def test_parse_empty_raw_returns_empty_tuple() -> None:
    assert parse_pre_hooks([]) == ()
    assert parse_pre_hooks(None) == ()


# ---------- Template variable whitelist ----------


def test_allowed_template_vars_is_frozen_set() -> None:
    """The whitelist must be a frozenset so callers can't mutate it."""
    assert isinstance(ALLOWED_TEMPLATE_VARS, frozenset)
    # Required minimum set — extending later is fine, removing breaks contracts.
    assert {"ctx.host", "ctx.ssh_user", "ctx.target"} <= ALLOWED_TEMPLATE_VARS


def test_template_in_args_passes_validation_when_whitelisted() -> None:
    raw = [
        {"tool": "run_compliance_audit",
         "args": {"host": "{ctx.host}", "ssh_user": "{ctx.ssh_user}"}}
    ]
    # Should not raise
    hooks = parse_pre_hooks(raw)
    assert hooks[0].args["host"] == "{ctx.host}"


def test_template_in_args_rejects_unknown_var() -> None:
    raw = [
        {"tool": "run_compliance_audit",
         "args": {"host": "{ctx.evil_thing}"}}
    ]
    with pytest.raises(PreHookSchemaError, match="unknown template variable"):
        parse_pre_hooks(raw)


def test_template_in_args_rejects_arbitrary_python() -> None:
    """SSTI guard: anything that's not exactly {ctx.X} from whitelist is rejected."""
    bad_cases = [
        {"host": "{__import__('os').system('rm -rf /')}"},
        {"host": "{ctx.host.__class__}"},
        {"host": "{ctx.host or 1==1}"},
    ]
    for args in bad_cases:
        raw = [{"tool": "run_compliance_audit", "args": args}]
        with pytest.raises(PreHookSchemaError):
            parse_pre_hooks(raw)


# ---------- Validation errors ----------


def test_missing_tool_and_python_raises() -> None:
    raw = [{"args": {}, "inject_as": "x"}]
    with pytest.raises(PreHookSchemaError, match="must specify either 'tool' or 'python'"):
        parse_pre_hooks(raw)


def test_both_tool_and_python_raises() -> None:
    raw = [{"tool": "run_command", "python": "./x.py:run"}]
    with pytest.raises(PreHookSchemaError, match="mutually exclusive"):
        parse_pre_hooks(raw)


def test_empty_tool_name_raises() -> None:
    raw = [{"tool": ""}]
    with pytest.raises(PreHookSchemaError, match="non-empty"):
        parse_pre_hooks(raw)


def test_negative_timeout_raises() -> None:
    raw = [{"tool": "run_command", "timeout_s": -5}]
    with pytest.raises(PreHookSchemaError, match="timeout_s.*positive"):
        parse_pre_hooks(raw)


def test_zero_timeout_raises() -> None:
    raw = [{"tool": "run_command", "timeout_s": 0}]
    with pytest.raises(PreHookSchemaError, match="timeout_s.*positive"):
        parse_pre_hooks(raw)


def test_duplicate_inject_as_raises() -> None:
    raw = [
        {"tool": "run_command", "inject_as": "x"},
        {"tool": "nmap", "inject_as": "x"},
    ]
    with pytest.raises(PreHookSchemaError, match="duplicate inject_as"):
        parse_pre_hooks(raw)


def test_args_must_be_dict() -> None:
    raw = [{"tool": "run_command", "args": "not a dict"}]
    with pytest.raises(PreHookSchemaError, match="args.*dict"):
        parse_pre_hooks(raw)


def test_invalid_python_path_raises() -> None:
    """Python escape hatch path must be `./<file>.py:<callable>`."""
    bad_paths = [
        "no_colon.py",
        "/etc/passwd:run",          # absolute path — not allowed
        "../../../escape.py:run",   # path traversal
        ":run",                      # empty file
        "./file.py:",                # empty callable
    ]
    for p in bad_paths:
        raw = [{"python": p}]
        with pytest.raises(PreHookSchemaError):
            parse_pre_hooks(raw)


def test_unknown_top_level_field_raises() -> None:
    """Strict schema: typos like `requireed: true` should fail loud, not silent."""
    raw = [{"tool": "run_command", "requireed": True}]
    with pytest.raises(PreHookSchemaError, match="unknown field"):
        parse_pre_hooks(raw)


# ---------- Frozen dataclass contract ----------


def test_pre_hook_spec_is_frozen() -> None:
    """Spec must be immutable so consumers can't mutate hooks across runs."""
    raw = [{"tool": "run_command"}]
    hook = parse_pre_hooks(raw)[0]
    with pytest.raises((AttributeError, TypeError)):
        hook.tool = "different"  # type: ignore[misc]


def test_pre_hook_spec_is_hashable() -> None:
    """Frozen dataclass should be hashable — needed for cache/dedupe."""
    raw = [{"tool": "run_command"}]
    hook = parse_pre_hooks(raw)[0]
    # If hash() raises, the dataclass isn't frozen properly.
    hash(hook)
