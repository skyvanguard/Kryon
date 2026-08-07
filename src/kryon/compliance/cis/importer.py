"""Load a declarative CIS-style framework YAML and register its checks.

The importer:

1. Parses a YAML file into a :class:`~kryon.compliance.cis.schema.Framework`
   (strictly typed, frozen).
2. For each :class:`CheckSpec`, builds a tiny runtime wrapper that
   satisfies the :class:`~kryon.compliance.checks.base.Check` protocol.
3. Calls :func:`~kryon.compliance.runner.register_check` so the check
   participates in the same ``run_all`` / ``reproducibility_hash``
   pipeline the hand-written PVE/AD/PCI checks use.

Public API:

    load_framework(path)            → Framework (parsed, not registered)
    register_framework(path)        → list[Check] and registers them
    build_check(spec)               → Check (for testing without registry)

Design notes:
- We do NOT lazily read YAML on every ``run()`` call. The framework is
  parsed once at import time, checks are registered once; each check's
  ``run()`` only executes the command and the pre-parsed predicate.
- The generated check class is a real dataclass-backed object, not a
  dict-lookup, so it pickles and prints cleanly in tracebacks.
- If ``pass_when`` evaluation raises for a given result, we return an
  ``ERROR`` verdict rather than crashing the whole run. Framework
  authoring bugs surface as ERRORs on exactly the affected checks.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from kryon.compliance.checks.base import CheckContext, CheckResult
from kryon.compliance.cis.evaluator import PassWhenError, evaluate
from kryon.compliance.cis.schema import (
    CheckSpec,
    Framework,
    FrameworkMetadata,
    PassWhen,
)
from kryon.compliance.runner import register_check, run_cmd


class FrameworkSchemaError(ValueError):
    """Framework YAML failed structural validation."""


_ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_LEAF_PREDICATES = {
    "stdout_contains",
    "stdout_not_contains",
    "stdout_matches",
    "stdout_not_matches",
    "stdout_empty",
    "exit_code_is",
}
_COMBINATORS = {"all_of", "any_of", "not_", "not"}


def _parse_pass_when(raw: Any, path: str) -> PassWhen:
    """Parse a ``pass_when:`` YAML fragment into a :class:`PassWhen`."""
    if not isinstance(raw, dict):
        raise FrameworkSchemaError(f"{path}: pass_when must be a mapping, got {type(raw).__name__}")

    unknown = set(raw) - _LEAF_PREDICATES - _COMBINATORS
    if unknown:
        raise FrameworkSchemaError(f"{path}: unknown pass_when keys: {sorted(unknown)}")

    kwargs: dict[str, Any] = {}

    for key in _LEAF_PREDICATES:
        if key in raw:
            kwargs[key] = raw[key]

    if "all_of" in raw:
        if not isinstance(raw["all_of"], list) or not raw["all_of"]:
            raise FrameworkSchemaError(f"{path}: all_of must be a non-empty list")
        kwargs["all_of"] = tuple(_parse_pass_when(sub, f"{path}.all_of[{i}]") for i, sub in enumerate(raw["all_of"]))
    if "any_of" in raw:
        if not isinstance(raw["any_of"], list) or not raw["any_of"]:
            raise FrameworkSchemaError(f"{path}: any_of must be a non-empty list")
        kwargs["any_of"] = tuple(_parse_pass_when(sub, f"{path}.any_of[{i}]") for i, sub in enumerate(raw["any_of"]))
    # Accept both `not` and `not_` — YAML authors prefer `not`.
    for nkey in ("not_", "not"):
        if nkey in raw:
            kwargs["not_"] = _parse_pass_when(raw[nkey], f"{path}.{nkey}")
            break

    if not kwargs:
        raise FrameworkSchemaError(f"{path}: pass_when must set at least one predicate or combinator")

    return PassWhen(**kwargs)


def _parse_check(raw: Any, index: int) -> CheckSpec:
    if not isinstance(raw, dict):
        raise FrameworkSchemaError(f"checks[{index}]: entry must be a mapping, got {type(raw).__name__}")

    required = {"id", "title", "section", "severity", "remediation", "command", "pass_when"}
    missing = required - set(raw)
    if missing:
        raise FrameworkSchemaError(f"checks[{index}] ({raw.get('id', '?')}): missing keys: {sorted(missing)}")

    severity = str(raw["severity"]).upper()
    if severity not in _ALLOWED_SEVERITIES:
        raise FrameworkSchemaError(
            f"checks[{index}] {raw['id']}: severity must be one of {sorted(_ALLOWED_SEVERITIES)}, got {severity!r}"
        )

    pw = _parse_pass_when(raw["pass_when"], f"checks[{index}].{raw['id']}.pass_when")

    refs_raw = raw.get("references", ())
    if isinstance(refs_raw, list):
        references = tuple(str(r) for r in refs_raw)
    elif isinstance(refs_raw, tuple):
        references = refs_raw
    else:
        references = ()

    return CheckSpec(
        id=str(raw["id"]),
        title=str(raw["title"]),
        section=str(raw["section"]),
        severity=severity,  # type: ignore[arg-type]
        remediation=str(raw["remediation"]),
        command=str(raw["command"]),
        pass_when=pw,
        timeout_s=int(raw.get("timeout_s", 15)),
        shell=bool(raw.get("shell", True)),
        rationale=str(raw.get("rationale", "")),
        references=references,
    )


def _parse_framework(raw: Any) -> Framework:
    if not isinstance(raw, dict):
        raise FrameworkSchemaError("top-level YAML must be a mapping")

    if "framework" not in raw or "checks" not in raw:
        raise FrameworkSchemaError("YAML must contain top-level 'framework' and 'checks' keys")

    fw_raw = raw["framework"]
    if not isinstance(fw_raw, dict):
        raise FrameworkSchemaError("'framework' must be a mapping")
    for key in ("id", "title", "version"):
        if key not in fw_raw:
            raise FrameworkSchemaError(f"framework.{key} is required")

    metadata = FrameworkMetadata(
        id=str(fw_raw["id"]),
        title=str(fw_raw["title"]),
        version=str(fw_raw["version"]),
        source=str(fw_raw.get("source", "")),
        description=str(fw_raw.get("description", "")),
    )

    checks_raw = raw["checks"]
    if not isinstance(checks_raw, list) or not checks_raw:
        raise FrameworkSchemaError("'checks' must be a non-empty list")

    seen_ids: set[str] = set()
    checks: list[CheckSpec] = []
    for i, c in enumerate(checks_raw):
        spec = _parse_check(c, i)
        if spec.id in seen_ids:
            raise FrameworkSchemaError(f"duplicate check id {spec.id!r} at checks[{i}]")
        seen_ids.add(spec.id)
        checks.append(spec)

    return Framework(metadata=metadata, checks=tuple(checks))


def load_framework(path: str | Path) -> Framework:
    """Parse a framework YAML file. No registration side-effects."""
    try:
        import yaml  # noqa: PLC0415 — optional dep, avoid hard import cost
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "PyYAML is required for CIS framework import; add it to the compliance optional extras."
        ) from exc

    src = Path(path)
    if not src.is_file():
        raise FileNotFoundError(f"framework YAML not found: {src}")

    with src.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    try:
        return _parse_framework(raw)
    except FrameworkSchemaError as exc:
        raise FrameworkSchemaError(f"{src}: {exc}") from exc


class _CISCheck:
    """Runtime wrapper generated per :class:`CheckSpec`.

    Satisfies the :class:`~kryon.compliance.checks.base.Check` protocol.
    Instance attributes match the Check protocol by design so the
    existing runner treats it identically to hand-written checks.
    """

    __slots__ = (
        "control_id",
        "control_title",
        "section",
        "severity",
        "remediation_static",
        "_spec",
    )

    def __init__(self, spec: CheckSpec) -> None:
        self.control_id = spec.id
        self.control_title = spec.title
        self.section = spec.section
        self.severity = spec.severity
        self.remediation_static = spec.remediation
        self._spec = spec

    def run(self, ctx: CheckContext) -> CheckResult:
        t0 = time.time()
        spec = self._spec
        out, err, rc = run_cmd(ctx, spec.command, shell=spec.shell, timeout_s=spec.timeout_s)

        # Transport-level error bubbles up as ERROR, not FAIL — we want
        # auditors to see "we could not test" distinct from "test failed".
        if rc in (124, 127) or (rc != 0 and err and "exec error" in err):
            return CheckResult(
                control_id=spec.id,
                control_title=spec.title,
                section=spec.section,
                verdict="ERROR",
                evidence_command=spec.command,
                evidence_stdout=out[:1024],
                evidence_stderr=err[:512],
                evidence_parsed={
                    "reason": "command transport error",
                    "exit_code": rc,
                },
                remediation_static=spec.remediation,
                severity=spec.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        try:
            passed = evaluate(spec.pass_when, stdout=out, stderr=err, exit_code=rc)
        except PassWhenError as exc:
            return CheckResult(
                control_id=spec.id,
                control_title=spec.title,
                section=spec.section,
                verdict="ERROR",
                evidence_command=spec.command,
                evidence_stdout=out[:1024],
                evidence_stderr=err[:512],
                evidence_parsed={
                    "reason": "framework authoring error: " + str(exc),
                },
                remediation_static=spec.remediation,
                severity=spec.severity,
                duration_ms=int((time.time() - t0) * 1000),
                host=ctx.host,
                run_id="",
            )

        return CheckResult(
            control_id=spec.id,
            control_title=spec.title,
            section=spec.section,
            verdict="PASS" if passed else "FAIL",
            evidence_command=spec.command,
            evidence_stdout=out[:2048],
            evidence_stderr=err[:512],
            evidence_parsed={"exit_code": rc, "passed": passed},
            remediation_static=spec.remediation,
            severity=spec.severity,
            duration_ms=int((time.time() - t0) * 1000),
            host=ctx.host,
            run_id="",
        )


def build_check(spec: CheckSpec) -> _CISCheck:
    """Factory helper — returns a Check object without registering."""
    return _CISCheck(spec)


def register_framework(path: str | Path) -> list[_CISCheck]:
    """Load a framework YAML and register every check with the runner.

    Returns the list of registered check objects so callers can also
    interact with them directly (e.g. run a single check, introspect).
    """
    fw = load_framework(path)
    out: list[_CISCheck] = []
    for spec in fw.checks:
        chk = _CISCheck(spec)
        register_check(chk)
        out.append(chk)
    return out
