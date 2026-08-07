"""FASE 9.A — auto-distillation: planner rules loadable from YAML.

Background
==========
Through FASES 1-8 every planner rule was a Python function hard-coded
in ``exploit_chain_planner``. Each new exploit class the operator
resolved manually required a code change, a test, and a commit. That
makes the system fast for known classes (Python REPL → asreproast →
secretsdump) but slow to extend.

This module breaks that bottleneck. Rules can now be expressed as YAML
files dropped into ``~/.kryon/distilled_rules/*.yaml`` (or a directory
override via ``KRYON_DISTILLED_RULES_DIR``). At planner-import time we
scan the directory, parse each file into a ``DistilledRule``, and turn
it into a callable that matches the ``_Rule`` signature used by
``plan_next_action``. The runtime can pick those callables up
alongside the hard-coded Python rules without any code change.

YAML schema
===========

.. code-block:: yaml

   name: confirm_python_repl
   confidence: 0.92
   when:
     hints_any_of:
       - "invalid syntax"
       - "is not defined"
     services_have_non_ssh_port: true
     not_invoked_before:
       - "kryon-probe"
   emit:
     tool: run_command
     args: |
       echo 'print("kryon-probe")' | nc -q 1 -w 5 <target> {port}
     rationale: |
       The server emitted a Python NameError / SyntaxError — that
       comes from compile()+exec() on input. ``print('kryon-probe')``
       confirms exec() if the server echoes the string.

Predicates supported in ``when``:
  - ``hints_any_of``: list of strings; fires when ANY appears in
    ``facts.hints`` (case-insensitive substring match).
  - ``hints_all_of``: same, but ALL must appear.
  - ``services_have_non_ssh_port``: True ⇒ rule needs a non-22 port
    in ``facts.services``; first non-22 port substitutes ``{port}``
    in the args template.
  - ``users_present``: minimum count.
  - ``creds_present``: True ⇒ at least one cred tuple.
  - ``hashes_present``: True ⇒ at least one hash string.
  - ``domains_present``: True ⇒ at least one AD domain.
  - ``not_invoked_before``: list of substrings; rule abstains if any
    appears in ``prior_tool_args`` (to avoid re-firing).
  - ``invoked_before``: list of substrings; rule REQUIRES all to be
    present (used for chain ordering — only fire after a previous
    stage's marker appears in history).

Template substitution in ``args``:
  - ``<target>``: kept as a literal placeholder (the reflective
    runner substitutes it with the concrete host later).
  - ``{port}``: replaced with the first non-SSH port from
    ``facts.services`` when ``services_have_non_ssh_port`` is true.
  - ``{domain}``: first entry from ``facts.domains``.
  - ``{user}``: first cred's username, when ``creds_present`` is true.
  - ``{password}``: first cred's password.

Failure mode
============
A malformed YAML file logs a warning and gets skipped; the planner
keeps working with the hard-coded rules. We never raise from inside
the planner's rule loop — distillation is supposed to extend, not
break, the base system.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from kryon.intelligence.exploit_chain_planner import (
    NextActionRecommendation,
)
from kryon.intelligence.fact_extractor import ExtractedFacts

logger = logging.getLogger(__name__)


_PLACEHOLDER_PORT = "{port}"
_PLACEHOLDER_DOMAIN = "{domain}"
_PLACEHOLDER_USER = "{user}"
_PLACEHOLDER_PASSWORD = "{password}"


@dataclass(frozen=True)
class DistilledRule:
    """Parsed-and-validated representation of one YAML rule file.

    Once built, ``as_callable()`` returns a function matching the
    ``_Rule`` signature in ``exploit_chain_planner._RULES``.
    """

    name: str
    confidence: float
    tool: str
    args_template: str
    rationale: str
    hints_any_of: tuple[str, ...] = ()
    hints_all_of: tuple[str, ...] = ()
    services_have_non_ssh_port: bool = False
    users_present: int = 0
    creds_present: bool = False
    hashes_present: bool = False
    domains_present: bool = False
    not_invoked_before: tuple[str, ...] = ()
    invoked_before: tuple[str, ...] = ()
    source_path: str = ""

    def _check_preconditions(
        self,
        facts: ExtractedFacts,
        prior_args: list[str],
    ) -> tuple[bool, dict[str, str]]:
        """Walk every predicate. Return (passed, substitutions).
        ``substitutions`` carries the values that fill the args
        template (port, domain, user, password) when the rule fires.
        """
        subs: dict[str, str] = {}
        if self.hints_any_of:
            lower = [h.lower() for h in facts.hints]
            if not any(phrase.lower() in h for phrase in self.hints_any_of for h in lower):
                return False, subs
        if self.hints_all_of:
            lower = [h.lower() for h in facts.hints]
            if not all(any(phrase.lower() in h for h in lower) for phrase in self.hints_all_of):
                return False, subs
        if self.services_have_non_ssh_port:
            port = ""
            for p, _svc in facts.services:
                if p == 22:
                    continue
                port = str(p)
                break
            if not port:
                return False, subs
            subs[_PLACEHOLDER_PORT] = port
        if self.users_present and len(facts.users) < self.users_present:
            return False, subs
        if self.creds_present:
            if not facts.creds:
                return False, subs
            user, pwd = facts.creds[0]
            subs[_PLACEHOLDER_USER] = user  # already sanitized by ExtractedFacts
            # The password legitimately carries shell metachars; shlex-quote it so
            # a distilled-rule template can't be broken out of (templates must use
            # bare {password}, no surrounding quotes — shlex adds its own).
            import shlex

            subs[_PLACEHOLDER_PASSWORD] = shlex.quote(pwd)
        if self.hashes_present and not facts.hashes:
            return False, subs
        if self.domains_present:
            if not facts.domains:
                return False, subs
            subs[_PLACEHOLDER_DOMAIN] = facts.domains[0]
        if self.not_invoked_before:
            lowered = [a.lower() for a in prior_args]
            for marker in self.not_invoked_before:
                if any(marker.lower() in arg for arg in lowered):
                    return False, subs
        if self.invoked_before:
            lowered = [a.lower() for a in prior_args]
            for marker in self.invoked_before:
                if not any(marker.lower() in arg for arg in lowered):
                    return False, subs
        return True, subs

    def _render_args(self, subs: dict[str, str]) -> str:
        """Apply collected substitutions to the args template."""
        out = self.args_template
        for placeholder, value in subs.items():
            out = out.replace(placeholder, value)
        return out

    def as_callable(
        self,
    ) -> Callable[
        [ExtractedFacts, list[str], str],
        NextActionRecommendation | None,
    ]:
        """Return a function that the planner can call alongside its
        hard-coded rules. The closure captures this dataclass."""

        def _rule(
            facts: ExtractedFacts,
            prior_tool_args: list[str],
            intent: str,
        ) -> NextActionRecommendation | None:
            try:
                ok, subs = self._check_preconditions(facts, prior_tool_args)
            except Exception as exc:  # noqa: BLE001 — must never raise
                logger.debug(
                    "distilled rule %r precondition check failed: %s",
                    self.name,
                    exc,
                )
                return None
            if not ok:
                return None
            try:
                args = self._render_args(subs)
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "distilled rule %r arg render failed: %s",
                    self.name,
                    exc,
                )
                return None
            return NextActionRecommendation(
                tool=self.tool,
                args=args,
                rationale=self.rationale,
                confidence=self.confidence,
            )

        # Set ``__name__`` so logging in the planner identifies which
        # distilled rule fired even though the function is a closure.
        _rule.__name__ = f"_distilled_rule_{self.name}"  # type: ignore[attr-defined]
        return _rule


def _coerce_str_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value)
    return ()


def parse_distilled_rule(
    data: dict[str, Any],
    source_path: str = "",
) -> DistilledRule:
    """Validate + build a ``DistilledRule`` from a parsed dict.

    Raises ``ValueError`` when required fields are missing — caller
    catches and logs so the planner keeps the other rules.
    """
    if not isinstance(data, dict):
        raise ValueError("distilled rule must be a YAML mapping")
    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("distilled rule requires a non-empty 'name'")
    emit = data.get("emit") or {}
    if not isinstance(emit, dict):
        raise ValueError("'emit' must be a mapping")
    tool = emit.get("tool")
    if not isinstance(tool, str) or not tool.strip():
        raise ValueError("'emit.tool' is required")
    args = emit.get("args")
    if not isinstance(args, str) or not args.strip():
        raise ValueError("'emit.args' is required (string template)")
    rationale = emit.get("rationale") or "(no rationale provided)"
    if not isinstance(rationale, str):
        rationale = str(rationale)

    raw_confidence = data.get("confidence", 0.8)
    try:
        confidence = float(raw_confidence)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"'confidence' must be a number, got {raw_confidence!r}") from exc
    if not 0.0 <= confidence <= 1.0:
        raise ValueError(f"'confidence' must be in [0.0, 1.0], got {confidence}")

    when = data.get("when") or {}
    if not isinstance(when, dict):
        raise ValueError("'when' must be a mapping")

    users_present_raw = when.get("users_present", 0)
    try:
        users_present = int(users_present_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"'when.users_present' must be int, got {users_present_raw!r}") from exc

    return DistilledRule(
        name=name.strip(),
        confidence=confidence,
        tool=tool.strip(),
        args_template=args,
        rationale=rationale.strip(),
        hints_any_of=_coerce_str_tuple(when.get("hints_any_of")),
        hints_all_of=_coerce_str_tuple(when.get("hints_all_of")),
        services_have_non_ssh_port=bool(when.get("services_have_non_ssh_port", False)),
        users_present=users_present,
        creds_present=bool(when.get("creds_present", False)),
        hashes_present=bool(when.get("hashes_present", False)),
        domains_present=bool(when.get("domains_present", False)),
        not_invoked_before=_coerce_str_tuple(when.get("not_invoked_before")),
        invoked_before=_coerce_str_tuple(when.get("invoked_before")),
        source_path=source_path,
    )


def _default_distilled_rules_dir() -> Path:
    override = os.environ.get("KRYON_DISTILLED_RULES_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".kryon" / "distilled_rules"


def load_distilled_rules(
    directory: Path | None = None,
) -> list[
    Callable[
        [ExtractedFacts, list[str], str],
        NextActionRecommendation | None,
    ]
]:
    """Scan ``directory`` (default ``~/.kryon/distilled_rules/``) for
    YAML rule files and return them as planner-compatible callables.

    Files that fail validation log a warning and get skipped — the
    planner never breaks on a bad distilled rule.

    Sorting: callables are returned in lexicographic order of file
    name so the operator can prefix files with numeric ordering hints
    (``00_high_priority.yaml`` fires before ``99_fallback.yaml``).
    """
    if directory is None:
        directory = _default_distilled_rules_dir()
    if not directory.is_dir():
        logger.debug(
            "distilled rules dir %s does not exist — none to load",
            directory,
        )
        return []
    try:
        import yaml  # PyYAML; project already depends on it via skills loader
    except ImportError:  # pragma: no cover — yaml is in the lockfile
        logger.warning(
            "PyYAML unavailable — skipping distilled rules in %s",
            directory,
        )
        return []

    rules: list[Callable] = []
    for path in sorted(directory.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            rule = parse_distilled_rule(data, source_path=str(path))
            rules.append(rule.as_callable())
            logger.info(
                "loaded distilled rule %r from %s (confidence=%.2f)",
                rule.name,
                path.name,
                rule.confidence,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "skipping distilled rule %s — failed to parse: %s",
                path.name,
                exc,
            )
    return rules


__all__ = [
    "DistilledRule",
    "parse_distilled_rule",
    "load_distilled_rules",
]
