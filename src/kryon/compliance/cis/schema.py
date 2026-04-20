"""Declarative schema for CIS-style compliance check frameworks.

A *framework* YAML file describes a benchmark (e.g. CIS Ubuntu 22.04 L1)
and a list of *checks*. Each check declares a command to run plus a
``pass_when`` boolean expression over the command's output.

The same schema is reused for SWIFT CSP (F40) and BCP Res. 12/2021
(F41) — any framework whose rules can be expressed as
``run shell command → apply predicate`` fits here. Rules that need
genuine Python logic (e.g. timestamp math, multi-host correlation)
stay as hand-written modules under ``compliance/checks/``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass(frozen=True)
class PassWhen:
    """Boolean expression over ``(stdout, stderr, exit_code)``.

    At most one *leaf* predicate per instance; combinators (``all_of``,
    ``any_of``, ``not_``) nest additional :class:`PassWhen` trees.

    Leaves — at most one set per PassWhen:
        ``stdout_contains``      substring must appear in stdout
        ``stdout_not_contains``  substring must NOT appear
        ``stdout_matches``       regex (``re.search``) must match stdout
        ``stdout_not_matches``   regex must NOT match
        ``stdout_empty``         stdout is empty (after strip) / non-empty
        ``exit_code_is``         exact exit code equality

    Combinators:
        ``all_of``               every sub-expression passes
        ``any_of``               at least one sub-expression passes
        ``not_``                 the sub-expression fails
    """

    stdout_contains: Optional[str] = None
    stdout_not_contains: Optional[str] = None
    stdout_matches: Optional[str] = None
    stdout_not_matches: Optional[str] = None
    stdout_empty: Optional[bool] = None
    exit_code_is: Optional[int] = None
    all_of: Optional[tuple["PassWhen", ...]] = None
    any_of: Optional[tuple["PassWhen", ...]] = None
    not_: Optional["PassWhen"] = None


@dataclass(frozen=True)
class CheckSpec:
    """A single declarative check entry from a framework YAML."""

    id: str
    title: str
    section: str
    severity: Severity
    remediation: str
    command: str
    pass_when: PassWhen
    timeout_s: int = 15
    shell: bool = True
    # Optional documentation — not used at runtime, surfaces in reports.
    rationale: str = ""
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class FrameworkMetadata:
    """Top-level ``framework:`` block of the YAML."""

    id: str
    title: str
    version: str
    source: str = ""
    description: str = ""


@dataclass(frozen=True)
class Framework:
    """Parsed framework: metadata + all declarative checks."""

    metadata: FrameworkMetadata
    checks: tuple[CheckSpec, ...]

    def __len__(self) -> int:
        return len(self.checks)
