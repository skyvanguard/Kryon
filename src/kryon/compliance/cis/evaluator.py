"""Evaluator for :class:`~kryon.compliance.cis.schema.PassWhen` expressions.

Pure function from ``(stdout, stderr, exit_code) + PassWhen`` to bool.
Kept tiny and allocation-free so importing thousands of checks does not
dominate registry init time.
"""

from __future__ import annotations

import re

from kryon.compliance.cis.schema import PassWhen


class PassWhenError(ValueError):
    """The ``pass_when`` expression is malformed (detected at eval time)."""


def evaluate(pw: PassWhen, *, stdout: str, stderr: str, exit_code: int) -> bool:
    """Return ``True`` iff the check's output satisfies the predicate.

    Unknown / empty :class:`PassWhen` (no field set) evaluates to
    ``True``; callers that want a default-fail can wrap in ``not_``.
    """
    if pw.all_of is not None:
        return all(evaluate(sub, stdout=stdout, stderr=stderr, exit_code=exit_code) for sub in pw.all_of)
    if pw.any_of is not None:
        return any(evaluate(sub, stdout=stdout, stderr=stderr, exit_code=exit_code) for sub in pw.any_of)
    if pw.not_ is not None:
        return not evaluate(pw.not_, stdout=stdout, stderr=stderr, exit_code=exit_code)

    # Leaf predicates — at most one should be set; multiples ANDed.
    decided = False
    result = True

    if pw.stdout_contains is not None:
        result = result and (pw.stdout_contains in stdout)
        decided = True
    if pw.stdout_not_contains is not None:
        result = result and (pw.stdout_not_contains not in stdout)
        decided = True
    if pw.stdout_matches is not None:
        result = result and bool(re.search(pw.stdout_matches, stdout, re.MULTILINE))
        decided = True
    if pw.stdout_not_matches is not None:
        result = result and not re.search(pw.stdout_not_matches, stdout, re.MULTILINE)
        decided = True
    if pw.stdout_empty is not None:
        is_empty = not stdout.strip()
        result = result and (is_empty if pw.stdout_empty else not is_empty)
        decided = True
    if pw.exit_code_is is not None:
        result = result and (exit_code == pw.exit_code_is)
        decided = True

    if not decided:
        # An empty PassWhen with no combinators and no leaves is a
        # framework authoring bug — refuse rather than silently pass.
        raise PassWhenError("pass_when must set at least one predicate or combinator")

    return result
