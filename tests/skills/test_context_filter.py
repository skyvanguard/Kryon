"""context_filter FP-suppression must not misclassify production files as tests.

The `test_` fragment was matched as a raw substring, so production files like
`src/latest_release/parser.c` (la+test_+release) had their CRITICAL/HIGH findings
silently downgraded to MEDIUM — a false-negative in the suppression logic.
"""

from __future__ import annotations

import pytest

from kryon.skills.context_filter import _is_test_path


@pytest.mark.parametrize(
    "path",
    [
        "src/tests/parser.c",
        "src/test/foo.c",
        "pkg/testing/x.go",
        "a/examples/demo.c",
        "lib/vendor/dep.c",
        "src/parser_test.c",
        "src/parser_tests.c",
        "src/test_parser.c",  # basename starts with test_
        "TEST/UPPER.C",  # case-insensitive
    ],
)
def test_real_test_paths_detected(path):
    assert _is_test_path(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "src/latest_release/parser.c",  # 'test_' substring, NOT a test path
        "src/contest_manager.c",
        "src/fastest_parser.c",
        "src/net/http.c",
        "app/greatest_hits.c",
        "src/attestation/verify.c",  # 'test' substring inside 'attestation'
    ],
)
def test_production_paths_not_misclassified(path):
    assert _is_test_path(path) is False


def test_null_check_requires_control_flow_escape():
    from kryon.skills.context_filter import _has_null_check

    # Fall-through: check logs but does NOT return → deref still unguarded → NOT a null-check.
    assert _has_null_check("if (!ptr) { log_error(); } ptr->field = 1;", "ptr") is False
    # Early-return guard → valid.
    assert _has_null_check("if (!ptr) return -1;", "ptr") is True
    assert _has_null_check("if (ptr == NULL) goto err;", "ptr") is True
    # Positive check guards its own body → valid without an escape.
    assert _has_null_check("if (ptr != NULL) { ptr->field = 1; }", "ptr") is True
    # assert aborts → valid.
    assert _has_null_check("assert(ptr != NULL);", "ptr") is True


def test_multi_deref_line_only_suppresses_if_all_guarded():
    from kryon.skills.context_filter import _extract_dereffed_vars, _has_null_check

    line = "x->f = other->g;"
    vars_ = _extract_dereffed_vars(line)
    assert vars_ == ["x", "other"]
    # Only x is guarded → not all guarded → must NOT suppress.
    preceding = "if (!x) return;"
    assert not all(_has_null_check(preceding, v) for v in vars_)
    # Both guarded → suppress.
    preceding2 = "if (!x) return;\nif (!other) return;"
    assert all(_has_null_check(preceding2, v) for v in vars_)
