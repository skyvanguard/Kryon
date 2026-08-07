"""Tests for variant analysis Etapa A (robust sink matching) + Etapa B
(seed-context-directed re-review).

Etapa A: collect_variant_targets no longer does a literal substring match on
the sink — it matches the sink's call token whitespace-insensitively, so
``memcpy (dst,`` and ``memcpy(\\n dst,`` hit where ``memcpy(dst, src, n)`` as a
literal substring would miss them.

Etapa B: during the variant loop, review_tree passes the confirmed primary-pass
sinks to the reviewer as ``seed_context`` so the re-review is directed. The
Reviewer = Callable[[str, str]] contract stays intact for fakes that don't
accept the kwarg.
"""

from __future__ import annotations

from pathlib import Path

from kryon.intelligence.source_review import (
    SourceFinding,
    _build_seed_context,
    _call_reviewer,
    _compile_sink_matchers,
    build_review_prompt,
    collect_variant_targets,
    review_tree,
)


def _write(p: Path, content: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _seed(sink: str, *, confidence: float = 0.9, cwe: str = "CWE-78", title: str = "t") -> SourceFinding:
    return SourceFinding(
        file="seed.c", line=1, cwe=cwe, severity="HIGH", title=title, sink=sink, confidence=confidence
    )


# ---------------------------------------------------------------------------
# Etapa A — robust sink matchers
# ---------------------------------------------------------------------------


def test_compile_matchers_call_token_from_full_sink():
    # A full call-shaped sink compiles to a call-token regex, not a literal.
    matchers = _compile_sink_matchers({"memcpy(dst, src, n)"})
    assert len(matchers) == 1
    assert matchers[0].search("  memcpy(a, b, c);")
    # whitespace between name and paren — the old literal substring missed this
    assert matchers[0].search("memcpy (a, b, c);")
    # newline after the paren
    assert matchers[0].search("memcpy(\n    a, b, c);")
    # a different arg list is irrelevant; the call token is what matters
    assert matchers[0].search("y = memcpy(other, args);")


def test_compile_matchers_no_false_substring():
    # `strcpy` must not match `my_strcpy_wrapper(` — \b guards the token,
    # and the old `s in code` would have false-hit on the substring.
    matchers = _compile_sink_matchers({"strcpy(d, s)"})
    assert not matchers[0].search("my_strcpy_wrapper(d, s)")
    assert matchers[0].search("strcpy(d, s)")


def test_compile_matchers_non_call_sink_literal():
    # A sink with no call token (assignment / operator) falls back to a literal.
    matchers = _compile_sink_matchers({"innerHTML ="})
    assert matchers[0].search("el.innerHTML = userInput")


def test_variant_target_matches_whitespace_variant(tmp_path: Path):
    # The whole point of Etapa A: a real variant written with a space after the
    # function name is now caught where it was silently missed before.
    _write(tmp_path / "seed.c", "system(cmd);\n")
    hit = _write(tmp_path / "variant.c", "int r = system (userctrl);\n")
    _write(tmp_path / "clean.c", "return 0;\n")

    seed = _seed("system(cmd)", cwe="CWE-78")
    targets = collect_variant_targets(tmp_path, [seed], {tmp_path / "seed.c"})

    assert hit in targets
    assert (tmp_path / "clean.c") not in targets


def test_variant_target_no_wrapper_false_positive(tmp_path: Path):
    # A wrapper function whose name merely contains the sink token must not be
    # flagged as a variant (the substring match would have).
    _write(tmp_path / "seed.c", "strcpy(a, b);\n")
    wrapper = _write(tmp_path / "wrap.c", "void safe_strcpy_bounded(char *d) {}\n")

    seed = _seed("strcpy(a, b)", cwe="CWE-120")
    targets = collect_variant_targets(tmp_path, [seed], {tmp_path / "seed.c"})

    assert wrapper not in targets


# ---------------------------------------------------------------------------
# Etapa B — seed-context-directed re-review
# ---------------------------------------------------------------------------


def test_build_seed_context_lists_confident_sinks():
    ctx = _build_seed_context(
        [
            _seed("system(cmd)", confidence=0.9, cwe="CWE-78", title="cmd injection"),
            _seed("sprintf(buf, s)", confidence=0.8, cwe="CWE-120", title="overflow"),
        ]
    )
    assert "VARIANT ANALYSIS" in ctx
    assert "system(cmd)" in ctx
    assert "CWE-78" in ctx
    assert "sprintf(buf, s)" in ctx


def test_build_seed_context_skips_low_confidence_and_variants():
    low = _seed("weak()", confidence=0.3)
    variant = SourceFinding(
        file="v.c", line=2, cwe="CWE-78", severity="HIGH", title="t",
        sink="system(x)", confidence=0.9, variant_of="variant-expansion",
    )
    ctx = _build_seed_context([low, variant])
    assert ctx == ""


def test_build_seed_context_empty_when_no_seeds():
    assert _build_seed_context([]) == ""


def test_build_review_prompt_includes_seed_context():
    prompt = build_review_prompt("f.c", "system(x);", seed_context="VARIANT ANALYSIS — foo")
    assert "VARIANT ANALYSIS — foo" in prompt
    # without it, no seed block
    assert "VARIANT ANALYSIS" not in build_review_prompt("f.c", "system(x);")


def test_call_reviewer_threads_seed_when_accepted():
    seen = {}

    def seed_aware(rel: str, code: str, seed_context: str = "") -> list[SourceFinding]:
        seen["ctx"] = seed_context
        return []

    _call_reviewer(seed_aware, "f.c", "code", "SEED-CTX")
    assert seen["ctx"] == "SEED-CTX"


def test_call_reviewer_falls_back_for_plain_callable():
    # A 2-arg fake must still work (no TypeError) — the contract is preserved.
    def plain(rel: str, code: str) -> list[SourceFinding]:
        return [SourceFinding(file=rel, line=1, cwe="CWE-1", severity="LOW", title="t")]

    out = _call_reviewer(plain, "f.c", "code", "SEED-CTX")
    assert len(out) == 1


def test_call_reviewer_no_seed_context_uses_two_arg():
    calls = []

    def seed_aware(rel: str, code: str, seed_context: str = "") -> list[SourceFinding]:
        calls.append(seed_context)
        return []

    _call_reviewer(seed_aware, "f.c", "code", "")  # empty seed → classic call
    assert calls == [""]


def test_review_tree_passes_seed_context_to_variant_review(tmp_path: Path):
    # seed.c has denser sinks → picked as the single primary file; variant.c is
    # left out of the primary pass and reached ONLY via variant expansion, where
    # the seed context must be threaded in.
    _write(tmp_path / "seed.c", "system(cmd);\nexec(a);\nsystem(b);\n")
    _write(tmp_path / "variant.c", "system(other);\n")

    seed_contexts: list[str] = []

    def reviewer(rel: str, code: str, seed_context: str = "") -> list[SourceFinding]:
        seed_contexts.append(seed_context)
        if "system(" in code:
            return [
                SourceFinding(
                    file=rel, line=1, cwe="CWE-78", severity="HIGH",
                    title="cmd injection", sink="system(cmd)", confidence=0.9,
                )
            ]
        return []

    result = review_tree(tmp_path, reviewer=reviewer, max_files=1)

    # primary pass ran with no seed; variant pass ran with a non-empty seed
    assert "" in seed_contexts
    assert any("VARIANT ANALYSIS" in c and "system(cmd)" in c for c in seed_contexts)
    # the variant file was reached
    assert result.variant_files_reviewed >= 1
    assert len(result.findings) >= 1
