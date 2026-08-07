"""Deterministic SAST triage tool.

Ranks a local source tree by sink-density and hands the reviewer the top-N files
with their dangerous sinks (file:line + CWE) — so a code-audit starts at the files
most likely to hold the bug instead of grepping the whole tree. On big repos
(CyberGym: openssl/log4j2/struts) a blind ``grep -rn`` floods the model with
hundreds of matches and it never converges; this pre-filters deterministically.

Reuses ``source_review``'s ``SINK_PATTERNS`` + ``enumerate_source_files`` +
``triage_files`` (single source of truth for what counts as a sink).
"""

from __future__ import annotations

from pathlib import Path

from kryon.sdk.agents import function_tool


@function_tool
def sast_triage(code_path: str, top_n: int = 8, sinks_per_file: int = 6) -> str:
    """Rank the source files under a local code tree by sink-density and return the
    top-N candidate files with their dangerous sink lines (file:line + CWE).

    Use this FIRST on a source-code (SAST) task to decide which files to read,
    instead of grepping the whole tree — on large repos a blind grep floods you
    with matches. Then ``cat``/``sed -n`` the top files to confirm the data-flow.

    Args:
        code_path: local directory (or single file) of the source tree to triage.
        top_n: how many top-ranked files to return (default 8).
        sinks_per_file: max sink lines to list per file (default 6).

    Returns:
        A ranked, human-readable list of files with their sink lines, or a note
        when nothing scored (e.g. a language whose sinks aren't modeled).
    """
    from kryon.intelligence.source_review import (
        _COMPILED_SINKS,
        _read_text,
        enumerate_source_files,
        triage_files,
    )

    root = Path(code_path)
    if not root.exists():
        return f"[sast_triage] el path no existe: {code_path}"

    files = enumerate_source_files(root)
    ranked = [(p, s) for p, s in triage_files(files) if s > 0][:top_n]
    if not ranked:
        return (
            f"[sast_triage] 0 archivos con sinks de riesgo bajo {code_path} "
            f"(revisá {len(files)} archivos; el lenguaje puede no estar modelado — "
            f"caé al grep manual)."
        )

    base = root if root.is_dir() else root.parent
    out = [f"[sast_triage] top {len(ranked)} archivos por densidad de sinks en {code_path}:"]
    for p, score in ranked:
        try:
            rel = str(p.relative_to(base))
        except ValueError:
            rel = str(p)
        out.append(f"\n## {rel}  (sink-score {score})")
        try:
            hits = 0
            for i, line in enumerate(_read_text(p).splitlines(), 1):
                matched = next((cwe for rx, cwe in _COMPILED_SINKS if rx.search(line)), None)
                if matched:
                    out.append(f"  {rel}:{i}  [{matched}]  {line.strip()[:90]}")
                    hits += 1
                    if hits >= sinks_per_file:
                        break
        except OSError:
            continue
    out.append(
        "\nAhora `cat`/`sed -n` los archivos de arriba para confirmar el data-flow "
        "y emití `CWE-XXX en <archivo>:<línea>`."
    )
    return "\n".join(out)
