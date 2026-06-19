"""Deterministic SAST ruleset — a semgrep-style pattern scanner that complements
the LLM ``source_review``. It catches the high-frequency CWE sinks (SQLi, command/
code injection, unsafe deserialization, weak crypto, hardcoded secrets, SSRF, DOM
XSS, PHP LFI) with curated, FP-aware regexes. No model, no network.

The LLM review finds the subtle/contextual bugs; this floor of deterministic rules
catches the obvious ones cheaply and reproducibly. Pattern SAST has real false
positives, so findings carry per-rule confidence and ``needs_verification``.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SastFinding:
    file: str
    line: int
    cwe: str
    rule_id: str
    severity: str
    snippet: str
    confidence: float


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    cwe: str
    severity: str
    confidence: float
    exts: tuple[str, ...]
    rx: re.Pattern[str]
    # optional guard: if it matches the line, the rule is suppressed (FP guard)
    skip_rx: re.Pattern[str] | None = None


_PY = (".py",)
_JS = (".js", ".jsx", ".ts", ".tsx")
_PHP = (".php", ".phtml")

_RULES: tuple[_Rule, ...] = (
    # --- Python ---
    _Rule("sast-py-sqli", "CWE-89", "HIGH", 0.6, _PY,
          re.compile(r"\.execute(?:many)?\s*\(\s*(?:f[\"'].*\{|[\"'].*[\"']\s*(?:%|\+|\.format))", re.I)),
    _Rule("sast-py-cmdi", "CWE-78", "CRITICAL", 0.7, _PY,
          re.compile(r"(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True)", re.I),
          re.compile(r"#")),
    _Rule("sast-py-eval", "CWE-94", "HIGH", 0.5, _PY,
          re.compile(r"\b(?:eval|exec)\s*\(\s*(?!['\"])"), re.compile(r"#|ast\.literal_eval")),
    _Rule("sast-py-deser", "CWE-502", "HIGH", 0.8, _PY,
          re.compile(r"\b(?:pickle\.loads?|marshal\.loads|yaml\.load)\s*\(")),
    _Rule("sast-py-weakcrypto", "CWE-327", "MEDIUM", 0.6, _PY,
          re.compile(r"hashlib\.(?:md5|sha1)\s*\(|MODE_ECB|\bDES\.new")),
    _Rule("sast-hardcoded-secret", "CWE-798", "MEDIUM", 0.4, _PY + _JS + _PHP,
          re.compile(r"(?i)(?:password|passwd|secret|api_?key|token|access_?key)\s*[=:]\s*[\"'][^\"'\s]{6,}[\"']"),
          re.compile(r"(?i)os\.(?:environ|getenv)|process\.env|getenv\(|<%|\{\{|example|changeme|xxxx|\*\*\*")),
    _Rule("sast-py-ssrf", "CWE-918", "HIGH", 0.5, _PY,
          re.compile(r"requests\.(?:get|post|put|head)\s*\([^)]*request\.(?:args|form|values|GET|POST|json)", re.I)),
    _Rule("sast-py-pathtraversal", "CWE-22", "HIGH", 0.5, _PY,
          re.compile(r"open\s*\([^)]*(?:request\.(?:args|form|values)|\+\s*\w+).*\)|send_file\s*\([^)]*request\.", re.I)),
    # --- JS / TS ---
    _Rule("sast-js-domxss", "CWE-79", "HIGH", 0.5, _JS,
          re.compile(r"\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(")),
    _Rule("sast-js-eval", "CWE-94", "HIGH", 0.5, _JS,
          re.compile(r"\beval\s*\(|new\s+Function\s*\("), re.compile(r"//")),
    _Rule("sast-js-cmdi", "CWE-78", "CRITICAL", 0.6, _JS,
          re.compile(r"child_process\.exec\s*\(")),
    _Rule("sast-js-sqli", "CWE-89", "HIGH", 0.5, _JS,
          re.compile(r"(?:query|execute)\s*\(\s*`[^`]*\$\{")),
    # --- PHP ---
    _Rule("sast-php-cmdi", "CWE-78", "CRITICAL", 0.6, _PHP,
          re.compile(r"\b(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(")),
    _Rule("sast-php-eval", "CWE-95", "HIGH", 0.6, _PHP,
          re.compile(r"\beval\s*\(")),
    _Rule("sast-php-sqli", "CWE-89", "HIGH", 0.6, _PHP,
          re.compile(r"mysqli?_query\s*\([^)]*\$_(?:GET|POST|REQUEST)", re.I)),
    _Rule("sast-php-lfi", "CWE-98", "HIGH", 0.7, _PHP,
          re.compile(r"\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST)", re.I)),
)

_TEXT_EXTS = frozenset(e for r in _RULES for e in r.exts)
_SKIP_DIRS = frozenset({".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "vendor", ".tox"})


def scan_text(text: str, filename: str) -> list[SastFinding]:
    """Apply every rule whose extension matches ``filename`` to the text. Pure."""
    ext = os.path.splitext(filename)[1].lower()
    rules = [r for r in _RULES if ext in r.exts]
    if not rules:
        return []
    out: list[SastFinding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or len(line) > 1000:
            continue
        for r in rules:
            if r.rx.search(line) and not (r.skip_rx and r.skip_rx.search(line)):
                out.append(SastFinding(filename, i, r.cwe, r.rule_id, r.severity, stripped[:160], r.confidence))
    return out


def scan_path(root: str, max_files: int = 2000) -> list[SastFinding]:
    """Walk a source tree and scan every supported file. Never raises per-file."""
    out: list[SastFinding] = []
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() not in _TEXT_EXTS:
                continue
            if n >= max_files:
                return out
            n += 1
            path = os.path.join(dirpath, fn)
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read(500_000)
            except OSError:
                continue
            out.extend(scan_text(text, path))
    return out


def to_findings(sast: list[SastFinding], host: str = "local"):
    """Convert to engage Findings (needs_verification — pattern SAST has FPs)."""
    from kryon.cli.engage import make_finding  # noqa: PLC0415

    return [
        make_finding(
            s.cwe, s.severity, host, s.rule_id,
            f"{s.rule_id} ({s.cwe}) en {s.file}:{s.line}",
            evidence=f"{s.file}:{s.line} → {s.snippet}",
            remediation="Revisar el sink: parametrizar consultas / evitar shell+concat / deserialización segura / "
                        "secret manager. Hallazgo de patrón determinista — confirmar explotabilidad.",
            confidence=s.confidence,
            needs_verification=True,
        )
        for s in sast
    ]
