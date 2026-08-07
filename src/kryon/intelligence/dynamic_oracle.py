"""Dynamic oracle (F3) — verify non-memory bugs by canary execution.

ASAN (F2) only adjudicates C/C++ memory violations. But a 284B reasoner will
surface *logic / injection / deserialization / traversal* bugs far more often
than heap overflows — and for those there was no automatic oracle, so they
died in ``needs_verification`` forever.

This closes that gap with a **canary oracle**. The model writes a harness that
inlines the vulnerable function and drives it with a malicious payload crafted
so that *iff the bug is real* an observable side effect fires — printing a
unique canary token. The oracle then just checks: did the canary appear in
stdout? A fired canary is proof the bug is reachable and exploitable; anything
else is not.

Examples of the canary construction (the model builds the specifics):
- CWE-78 cmd-injection: payload ``; echo <CANARY>`` → canary in command output.
- CWE-22 path-traversal: payload ``../../<canary-file>`` → canary file read.
- CWE-89 SQLi: ``' OR '1'='1`` against an in-memory sqlite → dumped canary row.
- CWE-502/94 code-exec: payload whose deserialization/eval prints the canary.

Design mirrors verification_bridge (F2): both impure deps — the PoC generator
(model) and the script runner — are injected callables, so the orchestration
is pure and unit-testable with fakes. Reuses F2's ``VerificationResult`` and
``apply_verification`` so a dynamically-confirmed finding flows downstream with
needs_verification off, exactly like an ASAN-confirmed one.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from kryon.intelligence.source_review import SourceFinding
from kryon.intelligence.verification_bridge import VerificationResult, apply_verification

logger = logging.getLogger(__name__)

# CWEs whose exploitation produces an observable side effect a canary harness
# can prove in a sandboxed interpreter run. The F3 bucket — the complement of
# F2's ASAN memory classes.
DYNAMIC_VERIFIABLE_CWES: frozenset[str] = frozenset(
    {
        "CWE-77",  # command injection (generic)
        "CWE-78",  # OS command injection
        "CWE-88",  # argument injection
        "CWE-89",  # SQL injection
        "CWE-90",  # LDAP injection
        "CWE-91",  # XML injection
        "CWE-94",  # code injection
        "CWE-95",  # eval injection
        "CWE-22",  # path traversal
        "CWE-23",  # relative path traversal
        "CWE-36",  # absolute path traversal
        "CWE-98",  # PHP file inclusion (LFI/RFI)
        "CWE-434",  # unrestricted file upload
        "CWE-502",  # deserialization of untrusted data
        "CWE-611",  # XXE
        "CWE-643",  # XPath injection
        "CWE-776",  # XML entity expansion
        "CWE-917",  # expression language injection
        "CWE-943",  # NoSQL / query injection
        "CWE-1336",  # template injection (SSTI)
    }
)

# Interpreter per source language. Value is the interpreter *name*; python uses
# the current executable so the harness runs under the same env.
_DYNAMIC_LANGS: dict[str, str] = {
    ".py": "python",
    ".rb": "ruby",
    ".php": "php",
    ".js": "node",
    ".jsx": "node",
    ".ts": "node",
    ".pl": "perl",
    ".lua": "lua",
    ".sh": "bash",
}


@dataclass(frozen=True)
class DynamicPocSpec:
    """A canary harness the oracle runs in the source language."""

    script: str
    language: str  # python | ruby | php | node | perl | lua | bash
    canary: str  # the token the script prints IFF the bug fires


# (finding, code_context, canary) -> harness, or None if the model declines.
DynamicPocGenerator = Callable[[SourceFinding, str, str], "DynamicPocSpec | None"]
# (spec) -> run report dict: {ran, stdout, stderr, timeout?, error?}.
DynamicRunner = Callable[["DynamicPocSpec"], dict]


def _lang_for(finding: SourceFinding) -> str | None:
    return _DYNAMIC_LANGS.get(os.path.splitext(finding.file.lower())[1])


def is_dynamic_verifiable(finding: SourceFinding, *, verifiable_cwes: frozenset[str] = DYNAMIC_VERIFIABLE_CWES) -> bool:
    """True if this finding is a non-memory bug with a canary oracle + a
    runnable source language."""
    if finding.cwe.upper().strip() not in verifiable_cwes:
        return False
    return _lang_for(finding) is not None


def _new_canary() -> str:
    return "KRYON_CANARY_" + uuid.uuid4().hex


def verify_dynamic(
    finding: SourceFinding,
    *,
    poc_generator: DynamicPocGenerator,
    runner: DynamicRunner,
    code_context: str = "",
    canary: str | None = None,
) -> VerificationResult:
    """Try to prove ``finding`` by firing a canary. A canary in stdout is the
    only 'confirmed'. Pure modulo the two injected callables.

    Verdicts (shared with F2's VerificationResult):
    - ``confirmed``      — the canary fired: bug is reachable & exploitable.
    - ``not-reproduced`` — harness ran clean, canary never fired.
    - ``poc-error``      — the harness itself errored (bad script).
    - ``no-poc``         — the generator declined.
    - ``inconclusive``   — timeout / runner error.
    - ``unsupported``    — not a dynamic-verifiable class (memory → F2).
    """
    if not is_dynamic_verifiable(finding):
        return VerificationResult(
            verdict="unsupported",
            crash_type="",
            detail=f"{finding.cwe} in {finding.file} has no canary oracle (memory bug → F2)",
            poc_source="",
        )

    token = canary or _new_canary()
    try:
        spec = poc_generator(finding, code_context, token)
    except Exception as e:  # noqa: BLE001
        return VerificationResult("inconclusive", "", f"PoC generation failed ({type(e).__name__}: {e})", "")

    if spec is None or not spec.script.strip():
        return VerificationResult("no-poc", "", "model produced no canary harness for this finding", "")

    try:
        report = runner(spec)
    except Exception as e:  # noqa: BLE001
        return VerificationResult("inconclusive", "", f"runner error ({type(e).__name__}: {e})", spec.script)

    if report.get("error"):
        return VerificationResult("inconclusive", "", f"runner: {report['error']}", spec.script)
    if report.get("timeout"):
        return VerificationResult("inconclusive", "", "canary harness timed out", spec.script)

    stdout = str(report.get("stdout", "") or "")
    if token in stdout:
        return VerificationResult(
            verdict="confirmed",
            crash_type="",
            detail=f"canary fired ({finding.cwe}) — payload reached the sink and produced an observable effect",
            poc_source=spec.script,
        )
    # No canary. A non-zero exit means the harness itself errored (bad script),
    # distinct from a clean run where the payload simply didn't reach a sink.
    if not report.get("ran", True) or report.get("exit_code", 0) not in (0, None):
        return VerificationResult(
            verdict="poc-error",
            crash_type="",
            detail=(str(report.get("stderr", "")) or "harness failed to run")[:300],
            poc_source=spec.script,
        )
    return VerificationResult(
        verdict="not-reproduced",
        crash_type="",
        detail="harness ran but the canary never fired — payload did not reach an exploitable sink",
        poc_source=spec.script,
    )


def verify_findings_dynamic(
    findings: list[SourceFinding],
    *,
    poc_generator: DynamicPocGenerator,
    runner: DynamicRunner,
    context_reader: Callable[[SourceFinding], str] | None = None,
    max_verifications: int = 20,
    only_verifiable: bool = True,
) -> list[SourceFinding]:
    """Run the dynamic oracle over a batch, stamping verdicts. Non-dynamic
    findings (memory bugs / unsupported langs) are left untouched for F2."""
    out: list[SourceFinding] = []
    budget = max_verifications
    for f in findings:
        if only_verifiable and not is_dynamic_verifiable(f):
            out.append(f)
            continue
        if budget <= 0:
            out.append(f)
            continue
        ctx = context_reader(f) if context_reader else ""
        result = verify_dynamic(f, poc_generator=poc_generator, runner=runner, code_context=ctx)
        budget -= 1
        out.append(apply_verification(f, result))
    return out


# ---------------------------------------------------------------------------
# Default runner (the real sandboxed interpreter execution)
# ---------------------------------------------------------------------------

_SUFFIX_FOR = {"python": ".py", "ruby": ".rb", "php": ".php", "node": ".js", "perl": ".pl", "lua": ".lua", "bash": ".sh"}


def _interpreter(language: str) -> list[str] | None:
    """Resolve the interpreter argv for a language, or None if unavailable."""
    if language == "python":
        return [sys.executable]
    binary = {"node": "node", "php": "php", "ruby": "ruby", "perl": "perl", "lua": "lua", "bash": "bash"}.get(language)
    if not binary:
        return None
    path = shutil.which(binary)
    return [path] if path else None


def default_dynamic_runner(spec: DynamicPocSpec, *, run_timeout: int = 10) -> dict:
    """Write the harness to a tempdir and run it under its interpreter.

    Banca-safe: read-only host, executes only inside the isolated container
    (the same trust boundary run_sandboxed relies on). No network is granted;
    a fired canary must be a *local* observable effect.
    """
    interp = _interpreter(spec.language)
    if interp is None:
        return {"ran": False, "error": f"no interpreter for language={spec.language!r}"}
    if len(spec.script) > 200_000:
        return {"ran": False, "error": "harness too large (>200KB)"}

    workdir = Path(tempfile.mkdtemp(prefix="kryon_dynoracle_"))
    try:
        src = workdir / f"poc{_SUFFIX_FOR.get(spec.language, '.txt')}"
        src.write_text(spec.script, encoding="utf-8")
        try:
            rp = subprocess.run(
                interp + [str(src)],
                capture_output=True,
                text=True,
                timeout=run_timeout,
                check=False,
                cwd=str(workdir),
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
        except subprocess.TimeoutExpired:
            return {"ran": True, "timeout": True}
        return {
            "ran": True,
            "exit_code": rp.returncode,
            "stdout": rp.stdout[:8000],
            "stderr": rp.stderr[:4000],
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


_DYN_INSTRUCTIONS = (
    "You are an exploit developer. Below is a non-memory vulnerability an "
    "auditor flagged (injection / deserialization / path traversal / etc.), "
    "plus the surrounding source. Write a MINIMAL, SELF-CONTAINED harness in "
    "the SAME language that inlines the vulnerable function and drives it with "
    "a malicious payload. Craft the payload so that IF AND ONLY IF the bug is "
    "real, the program prints this exact token to stdout: {canary}\n"
    "Do not print the token on any other path. If you genuinely cannot build "
    "such a harness, output the single token NO_POC.\n\n"
    "Respond with ONLY a JSON object (no prose, no fences): "
    '{{"language": "python"|"node"|"php"|"ruby"|"perl"|"lua"|"bash", '
    '"script": "<full program that prints the canary iff exploitable>"}}.'
)


class LocalDynamicPocGenerator:
    """Default ``DynamicPocGenerator`` — asks the local reasoning model
    (V4-Flash via llama.cpp) to write a canary harness."""

    def __init__(self, model: str | None = None, host: str | None = None, *, timeout: int = 240, temperature: float = 0.2) -> None:
        self.model = model or os.environ.get("KRYON_SOURCE_REVIEW_MODEL", "kryon-local")
        self.host = host or os.environ.get(
            "KRYON_SOURCE_REVIEW_BASE_URL",
            os.environ.get("OPENAI_BASE_URL", "http://localhost:8080/v1"),
        )
        self.api_key = os.environ.get("OPENAI_API_KEY", "llama")
        self.timeout = timeout
        self.temperature = temperature

    def __call__(self, finding: SourceFinding, code_context: str, canary: str) -> DynamicPocSpec | None:
        prompt = (
            f"{_DYN_INSTRUCTIONS.format(canary=canary)}\n\n"
            f"Finding: {finding.cwe} at {finding.file}:{finding.line} — {finding.title}\n"
            f"Sink: {finding.sink}\nEvidence: {finding.evidence}\n\n"
            f"Source context:\n```\n{code_context[:20000]}\n```\n"
        )
        raw = self._chat(prompt)
        return self._parse(raw, canary)

    @staticmethod
    def _parse(raw: str, canary: str) -> DynamicPocSpec | None:
        import json

        from kryon.intelligence.source_review import strip_think

        cleaned = strip_think(raw)
        if "NO_POC" in cleaned and "{" not in cleaned:
            return None
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start == -1 or end <= start:
            return None
        try:
            obj = json.loads(cleaned[start : end + 1])
        except (json.JSONDecodeError, ValueError):
            return None
        script = str(obj.get("script", "")).strip()
        if not script:
            return None
        lang = str(obj.get("language", "python")).strip().lower()
        if lang in ("js", "javascript", "typescript", "ts"):
            lang = "node"
        if lang not in _SUFFIX_FOR:
            lang = "python"
        return DynamicPocSpec(script=script, language=lang, canary=canary)

    def _chat(self, prompt: str) -> str:
        import json
        import urllib.request

        url = self.host.rstrip("/") + "/chat/completions"
        payload = json.dumps(
            {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "temperature": self.temperature,
                "max_tokens": 4096,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        choices = data.get("choices") or []
        if not choices:
            return ""
        return (choices[0].get("message", {}) or {}).get("content", "") or ""
