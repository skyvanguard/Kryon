"""Verification bridge (F2) — take a reasoned finding to the ASAN oracle.

The two halves of Kryon's zero-day stack were disconnected: ``source_review``
*reasons* about code (where V4-Flash shines, with its 1M-token window) but
never *verifies*; the ASAN sandbox (``tools/code/sandbox.run_sandboxed``)
*verifies* memory bugs as ground truth but was only reachable from the
heuristic ARTEMIS swarm, not from the strong reasoner.

Per the Mythos research, using a sanitizer as the crash oracle was "the single
most important architectural choice — perfectly separates real bugs from
hallucinations". This module is that bridge: a ``SourceFinding`` (with its
``sink``/``evidence``) → a minimal PoC → ``run_sandboxed`` → a hard verdict.

An ASAN crash is proof; anything else is not. That is exactly how the tesis
"harness > modelo" gets satisfied — the harness closes the verification loop
around the reasoner, so a confirmed finding is ground truth, not a hunch.

Design (mirrors source_review / novelty_gate)
---------------------------------------------
Both impure dependencies are injected callables, so the whole orchestration is
pure and unit-testable with fakes — no compiler, no model, no network:

- ``PocGenerator``  (finding, code_context) → ``PocSpec | None``  — the model
  writes a minimal reproducer. ``LocalPocGenerator`` asks the llama.cpp
  endpoint; tests inject a fake.
- ``SandboxRunner`` (spec) → sanitizer report dict — the ASAN oracle.
  ``default_sandbox_runner`` wraps ``_run_sandboxed_impl``; tests inject a fake.

Only C/C++ memory-safety findings are ASAN-verifiable. Everything else
(injection, deser, logic, auth) returns verdict ``unsupported`` and is picked
up by the F3 non-memory oracle.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
from dataclasses import dataclass
from typing import Callable

from kryon.intelligence.source_review import SourceFinding

logger = logging.getLogger(__name__)

# CWEs whose exploitation is a memory-safety violation an ASAN/UBSan build can
# catch at runtime. A crash here is proof; these are the F2 bucket. Everything
# else (89/79/78/94/502/287/918/…) is the F3 non-memory oracle's job.
ASAN_VERIFIABLE_CWES: frozenset[str] = frozenset(
    {
        "CWE-119",  # improper restriction of memory buffer
        "CWE-120",  # buffer copy without checking size (classic overflow)
        "CWE-121",  # stack-based buffer overflow
        "CWE-122",  # heap-based buffer overflow
        "CWE-124",  # buffer underwrite
        "CWE-125",  # out-of-bounds read
        "CWE-126",  # buffer over-read
        "CWE-127",  # buffer under-read
        "CWE-131",  # incorrect buffer size calculation
        "CWE-134",  # uncontrolled format string
        "CWE-170",  # improper null termination
        "CWE-190",  # integer overflow (UBSan)
        "CWE-191",  # integer underflow (UBSan)
        "CWE-242",  # use of inherently dangerous function (gets)
        "CWE-369",  # divide by zero (UBSan)
        "CWE-415",  # double free
        "CWE-416",  # use after free
        "CWE-457",  # use of uninitialized variable
        "CWE-476",  # NULL pointer dereference
        "CWE-590",  # free of memory not on the heap
        "CWE-617",  # reachable assertion
        "CWE-680",  # integer overflow to buffer overflow
        "CWE-787",  # out-of-bounds write
        "CWE-789",  # memory allocation with excessive size
    }
)

# Only findings in C/C++ files are ASAN-buildable.
_C_CPP_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".m", ".mm")


@dataclass(frozen=True)
class PocSpec:
    """A self-contained reproducer the sandbox can compile and run."""

    source_code: str
    language: str = "c"  # "c" | "cpp"
    stdin_bytes: str = ""
    extra_compile_flags: str = ""


@dataclass(frozen=True)
class VerificationResult:
    """The bridge's judgement for one finding."""

    verdict: str  # confirmed | not-reproduced | poc-build-failed | unsupported | no-poc | inconclusive
    crash_type: str  # ASAN crash class when confirmed
    detail: str
    poc_source: str  # the generated PoC, kept for the report / audit trail


# (finding, code_context) -> a PoC spec, or None if the model won't attempt one.
PocGenerator = Callable[[SourceFinding, str], "PocSpec | None"]
# (spec) -> the sanitizer report dict (parsed run_sandboxed JSON).
SandboxRunner = Callable[["PocSpec"], dict]


def is_asan_verifiable(finding: SourceFinding, *, verifiable_cwes: frozenset[str] = ASAN_VERIFIABLE_CWES) -> bool:
    """True if this finding is a C/C++ memory bug ASAN can adjudicate."""
    if finding.cwe.upper().strip() not in verifiable_cwes:
        return False
    suffix = os.path.splitext(finding.file.lower())[1]
    return suffix in _C_CPP_SUFFIXES


def verify_finding(
    finding: SourceFinding,
    *,
    poc_generator: PocGenerator,
    sandbox_runner: SandboxRunner,
    code_context: str = "",
    verifiable_cwes: frozenset[str] = ASAN_VERIFIABLE_CWES,
) -> VerificationResult:
    """Try to reproduce ``finding`` under ASAN. A crash is the only 'confirmed'.

    Pure modulo the two injected callables. Verdicts:
    - ``confirmed``       — the PoC crashed under the sanitizer (ground truth).
    - ``not-reproduced``  — PoC compiled and ran clean (no crash).
    - ``poc-build-failed``— the reproducer didn't compile.
    - ``no-poc``          — the generator declined / returned nothing.
    - ``inconclusive``    — timeout or sandbox error.
    - ``unsupported``     — not an ASAN-verifiable class (→ F3 handles it).
    """
    if not is_asan_verifiable(finding, verifiable_cwes=verifiable_cwes):
        return VerificationResult(
            verdict="unsupported",
            crash_type="",
            detail=f"{finding.cwe} in {finding.file} is not an ASAN memory class — needs the F3 oracle",
            poc_source="",
        )

    try:
        spec = poc_generator(finding, code_context)
    except Exception as e:  # noqa: BLE001 — a bad generator must not abort the batch
        return VerificationResult(
            verdict="inconclusive",
            crash_type="",
            detail=f"PoC generation failed ({type(e).__name__}: {e})",
            poc_source="",
        )

    if spec is None or not spec.source_code.strip():
        return VerificationResult(
            verdict="no-poc",
            crash_type="",
            detail="model produced no reproducer for this finding",
            poc_source="",
        )

    try:
        report = sandbox_runner(spec)
    except Exception as e:  # noqa: BLE001
        return VerificationResult(
            verdict="inconclusive",
            crash_type="",
            detail=f"sandbox error ({type(e).__name__}: {e})",
            poc_source=spec.source_code,
        )

    if report.get("error"):
        return VerificationResult(
            verdict="inconclusive",
            crash_type="",
            detail=f"sandbox: {report['error']}",
            poc_source=spec.source_code,
        )
    if report.get("timeout"):
        return VerificationResult(
            verdict="inconclusive",
            crash_type="",
            detail="PoC timed out under the sanitizer",
            poc_source=spec.source_code,
        )
    if not report.get("compiled", False):
        return VerificationResult(
            verdict="poc-build-failed",
            crash_type="",
            detail=(report.get("compile_stderr") or "reproducer did not compile")[:300],
            poc_source=spec.source_code,
        )
    if report.get("crashed", False):
        ct = str(report.get("crash_type") or "crash")
        summary = str(report.get("summary") or "")
        return VerificationResult(
            verdict="confirmed",
            crash_type=ct,
            detail=f"ASAN confirmed {ct}" + (f": {summary}" if summary else ""),
            poc_source=spec.source_code,
        )
    return VerificationResult(
        verdict="not-reproduced",
        crash_type="",
        detail="PoC compiled and ran clean under ASAN — no crash triggered",
        poc_source=spec.source_code,
    )


def apply_verification(finding: SourceFinding, result: VerificationResult) -> SourceFinding:
    """Stamp a verification result onto a copy of the finding.

    ``verified`` is True only for a real ASAN crash. A confirmed finding will
    then flow downstream with needs_verification off (see to_engage_finding).
    """
    return dataclasses.replace(
        finding,
        verified=result.verdict == "confirmed",
        verification_verdict=result.verdict,
        crash_type=result.crash_type,
    )


def verify_findings(
    findings: list[SourceFinding],
    *,
    poc_generator: PocGenerator,
    sandbox_runner: SandboxRunner,
    context_reader: Callable[[SourceFinding], str] | None = None,
    max_verifications: int = 20,
    only_verifiable: bool = True,
) -> list[SourceFinding]:
    """Run the bridge over a batch, returning findings with verdicts stamped.

    ``context_reader`` supplies the source context (usually the vulnerable
    file) for the PoC generator. ``max_verifications`` caps the expensive
    generate+compile+run loop; ``only_verifiable`` skips non-ASAN classes
    entirely (they stay untouched for F3) rather than tagging them
    ``unsupported``.
    """
    out: list[SourceFinding] = []
    budget = max_verifications
    for f in findings:
        if only_verifiable and not is_asan_verifiable(f):
            out.append(f)
            continue
        if budget <= 0:
            out.append(f)
            continue
        ctx = context_reader(f) if context_reader else ""
        result = verify_finding(
            f, poc_generator=poc_generator, sandbox_runner=sandbox_runner, code_context=ctx
        )
        budget -= 1
        out.append(apply_verification(f, result))
    return out


# ---------------------------------------------------------------------------
# Default impure implementations (the real model + the real sandbox)
# ---------------------------------------------------------------------------


def default_sandbox_runner(spec: PocSpec) -> dict:
    """Wrap ``_run_sandboxed_impl`` and parse its JSON into a dict."""
    from kryon.tools.code.sandbox import _run_sandboxed_impl

    raw = _run_sandboxed_impl(
        spec.source_code,
        language=spec.language,
        stdin_bytes=spec.stdin_bytes,
        extra_compile_flags=spec.extra_compile_flags,
    )
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"error": "sandbox returned non-JSON output"}


_POC_INSTRUCTIONS = (
    "You are an exploit developer. Below is a vulnerability a code auditor "
    "flagged, plus the surrounding source. Write a MINIMAL, SELF-CONTAINED C "
    "(or C++) program with a complete main() that triggers this exact memory "
    "bug so AddressSanitizer aborts. Inline only what you need — copy the "
    "vulnerable function and feed it the malicious input directly; do not "
    "depend on the project's build. If you genuinely cannot build a "
    "reproducer, output the single token NO_POC.\n\n"
    "Respond with ONLY a JSON object (no prose, no fences): "
    '{"language": "c"|"cpp", "source_code": "<full program>", '
    '"stdin_bytes": "<optional stdin>", "extra_compile_flags": "<optional>"}.'
)


class LocalPocGenerator:
    """Default ``PocGenerator`` — asks the local reasoning model (V4-Flash via
    llama.cpp, OpenAI-compatible) to write an ASAN reproducer. Reuses the
    source_review model/host env (``KRYON_SOURCE_REVIEW_MODEL`` /
    ``_BASE_URL`` / ``OPENAI_BASE_URL``)."""

    def __init__(self, model: str | None = None, host: str | None = None, *, timeout: int = 240, temperature: float = 0.2) -> None:
        self.model = model or os.environ.get("KRYON_SOURCE_REVIEW_MODEL", "kryon-local")
        self.host = host or os.environ.get(
            "KRYON_SOURCE_REVIEW_BASE_URL",
            os.environ.get("OPENAI_BASE_URL", "http://localhost:8080/v1"),
        )
        self.api_key = os.environ.get("OPENAI_API_KEY", "llama")
        self.timeout = timeout
        self.temperature = temperature

    def __call__(self, finding: SourceFinding, code_context: str) -> PocSpec | None:
        prompt = (
            f"{_POC_INSTRUCTIONS}\n\n"
            f"Finding: {finding.cwe} at {finding.file}:{finding.line} — {finding.title}\n"
            f"Sink: {finding.sink}\nEvidence: {finding.evidence}\n\n"
            f"Source context:\n```\n{code_context[:20000]}\n```\n"
        )
        raw = self._chat(prompt)
        return self._parse(raw)

    @staticmethod
    def _parse(raw: str) -> PocSpec | None:
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
        src = str(obj.get("source_code", "")).strip()
        if not src:
            return None
        lang = str(obj.get("language", "c")).strip().lower()
        lang = "cpp" if lang in ("cpp", "c++", "cxx") else "c"
        return PocSpec(
            source_code=src,
            language=lang,
            stdin_bytes=str(obj.get("stdin_bytes", "")),
            extra_compile_flags=str(obj.get("extra_compile_flags", "")),
        )

    def _chat(self, prompt: str) -> str:
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
