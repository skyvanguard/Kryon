"""
run_sandboxed — the ground-truth oracle for the 0-day hunter.

Compiles a short C/C++ program with `-fsanitize=address,undefined`, runs it
with the provided input, and parses the AddressSanitizer / UBSan output
into a structured crash report.

Why this matters
----------------
Per the Mythos research (red.anthropic.com/2026/zero-days/), using
sanitizers as crash oracles was the single most important architectural
choice: "perfectly separate real bugs from hallucinations". Every reported
vulnerability was a genuine true positive.

This tool is the first of two run_sandboxed variants:
- (here) inline C/C++ compile+run — for quick hypothesis checks
- (later) repo-scoped build — compile the whole project with ASAN and
  run its existing test harness / libFuzzer targets

Output
------
JSON with keys:
  crashed: bool
  crash_type: str         # e.g. "heap-buffer-overflow", "stack-use-after-return"
  address:   str          # offending address, if any
  summary:   str          # one-line human summary from ASAN
  stack_top: [str]        # 0-10 frames from ASAN backtrace
  exit_code: int
  stdout:    str          # program stdout (capped)
  stderr:    str          # compiler + sanitizer stderr (capped)
  raw:       str          # full sanitizer report snippet (capped)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from kryon.sdk.agents import function_tool

# Output size caps — ASAN reports can be huge.
_MAX_RAW = 8000
_MAX_STDOUT = 2000
_MAX_STDERR = 4000

_ASAN_SUMMARY_RE = re.compile(
    r"==\d+==ERROR:\s*AddressSanitizer:\s*(?P<kind>[\w\-]+)"
    r"(?:\s+on\s+address\s+(?P<addr>0x[0-9a-fA-F]+))?",
)
_UBSAN_SUMMARY_RE = re.compile(
    r"runtime error:\s*(?P<kind>[^\n]+)",
)
_FRAME_RE = re.compile(r"^\s*#\d+\s+0x[0-9a-f]+\s+in\s+(.+)$", re.M)
_SUMMARY_LINE_RE = re.compile(r"^SUMMARY:\s*(.+)$", re.M)


def _parse_sanitizer(stderr_text: str) -> dict:
    """Extract crash type / backtrace from combined ASAN+UBSan output."""
    out = {"crashed": False, "crash_type": "", "address": "", "summary": "", "stack_top": []}

    m = _ASAN_SUMMARY_RE.search(stderr_text)
    if m:
        out["crashed"] = True
        out["crash_type"] = m.group("kind")
        out["address"] = m.group("addr") or ""
    else:
        m = _UBSAN_SUMMARY_RE.search(stderr_text)
        if m:
            out["crashed"] = True
            out["crash_type"] = "undefined-behavior"
            out["summary"] = m.group("kind").strip()

    sm = _SUMMARY_LINE_RE.search(stderr_text)
    if sm and not out["summary"]:
        out["summary"] = sm.group(1).strip()

    frames = _FRAME_RE.findall(stderr_text)
    out["stack_top"] = frames[:10]
    return out


def _detect_compiler(language: str) -> tuple[str, list[str]]:
    """Return (compiler_bin, extra_default_flags) for the given language."""
    language = (language or "").lower()
    for bin_name in ("clang", "gcc"):
        path = shutil.which(bin_name)
        if path and language in ("c", ""):
            return path, ["-x", "c"]
    for bin_name in ("clang++", "g++"):
        path = shutil.which(bin_name)
        if path and language in ("cpp", "c++"):
            return path, ["-x", "c++"]
    return "", []


def _run_sandboxed_impl(
    source_code: str,
    language: str = "c",
    stdin_bytes: str = "",
    extra_compile_flags: str = "",
    run_timeout: int = 10,
    compile_timeout: int = 30,
) -> str:
    """Implementation separated from the function_tool wrapper for tests."""
    if not source_code.strip():
        return json.dumps({"error": "source_code is empty"})

    if len(source_code) > 200_000:
        return json.dumps({"error": "source_code too large (>200KB)"})

    compiler, lang_flags = _detect_compiler(language)
    if not compiler:
        return json.dumps(
            {
                "error": f"no compiler found for language={language!r}",
                "hint": "install clang or gcc in the container",
            }
        )

    # Build flags — ASAN + UBSan, with sensible error reporting knobs
    # halt_on_error=1 ensures the first violation aborts; symbolize=1 gives
    # readable stack frames (requires addr2line, present in the container).
    asan_options = "halt_on_error=1:symbolize=1:abort_on_error=0:detect_leaks=0"
    ubsan_options = "halt_on_error=1:print_stacktrace=1"
    base_flags = [
        "-O0",
        "-g",
        "-fno-omit-frame-pointer",
        "-fsanitize=address,undefined",
    ]
    extra = extra_compile_flags.split() if extra_compile_flags else []

    workdir = Path(tempfile.mkdtemp(prefix="kryon_sandbox_"))
    try:
        src_name = "prog.c" if language in ("c", "") else "prog.cpp"
        src_path = workdir / src_name
        bin_path = workdir / "prog"
        src_path.write_text(source_code)

        # Compile
        compile_cmd = (
            [compiler]
            + lang_flags
            + base_flags
            + extra
            + [
                str(src_path),
                "-o",
                str(bin_path),
            ]
        )
        cp = subprocess.run(
            compile_cmd,
            capture_output=True,
            text=True,
            timeout=compile_timeout,
            check=False,
        )
        if cp.returncode != 0:
            return json.dumps(
                {
                    "compiled": False,
                    "compile_cmd": " ".join(compile_cmd),
                    "compile_stderr": cp.stderr[:_MAX_STDERR],
                },
                indent=2,
            )

        # Run
        env = {**os.environ, "ASAN_OPTIONS": asan_options, "UBSAN_OPTIONS": ubsan_options}
        try:
            rp = subprocess.run(
                [str(bin_path)],
                input=stdin_bytes if stdin_bytes else None,
                capture_output=True,
                text=True,
                timeout=run_timeout,
                check=False,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return json.dumps(
                {
                    "compiled": True,
                    "timeout": True,
                    "run_timeout": run_timeout,
                },
                indent=2,
            )

        parsed = _parse_sanitizer(rp.stderr)
        parsed.update(
            {
                "compiled": True,
                "exit_code": rp.returncode,
                "stdout": rp.stdout[:_MAX_STDOUT],
                "stderr": rp.stderr[:_MAX_STDERR],
                "raw": rp.stderr[:_MAX_RAW] if parsed["crashed"] else "",
            }
        )
        return json.dumps(parsed, indent=2)

    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@function_tool(strict_mode=False)
def run_sandboxed(
    source_code: str,
    language: str = "c",
    stdin_bytes: str = "",
    extra_compile_flags: str = "",
    run_timeout: int = 10,
) -> str:
    """Compile and run a short C/C++ program with ASAN+UBSan; parse crashes.

    THIS IS THE GROUND-TRUTH ORACLE for vulnerability hypotheses. If the
    program crashes under sanitizers, the bug is real — not hallucinated.

    Args:
        source_code: Full C or C++ source text (a complete main()).
        language: "c" or "cpp".
        stdin_bytes: Optional input piped to the program's stdin.
        extra_compile_flags: Extra flags (e.g. "-std=c99 -lm").
        run_timeout: Seconds before the program is killed.

    Returns JSON with:
      compiled, crashed, crash_type, address, summary, stack_top,
      exit_code, stdout, stderr, raw.
    """
    return _run_sandboxed_impl(source_code, language, stdin_bytes, extra_compile_flags, run_timeout)
