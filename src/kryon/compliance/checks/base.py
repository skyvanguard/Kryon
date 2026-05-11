"""Base types for deterministic PCI-DSS v4 compliance checks.

`Check` is a Protocol — any callable with the right signature qualifies.
`CheckResult` is a frozen dataclass so downstream code (PDF generator,
LLM narrator) cannot mutate it.

Reproducibility contract: `CheckResult` does NOT carry wall-clock
timestamps. `duration_ms` is the only timing field; the runner excludes
it from the reproducibility-hashed artifact.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

Verdict = Literal["PASS", "FAIL", "N/A", "ERROR"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass(frozen=True)
class CheckContext:
    """Immutable input handed to each check.

    `host` is "localhost" for on-box audits. Remote audits populate the
    SSH connection fields; checks are responsible for wrapping their
    commands accordingly (helper in `runner.run_cmd`).
    """

    host: str = "localhost"
    ssh_user: str = ""
    ssh_key_path: str = ""
    ssh_port: int = 22
    # Opt-in slow path: extra evidence collection for forensic-grade reports.
    deep_evidence: bool = False

    # Transport selector. "ssh" (default) keeps SSH behaviour; "winrm"
    # routes through the WinRM runner for Windows hosts; "local" skips
    # any remote transport (host must resolve to the local box).
    transport: str = "ssh"

    # WinRM fields — only read when transport == "winrm".
    winrm_user: str = ""
    winrm_password: str = ""
    winrm_port: int = 5985
    winrm_scheme: str = "http"
    winrm_auth: str = "ntlm"


@dataclass(frozen=True)
class CheckResult:
    """Single-check outcome. Frozen — consumers never mutate."""

    control_id: str
    control_title: str
    section: str
    verdict: Verdict
    evidence_command: str
    evidence_stdout: str
    evidence_stderr: str
    evidence_parsed: dict
    remediation_static: str
    severity: Severity
    duration_ms: int
    host: str
    run_id: str

    def to_json_reproducible(self) -> dict:
        """Serialization used for reproducibility hashing.

        Excludes `duration_ms` (wall-clock variant) and `run_id`
        (different per invocation). Everything else must be byte-stable
        across runs on the same target.
        """
        return {
            "control_id": self.control_id,
            "control_title": self.control_title,
            "section": self.section,
            "verdict": self.verdict,
            "evidence_command": self.evidence_command,
            "evidence_stdout": self.evidence_stdout,
            "evidence_stderr": self.evidence_stderr,
            "evidence_parsed": self.evidence_parsed,
            "remediation_static": self.remediation_static,
            "severity": self.severity,
            "host": self.host,
        }


class Check(Protocol):
    """Each check module exports a `CHECK` object satisfying this
    protocol. Runner calls `CHECK.run(ctx)` and collects the result."""

    control_id: str
    control_title: str
    section: str
    severity: Severity
    remediation_static: str

    def run(self, ctx: CheckContext) -> CheckResult: ...
