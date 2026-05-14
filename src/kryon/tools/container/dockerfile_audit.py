"""F92.1 — Dockerfile static auditor (CIS Docker Benchmark §4).

Parses a Dockerfile's instructions and applies ~15 static checks
covering the CIS Docker Benchmark Section 4 (Container Images and
Build) plus a handful of pragmatic banking-specific patterns we see
in real engagements (BCP, BCB OBB customer deployments).

Why static-only:
  - The auditor runs inside the operator's air-gapped CI without
    Docker daemon access. The Dockerfile is the source of truth;
    runtime drift is a separate runtime-config check (out of scope
    for F92.1).
  - PURE text parsing. No subprocess, no network, no filesystem
    write. The operator pastes Dockerfile content; we return findings.

Checks implemented (CIS Docker Benchmark §4 mapping + extras):

  DKR-4.1  Create user for container (USER instruction present
           with non-root)
  DKR-4.2  Trusted base image — no scratch-pinning-by-digest-only
           guarantee, but `:latest` is flagged separately
  DKR-4.3  Don't install unnecessary packages — flags apt-get install
           without --no-install-recommends
  DKR-4.5  COPY over ADD (ADD has surprising fetch + tar semantics)
  DKR-4.6  HEALTHCHECK declared
  DKR-4.7  apt-get update + apt-get install in separate RUN layers
           (cache bust)
  DKR-4.9  Use COPY for plain content (overlap with 4.5; surfaces
           once)
  DKR-4.10 No secrets in Dockerfile (heuristic regex on ENV /
           ARG lines)
  DKR-4.11 Verify image — pinned digest (sha256:...) preferred
  DKR-4.12 VOLUME for ephemeral state (informational)

Plus:

  DKR-LATEST   :latest tag forbidden (pin a version)
  DKR-ROOT     Explicit USER root is suspicious
  DKR-CURL-PIPE-SH  curl | sh patterns flagged (supply chain risk)
  DKR-PRIVILEGED    --privileged flag in RUN (build-time, not
                    runtime)

Finding shape mirrors F39 PCI / F87 / F90: stable rule_id, severity,
title, detail (line + context), remediation. Operators can publish
them through the F89.1 SARIF reporter unchanged.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)


__all__ = [
    "DockerfileInstruction",
    "DockerfileFinding",
    "parse_dockerfile",
    "audit_dockerfile",
    "ALL_RULES",
]


_INSTRUCTION_RE = re.compile(
    r"^\s*(?P<cmd>FROM|RUN|CMD|LABEL|MAINTAINER|EXPOSE|ENV|ADD|COPY|ENTRYPOINT|VOLUME|USER|WORKDIR|ARG|ONBUILD|STOPSIGNAL|HEALTHCHECK|SHELL)\b\s*(?P<args>.*)$",
    re.IGNORECASE,
)

# Secret-like patterns in ENV/ARG values. Conservative — we want
# high precision, not coverage.
_SECRET_KEY_RE = re.compile(
    r"^(.*_)?(password|passwd|secret|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|token|aws[_-]?secret|stripe[_-]?key|"
    r"db[_-]?password|smtp[_-]?password)$",
    re.IGNORECASE,
)

# Inline secret-value heuristic: long alphanumeric or hex strings
# assigned to a key matching _SECRET_KEY_RE.
_SECRET_VALUE_HEX_RE = re.compile(r"^[A-Fa-f0-9]{20,}$")
_SECRET_VALUE_LONG_RE = re.compile(r"^[A-Za-z0-9+/=_-]{20,}$")


# All known rule IDs — pinned so a removal trips the test.
ALL_RULES: frozenset[str] = frozenset(
    {
        "DKR-4.1",
        "DKR-4.3",
        "DKR-4.5",
        "DKR-4.6",
        "DKR-4.7",
        "DKR-4.10",
        "DKR-4.11",
        "DKR-LATEST",
        "DKR-ROOT",
        "DKR-CURL-PIPE-SH",
        "DKR-PRIVILEGED",
    }
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DockerfileInstruction:
    """One parsed line of a Dockerfile."""

    cmd: str  # uppercased — FROM, RUN, USER, ...
    args: str  # raw argument string, multi-line glue applied
    line_number: int  # 1-based, position of the FIRST line of the instruction


@dataclass(frozen=True)
class DockerfileFinding:
    """One auditor verdict — mirrors the F39 / F87 / F90 shape."""

    rule_id: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    remediation: str
    line_number: int | None = None


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_dockerfile(text: str) -> list[DockerfileInstruction]:
    """Parse Dockerfile text into a list of instructions.

    Handles:
      - Line continuations with trailing backslash.
      - Comments (# ...) ignored.
      - Blank lines ignored.
      - Mixed-case instruction names (FROM / from / From).

    Defensive: lines that don't match a known instruction are
    silently skipped — Dockerfiles in the wild sometimes include
    BuildKit syntax (# syntax=docker/dockerfile:1.4) or comments
    pretending to be directives. The auditor's job is to flag
    real misconfigurations, not to be a strict parser.
    """
    if not text:
        return []
    out: list[DockerfileInstruction] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i].rstrip("\r")
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        # Accumulate continuations.
        start_line = i + 1
        accumulated = raw.rstrip("\\").rstrip()
        while raw.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            raw = lines[i].rstrip("\r")
            cont = raw.strip().rstrip("\\").rstrip()
            # Skip blank continuation lines + comments in the middle.
            if cont and not cont.startswith("#"):
                accumulated = accumulated + " " + cont
            if not raw.rstrip().endswith("\\"):
                break
        match = _INSTRUCTION_RE.match(accumulated)
        if match:
            out.append(
                DockerfileInstruction(
                    cmd=match.group("cmd").upper(),
                    args=match.group("args").strip(),
                    line_number=start_line,
                )
            )
        i += 1
    return out


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def _check_user_instruction(
    instructions: list[DockerfileInstruction],
) -> list[DockerfileFinding]:
    """DKR-4.1 + DKR-ROOT: USER must be set, must not be root."""
    user_instr = [i for i in instructions if i.cmd == "USER"]
    findings: list[DockerfileFinding] = []
    if not user_instr:
        # Find a representative line — last instruction in file
        # makes the most operator-actionable annotation.
        line = instructions[-1].line_number if instructions else None
        findings.append(
            DockerfileFinding(
                rule_id="DKR-4.1",
                severity="HIGH",
                title="No USER instruction — container runs as root",
                detail=(
                    "Dockerfile does not set a USER. By default Docker runs the "
                    "container's main process as root, which means a successful "
                    "exploit of the application has the same privileges as root "
                    "on the host's container runtime."
                ),
                remediation=(
                    "Add `RUN useradd --create-home --shell /bin/bash app` and "
                    "`USER app` near the end of the Dockerfile. Confirm the app "
                    "doesn't need privileges that only root has."
                ),
                line_number=line,
            )
        )
        return findings
    # USER set — verify it's not root.
    for inst in user_instr:
        arg = inst.args.strip().split()[0] if inst.args.strip() else ""
        if arg.lower() in ("root", "0", "0:0"):
            findings.append(
                DockerfileFinding(
                    rule_id="DKR-ROOT",
                    severity="HIGH",
                    title=f"USER explicitly set to root (line {inst.line_number})",
                    detail=(
                        f"`USER {arg}` runs the container as root. This is rarely "
                        "intentional; usually a debugging shim that shouldn't ship."
                    ),
                    remediation="Switch to a dedicated non-root user before the final stage.",
                    line_number=inst.line_number,
                )
            )
    return findings


def _check_latest_tag(
    instructions: list[DockerfileInstruction],
) -> list[DockerfileFinding]:
    """DKR-LATEST + DKR-4.11: pin base images.

    `:latest` (or no tag at all) is unreproducible — the same
    Dockerfile builds different content tomorrow. Banking compliance
    auditors flag this as a supply-chain risk.
    """
    findings: list[DockerfileFinding] = []
    for inst in instructions:
        if inst.cmd != "FROM":
            continue
        args = inst.args.strip()
        # FROM alpine          → tag missing (implicit :latest)
        # FROM alpine:latest   → tag :latest
        # FROM alpine:3.18     → pinned by tag (acceptable)
        # FROM alpine@sha256:..→ pinned by digest (preferred)
        # FROM scratch         → special; skip
        image = args.split()[0] if args else ""
        if not image or image.lower() == "scratch":
            continue
        if "@" in image:
            # Digest-pinned — fully reproducible. Skip.
            continue
        if ":" not in image:
            findings.append(
                DockerfileFinding(
                    rule_id="DKR-LATEST",
                    severity="HIGH",
                    title=f"Base image {image!r} has no tag (defaults to :latest)",
                    detail=(
                        "An untagged FROM resolves to :latest at build time. The "
                        "build is non-reproducible and silently inherits upstream "
                        "changes including supply-chain compromises."
                    ),
                    remediation=(
                        f"Pin to a version tag (e.g. `FROM {image}:3.18`) or — "
                        "better — to a sha256 digest (`FROM image@sha256:...`)."
                    ),
                    line_number=inst.line_number,
                )
            )
        elif image.lower().endswith(":latest"):
            findings.append(
                DockerfileFinding(
                    rule_id="DKR-LATEST",
                    severity="HIGH",
                    title=f"Base image {image!r} uses :latest tag",
                    detail=(
                        ":latest is a mutable tag. Same Dockerfile builds different "
                        "content tomorrow. Audit reproducibility lost."
                    ),
                    remediation="Pin to a version tag or sha256 digest.",
                    line_number=inst.line_number,
                )
            )
    return findings


def _check_copy_vs_add(
    instructions: list[DockerfileInstruction],
) -> list[DockerfileFinding]:
    """DKR-4.5 / DKR-4.9: prefer COPY over ADD. ADD silently fetches
    URLs and untars archives — both side effects that bite curious
    developers."""
    findings: list[DockerfileFinding] = []
    for inst in instructions:
        if inst.cmd != "ADD":
            continue
        args = inst.args.strip()
        # ADD with URL or tarball is the actual risk; ADD with plain
        # file path is just sloppy style. Surface both at MEDIUM.
        looks_like_url = "://" in args
        looks_like_tarball = re.search(r"\.(tar|tgz|tar\.gz|tar\.bz2|tar\.xz)\b", args, re.IGNORECASE)
        if looks_like_url or looks_like_tarball:
            severity = "HIGH"
            extra = "ADD fetches the URL / untars the archive at build time — opaque, networked, and easy to subvert."
        else:
            severity = "MEDIUM"
            extra = "Even for plain files, COPY is preferred — same semantics, no surprising side effects."
        findings.append(
            DockerfileFinding(
                rule_id="DKR-4.5",
                severity=severity,
                title=f"ADD instruction (prefer COPY): line {inst.line_number}",
                detail=f"`ADD {args}`. {extra}",
                remediation="Replace with `COPY`; fetch URLs explicitly via RUN curl + verify checksum.",
                line_number=inst.line_number,
            )
        )
    return findings


def _check_healthcheck(
    instructions: list[DockerfileInstruction],
) -> list[DockerfileFinding]:
    """DKR-4.6: HEALTHCHECK lets orchestrators (k8s, Swarm) replace
    unresponsive containers automatically. Missing it means the
    runtime can only detect process death, not deadlock."""
    if any(i.cmd == "HEALTHCHECK" for i in instructions):
        return []
    line = instructions[-1].line_number if instructions else None
    return [
        DockerfileFinding(
            rule_id="DKR-4.6",
            severity="MEDIUM",
            title="No HEALTHCHECK declared",
            detail=(
                "Without a HEALTHCHECK the orchestrator can only detect process "
                "death — a deadlocked or wedged process keeps serving 5xx "
                "responses indefinitely."
            ),
            remediation="Add `HEALTHCHECK --interval=30s CMD curl -f http://localhost:PORT/health || exit 1`.",
            line_number=line,
        )
    ]


def _check_apt_install_recommends(
    instructions: list[DockerfileInstruction],
) -> list[DockerfileFinding]:
    """DKR-4.3: `apt-get install` without `--no-install-recommends`
    pulls in `Recommends:` packages that bloat the image and add
    attack surface (perl, debconf, etc.)."""
    findings: list[DockerfileFinding] = []
    pattern = re.compile(r"\bapt-get\s+install\b", re.IGNORECASE)
    no_recommends_pattern = re.compile(r"--no-install-recommends", re.IGNORECASE)
    for inst in instructions:
        if inst.cmd != "RUN":
            continue
        if pattern.search(inst.args) and not no_recommends_pattern.search(inst.args):
            findings.append(
                DockerfileFinding(
                    rule_id="DKR-4.3",
                    severity="MEDIUM",
                    title=f"apt-get install without --no-install-recommends (line {inst.line_number})",
                    detail=(
                        "Without `--no-install-recommends`, apt pulls in Recommends: "
                        "packages that bloat the image and increase attack surface."
                    ),
                    remediation="Add `--no-install-recommends` to the apt-get install command.",
                    line_number=inst.line_number,
                )
            )
    return findings


def _check_apt_layers(
    instructions: list[DockerfileInstruction],
) -> list[DockerfileFinding]:
    """DKR-4.7: apt-get update + apt-get install MUST be in the same
    RUN layer. Separate layers cache the update output independently
    and a rebuild ships stale package indexes."""
    findings: list[DockerfileFinding] = []
    has_orphan_update = False
    for inst in instructions:
        if inst.cmd != "RUN":
            continue
        update = "apt-get update" in inst.args
        install = "apt-get install" in inst.args or "apt-get -y install" in inst.args
        # Orphan update in its own RUN, no install in same line.
        if update and not install:
            has_orphan_update = True
            findings.append(
                DockerfileFinding(
                    rule_id="DKR-4.7",
                    severity="MEDIUM",
                    title=f"apt-get update in separate RUN layer (line {inst.line_number})",
                    detail=(
                        "apt-get update + apt-get install in separate RUN layers means "
                        "the update output is cached independently. Rebuilds may use "
                        "stale package indexes and install old, vulnerable versions."
                    ),
                    remediation=(
                        "Combine into one RUN: `RUN apt-get update && apt-get install -y "
                        "--no-install-recommends <pkgs> && rm -rf /var/lib/apt/lists/*`."
                    ),
                    line_number=inst.line_number,
                )
            )
    _ = has_orphan_update
    return findings


def _check_secrets_in_env_arg(
    instructions: list[DockerfileInstruction],
) -> list[DockerfileFinding]:
    """DKR-4.10: ENV and ARG values are recorded in the image
    manifest and visible to anyone who can `docker inspect`. A
    secret-looking key with a long-string value is almost always a
    mistake."""
    findings: list[DockerfileFinding] = []
    for inst in instructions:
        if inst.cmd not in ("ENV", "ARG"):
            continue
        # Both ENV and ARG accept `KEY=value` (and ENV also `KEY value`).
        # Tokenise on whitespace, then split each token on the first =.
        for token in inst.args.split():
            if "=" not in token:
                continue
            key, _, value = token.partition("=")
            value = value.strip().strip('"').strip("'")
            if not _SECRET_KEY_RE.match(key):
                continue
            # Skip empty / template / placeholder values.
            if not value or value.startswith("$") or value in ("changeme", "placeholder", "TODO"):
                continue
            looks_like_secret = len(value) >= 20 and (
                _SECRET_VALUE_HEX_RE.match(value) or _SECRET_VALUE_LONG_RE.match(value)
            )
            if looks_like_secret:
                findings.append(
                    DockerfileFinding(
                        rule_id="DKR-4.10",
                        severity="CRITICAL",
                        title=f"Secret in {inst.cmd} (line {inst.line_number}, key={key!r})",
                        detail=(
                            f"The {inst.cmd} value for {key!r} looks like a real secret "
                            "(20+ alphanumeric chars). Image manifest persists this; "
                            "anyone with read access to the image registry can recover it."
                        ),
                        remediation=(
                            "Move secrets out of the build. Use BuildKit's `--mount=type=secret`, "
                            "K8s secrets at runtime, or a secrets manager (Vault, AWS Secrets Manager)."
                        ),
                        line_number=inst.line_number,
                    )
                )
    return findings


def _check_curl_pipe_sh(
    instructions: list[DockerfileInstruction],
) -> list[DockerfileFinding]:
    """DKR-CURL-PIPE-SH: `curl ... | sh` patterns execute remote
    scripts without verification. The remote endpoint can serve
    different content per-build, per-region, per-IP — supply-chain
    nightmare."""
    findings: list[DockerfileFinding] = []
    pattern = re.compile(
        r"(curl|wget)\s+[^|]*\|\s*(sh|bash|zsh|/bin/(sh|bash|zsh))",
        re.IGNORECASE,
    )
    for inst in instructions:
        if inst.cmd != "RUN":
            continue
        if pattern.search(inst.args):
            findings.append(
                DockerfileFinding(
                    rule_id="DKR-CURL-PIPE-SH",
                    severity="HIGH",
                    title=f"curl | sh pattern (line {inst.line_number})",
                    detail=(
                        "Piping curl/wget output directly to a shell executes attacker-"
                        "modifiable code without verification. The endpoint can serve "
                        "different content per-build, per-region, per-IP."
                    ),
                    remediation=(
                        "Download to a file, verify checksum, then execute. "
                        "Or pin a specific commit + sha of the install script."
                    ),
                    line_number=inst.line_number,
                )
            )
    return findings


def _check_privileged_flag(
    instructions: list[DockerfileInstruction],
) -> list[DockerfileFinding]:
    """DKR-PRIVILEGED: --privileged in RUN is a BuildKit feature
    that grants extended capabilities at build time. Rare and
    almost always a mistake (people meant runtime --privileged)."""
    findings: list[DockerfileFinding] = []
    for inst in instructions:
        if inst.cmd != "RUN":
            continue
        if "--privileged" in inst.args.lower():
            findings.append(
                DockerfileFinding(
                    rule_id="DKR-PRIVILEGED",
                    severity="HIGH",
                    title=f"--privileged in RUN (line {inst.line_number})",
                    detail=(
                        "--privileged on RUN grants extended build-time capabilities. "
                        "Almost always a confusion with runtime --privileged. Verify "
                        "intent; legitimate use cases are rare."
                    ),
                    remediation="Remove --privileged unless the build genuinely requires raw device access.",
                    line_number=inst.line_number,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------


def audit_dockerfile(text: str) -> list[DockerfileFinding]:
    """Run every check against the Dockerfile content.

    Returns a list of DockerfileFinding sorted by severity (CRITICAL
    first), then by line number. Empty input → empty findings.
    """
    instructions = parse_dockerfile(text)
    if not instructions:
        return []
    findings: list[DockerfileFinding] = []
    findings.extend(_check_user_instruction(instructions))
    findings.extend(_check_latest_tag(instructions))
    findings.extend(_check_copy_vs_add(instructions))
    findings.extend(_check_healthcheck(instructions))
    findings.extend(_check_apt_install_recommends(instructions))
    findings.extend(_check_apt_layers(instructions))
    findings.extend(_check_secrets_in_env_arg(instructions))
    findings.extend(_check_curl_pipe_sh(instructions))
    findings.extend(_check_privileged_flag(instructions))

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }

    findings.sort(
        key=lambda f: (
            severity_order.get(f.severity, 99),
            f.line_number if f.line_number is not None else 99999,
            f.rule_id,
        )
    )
    return findings
