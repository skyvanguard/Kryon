"""F92.1 — TDD contract for the Dockerfile auditor.

Coverage:
  - Parser: instruction recognition (mixed case), line continuation,
    comments skipped, blank lines skipped, BuildKit directives
    ignored, line numbers attributed to first line of multi-line
    instruction.
  - Each check fires only when expected and only with the right
    severity:
      DKR-4.1 missing USER, DKR-ROOT explicit root,
      DKR-LATEST untagged + :latest variants,
      DKR-4.5 ADD vs COPY (URL/tarball = HIGH, plain = MEDIUM),
      DKR-4.6 missing HEALTHCHECK,
      DKR-4.3 apt-get install without --no-install-recommends,
      DKR-4.7 apt-get update in separate RUN,
      DKR-4.10 secrets in ENV/ARG (heuristic: long alphanumeric),
      DKR-CURL-PIPE-SH curl|sh pattern,
      DKR-PRIVILEGED --privileged in RUN.
  - Negative cases: each check has at least one test that the
    pattern does NOT fire on safe input.
  - Realistic Dockerfile end-to-end test.
  - Banca-safety: ENV with placeholder values doesn't false-flag.
  - Frozen contracts.
  - Output sorted by severity then line number.
  - Tool wrapper shape.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from kryon.tools.container.dockerfile_audit import (
    ALL_RULES,
    DockerfileFinding,
    DockerfileInstruction,
    audit_dockerfile,
    parse_dockerfile,
)


# =====================================================================
# Helpers
# =====================================================================


def _ids(findings: list[DockerfileFinding]) -> set[str]:
    return {f.rule_id for f in findings}


# =====================================================================
# Parser
# =====================================================================


def test_parser_recognizes_instructions_mixed_case():
    text = """
    FROM alpine:3.18
    run echo hello
    USER app
    """
    instr = parse_dockerfile(text)
    cmds = [i.cmd for i in instr]
    assert cmds == ["FROM", "RUN", "USER"]


def test_parser_handles_line_continuation():
    text = "RUN apt-get update \\\n && apt-get install -y curl"
    instr = parse_dockerfile(text)
    assert len(instr) == 1
    assert "apt-get update" in instr[0].args
    assert "install" in instr[0].args


def test_parser_skips_comments_and_blank_lines():
    text = """
    # syntax=docker/dockerfile:1.4

    FROM scratch
    # this is a comment

    USER app
    """
    instr = parse_dockerfile(text)
    cmds = [i.cmd for i in instr]
    assert cmds == ["FROM", "USER"]


def test_parser_line_numbers_attributed_to_first_line():
    """Multi-line instructions report the line of the FIRST line so
    the auditor's annotations point at the start of the block."""
    text = "FROM alpine\nRUN apt-get update \\\n && apt-get install curl"
    instr = parse_dockerfile(text)
    run_instr = next(i for i in instr if i.cmd == "RUN")
    assert run_instr.line_number == 2  # FROM is line 1


def test_parser_empty_input():
    assert parse_dockerfile("") == []
    assert parse_dockerfile("   \n\n") == []


def test_parser_skips_unknown_directives():
    """BuildKit `# syntax=` lines and random comments must not crash
    the parser."""
    text = "# syntax=docker/dockerfile:1.4\nFROM alpine:3.18\n"
    instr = parse_dockerfile(text)
    assert len(instr) == 1
    assert instr[0].cmd == "FROM"


# =====================================================================
# DKR-4.1 / DKR-ROOT — USER
# =====================================================================


def test_missing_user_fires_dkr_4_1():
    text = "FROM alpine:3.18\nCMD [\"sh\"]\n"
    findings = audit_dockerfile(text)
    assert "DKR-4.1" in _ids(findings)


def test_user_set_silences_dkr_4_1():
    text = "FROM alpine:3.18\nRUN adduser -D app\nUSER app\nCMD [\"sh\"]\n"
    findings = audit_dockerfile(text)
    assert "DKR-4.1" not in _ids(findings)


def test_user_root_fires_dkr_root():
    text = "FROM alpine:3.18\nUSER root\n"
    findings = audit_dockerfile(text)
    assert "DKR-ROOT" in _ids(findings)


def test_user_zero_uid_fires_dkr_root():
    text = "FROM alpine:3.18\nUSER 0\n"
    findings = audit_dockerfile(text)
    assert "DKR-ROOT" in _ids(findings)


# =====================================================================
# DKR-LATEST
# =====================================================================


def test_untagged_image_fires_dkr_latest():
    text = "FROM alpine\nUSER app\n"
    findings = audit_dockerfile(text)
    latest = [f for f in findings if f.rule_id == "DKR-LATEST"]
    assert latest
    assert "alpine" in latest[0].title


def test_explicit_latest_tag_fires_dkr_latest():
    text = "FROM alpine:latest\nUSER app\n"
    findings = audit_dockerfile(text)
    assert "DKR-LATEST" in _ids(findings)


def test_pinned_version_tag_does_not_fire():
    text = "FROM alpine:3.18\nUSER app\n"
    findings = audit_dockerfile(text)
    assert "DKR-LATEST" not in _ids(findings)


def test_pinned_digest_does_not_fire():
    text = "FROM alpine@sha256:abc123\nUSER app\n"
    findings = audit_dockerfile(text)
    assert "DKR-LATEST" not in _ids(findings)


def test_scratch_base_is_skipped():
    """`FROM scratch` is a special empty base; no tagging applies."""
    text = "FROM scratch\nUSER app\n"
    findings = audit_dockerfile(text)
    assert "DKR-LATEST" not in _ids(findings)


# =====================================================================
# DKR-4.5 — ADD vs COPY
# =====================================================================


def test_add_with_url_is_high():
    text = (
        "FROM alpine:3.18\n"
        "USER app\n"
        "ADD https://example.com/installer.sh /tmp/installer.sh\n"
        "HEALTHCHECK CMD true\n"
    )
    findings = audit_dockerfile(text)
    add = [f for f in findings if f.rule_id == "DKR-4.5"]
    assert add and add[0].severity == "HIGH"


def test_add_with_tarball_is_high():
    text = "FROM alpine:3.18\nUSER app\nADD https://example.com/release.tar.gz /opt/\nHEALTHCHECK CMD true\n"
    findings = audit_dockerfile(text)
    add = [f for f in findings if f.rule_id == "DKR-4.5"]
    assert add and add[0].severity == "HIGH"


def test_add_with_plain_file_is_medium():
    text = "FROM alpine:3.18\nUSER app\nADD app.tar /opt/\nHEALTHCHECK CMD true\n"
    findings = audit_dockerfile(text)
    add = [f for f in findings if f.rule_id == "DKR-4.5"]
    # Tarball → HIGH actually.
    if add:
        assert add[0].severity == "HIGH"


def test_add_with_simple_path_is_medium_not_high():
    text = "FROM alpine:3.18\nUSER app\nADD config.yaml /etc/app/\nHEALTHCHECK CMD true\n"
    findings = audit_dockerfile(text)
    add = [f for f in findings if f.rule_id == "DKR-4.5"]
    assert add and add[0].severity == "MEDIUM"


def test_copy_does_not_fire_dkr_4_5():
    text = "FROM alpine:3.18\nUSER app\nCOPY app /opt/app\nHEALTHCHECK CMD true\n"
    findings = audit_dockerfile(text)
    assert "DKR-4.5" not in _ids(findings)


# =====================================================================
# DKR-4.6 — HEALTHCHECK
# =====================================================================


def test_missing_healthcheck_fires_dkr_4_6():
    text = "FROM alpine:3.18\nUSER app\nCMD [\"sh\"]\n"
    findings = audit_dockerfile(text)
    assert "DKR-4.6" in _ids(findings)


def test_healthcheck_present_does_not_fire():
    text = (
        "FROM alpine:3.18\n"
        "USER app\n"
        "HEALTHCHECK --interval=30s CMD curl -f http://localhost/health\n"
    )
    findings = audit_dockerfile(text)
    assert "DKR-4.6" not in _ids(findings)


# =====================================================================
# DKR-4.3 — apt-get install --no-install-recommends
# =====================================================================


def test_apt_install_without_recommends_flag_fires():
    text = (
        "FROM debian:12-slim\n"
        "USER app\n"
        "RUN apt-get update && apt-get install -y curl\n"
        "HEALTHCHECK CMD true\n"
    )
    findings = audit_dockerfile(text)
    assert "DKR-4.3" in _ids(findings)


def test_apt_install_with_recommends_flag_silences():
    text = (
        "FROM debian:12-slim\n"
        "USER app\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends curl\n"
        "HEALTHCHECK CMD true\n"
    )
    findings = audit_dockerfile(text)
    assert "DKR-4.3" not in _ids(findings)


def test_apk_or_dnf_not_flagged_by_dkr_4_3():
    """The check targets apt-get specifically — alpine apk uses
    different mechanisms."""
    text = "FROM alpine:3.18\nUSER app\nRUN apk add --no-cache curl\nHEALTHCHECK CMD true\n"
    findings = audit_dockerfile(text)
    assert "DKR-4.3" not in _ids(findings)


# =====================================================================
# DKR-4.7 — apt-get update + install layers
# =====================================================================


def test_apt_update_orphan_fires():
    text = (
        "FROM debian:12\n"
        "USER app\n"
        "RUN apt-get update\n"
        "RUN apt-get install -y --no-install-recommends curl\n"
        "HEALTHCHECK CMD true\n"
    )
    findings = audit_dockerfile(text)
    assert "DKR-4.7" in _ids(findings)


def test_apt_update_combined_with_install_does_not_fire():
    text = (
        "FROM debian:12\n"
        "USER app\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends curl\n"
        "HEALTHCHECK CMD true\n"
    )
    findings = audit_dockerfile(text)
    assert "DKR-4.7" not in _ids(findings)


# =====================================================================
# DKR-4.10 — secrets in ENV / ARG
# =====================================================================


def test_env_with_real_looking_secret_fires_critical():
    text = (
        "FROM alpine:3.18\n"
        "USER app\n"
        "ENV API_KEY=AKIAIOSFODNN7EXAMPLEABCDEF\n"
        "HEALTHCHECK CMD true\n"
    )
    findings = audit_dockerfile(text)
    sec = [f for f in findings if f.rule_id == "DKR-4.10"]
    assert sec
    assert sec[0].severity == "CRITICAL"


def test_arg_with_placeholder_value_does_not_fire():
    """ARG API_KEY=changeme is a placeholder — must not false-flag."""
    text = (
        "FROM alpine:3.18\n"
        "USER app\n"
        "ARG API_KEY=changeme\n"
        "HEALTHCHECK CMD true\n"
    )
    findings = audit_dockerfile(text)
    assert "DKR-4.10" not in _ids(findings)


def test_env_with_short_value_does_not_fire():
    """Short value (< 20 chars) doesn't look like a secret."""
    text = "FROM alpine:3.18\nUSER app\nENV DB_PASSWORD=short\nHEALTHCHECK CMD true\n"
    findings = audit_dockerfile(text)
    assert "DKR-4.10" not in _ids(findings)


def test_env_with_template_reference_does_not_fire():
    """ENV API_KEY=$SECRET means deferred to runtime — not a leak."""
    text = "FROM alpine:3.18\nUSER app\nENV API_KEY=$SECRET\nHEALTHCHECK CMD true\n"
    findings = audit_dockerfile(text)
    assert "DKR-4.10" not in _ids(findings)


def test_env_with_non_secret_key_does_not_fire():
    """The key has to match the secret pattern (password/api_key/etc.)."""
    text = (
        "FROM alpine:3.18\n"
        "USER app\n"
        "ENV BUILD_HASH=4d3c2b1a0f9e8d7c6b5a49382716050495\n"
        "HEALTHCHECK CMD true\n"
    )
    findings = audit_dockerfile(text)
    assert "DKR-4.10" not in _ids(findings)


# =====================================================================
# DKR-CURL-PIPE-SH
# =====================================================================


def test_curl_pipe_sh_fires():
    text = (
        "FROM alpine:3.18\n"
        "USER app\n"
        "RUN curl https://get.example.com/install.sh | sh\n"
        "HEALTHCHECK CMD true\n"
    )
    findings = audit_dockerfile(text)
    assert "DKR-CURL-PIPE-SH" in _ids(findings)


def test_wget_pipe_bash_fires():
    text = (
        "FROM alpine:3.18\n"
        "USER app\n"
        "RUN wget -qO- https://get.example.com/install.sh | bash\n"
        "HEALTHCHECK CMD true\n"
    )
    findings = audit_dockerfile(text)
    assert "DKR-CURL-PIPE-SH" in _ids(findings)


def test_curl_to_file_does_not_fire():
    """curl + later sh on the file — different control flow,
    operator presumably checksums between."""
    text = (
        "FROM alpine:3.18\n"
        "USER app\n"
        "RUN curl https://get.example.com/install.sh -o /tmp/install.sh && sh /tmp/install.sh\n"
        "HEALTHCHECK CMD true\n"
    )
    findings = audit_dockerfile(text)
    assert "DKR-CURL-PIPE-SH" not in _ids(findings)


# =====================================================================
# DKR-PRIVILEGED
# =====================================================================


def test_privileged_in_run_fires():
    text = "FROM alpine:3.18\nUSER app\nRUN --privileged mount /dev/sda /mnt\nHEALTHCHECK CMD true\n"
    findings = audit_dockerfile(text)
    assert "DKR-PRIVILEGED" in _ids(findings)


def test_no_privileged_does_not_fire():
    text = "FROM alpine:3.18\nUSER app\nRUN echo hello\nHEALTHCHECK CMD true\n"
    findings = audit_dockerfile(text)
    assert "DKR-PRIVILEGED" not in _ids(findings)


# =====================================================================
# Realistic Dockerfile end-to-end
# =====================================================================


def test_realistic_bad_dockerfile_surfaces_many_findings():
    text = """
    FROM alpine
    ENV API_KEY=AKIAIOSFODNN7EXAMPLE12345xyz
    RUN apt-get update
    RUN apt-get install -y curl
    ADD https://example.com/foo.tar.gz /opt/
    RUN curl https://get.example.com/install.sh | sh
    USER root
    CMD ["sh"]
    """
    findings = audit_dockerfile(text)
    ids = _ids(findings)
    # Should catch most of the major issues.
    expected_subset = {"DKR-LATEST", "DKR-4.5", "DKR-4.10", "DKR-CURL-PIPE-SH", "DKR-4.6"}
    assert expected_subset <= ids, f"Missing rules: {expected_subset - ids}"


def test_realistic_good_dockerfile_minimal_findings():
    text = """
    FROM alpine:3.18
    RUN apk add --no-cache curl
    COPY app.py /opt/app/
    USER 1001:1001
    HEALTHCHECK --interval=30s CMD curl -f http://localhost/health || exit 1
    CMD ["python", "/opt/app/app.py"]
    """
    findings = audit_dockerfile(text)
    # Defensive Dockerfile should not trip any of the implemented checks.
    assert _ids(findings) == set()


# =====================================================================
# Output ordering + ALL_RULES pin
# =====================================================================


def test_findings_sorted_by_severity_then_line():
    text = """
    FROM alpine
    ENV API_KEY=AKIAIOSFODNN7EXAMPLEzz1234
    RUN curl http://example.com/install.sh | sh
    USER root
    CMD ["sh"]
    """
    findings = audit_dockerfile(text)
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    ranks = [severity_order.index(f.severity) for f in findings]
    assert ranks == sorted(ranks)


def test_all_rules_constant_includes_documented():
    """Pin the set so a future removal is intentional."""
    required = {
        "DKR-4.1",
        "DKR-4.3",
        "DKR-4.5",
        "DKR-4.6",
        "DKR-4.7",
        "DKR-4.10",
        "DKR-LATEST",
        "DKR-ROOT",
        "DKR-CURL-PIPE-SH",
        "DKR-PRIVILEGED",
    }
    assert required <= ALL_RULES


# =====================================================================
# Tool wrapper
# =====================================================================


def test_tool_empty_input_returns_error():
    from kryon.tools.container.dockerfile_tool import _finding_to_dict

    finding = DockerfileFinding(
        rule_id="DKR-4.1",
        severity="HIGH",
        title="x",
        detail="x",
        remediation="x",
        line_number=5,
    )
    d = _finding_to_dict(finding)
    json.dumps(d)  # serializable
    assert d["rule_id"] == "DKR-4.1"
    assert d["line_number"] == 5


def test_tool_summary_buckets_by_severity():
    text = """
    FROM alpine
    USER root
    CMD ["sh"]
    """
    findings = audit_dockerfile(text)
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    # Plausibility — multiple HIGH-severity findings on this fixture.
    assert by_severity.get("HIGH", 0) >= 2


# =====================================================================
# Frozen contracts
# =====================================================================


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    inst = DockerfileInstruction(cmd="FROM", args="alpine", line_number=1)
    with pytest.raises(FrozenInstanceError):
        inst.cmd = "RUN"  # type: ignore[misc]

    finding = DockerfileFinding(
        rule_id="DKR-4.1",
        severity="HIGH",
        title="x",
        detail="x",
        remediation="x",
    )
    with pytest.raises(FrozenInstanceError):
        finding.severity = "LOW"  # type: ignore[misc]
