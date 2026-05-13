"""F89.3 — Structural tests for the GitLab CI template.

The template is YAML, not Python — so we can't unit-test logic.
Instead we pin the contract:

  - The YAML parses cleanly.
  - The hidden job `.kryon-audit` is present and well-shaped.
  - Documented variables are declared with their advertised
    defaults.
  - The artifact block publishes SARIF as `reports:sast` (GitLab
    16.8+ ingestion contract).
  - Severity-gate semantics align with F89.2 (same fail values
    accepted).
  - Banca-safety: KRYON_INCLUDE_EVIDENCE defaults to "false".
  - The example pipeline uses `extends: .kryon-audit` correctly.

If a future edit accidentally drops a variable, breaks the
artifacts shape, or flips include-evidence on by default, this
catches it before the next release.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# yaml is in deps via several other modules; the template tests need it.
yaml = pytest.importorskip("yaml")


_REPO_ROOT = Path(__file__).resolve().parents[2]
_TEMPLATE_PATH = _REPO_ROOT / ".gitlab" / "ci" / "kryon-audit.gitlab-ci.yml"
_EXAMPLE_PATH = _REPO_ROOT / ".gitlab" / "ci" / "example.gitlab-ci.yml"


@pytest.fixture(scope="module")
def template() -> dict:
    assert _TEMPLATE_PATH.is_file(), f"template missing: {_TEMPLATE_PATH}"
    return yaml.safe_load(_TEMPLATE_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def example() -> dict:
    assert _EXAMPLE_PATH.is_file(), f"example missing: {_EXAMPLE_PATH}"
    return yaml.safe_load(_EXAMPLE_PATH.read_text(encoding="utf-8"))


# =====================================================================
# Template YAML shape
# =====================================================================


def test_template_yaml_parses(template):
    assert isinstance(template, dict)
    assert "variables" in template


def test_template_declares_hidden_kryon_audit_job(template):
    """GitLab CI: jobs starting with '.' are hidden templates.
    Downstream pipelines extend them via `extends: .kryon-audit`."""
    assert ".kryon-audit" in template


def test_kryon_audit_job_has_script(template):
    job = template[".kryon-audit"]
    assert "script" in job
    # Script is a single-item list with a multi-line bash block.
    assert isinstance(job["script"], list)
    assert len(job["script"]) >= 1
    script_text = " ".join(job["script"])
    assert "python -m scripts.ci.kryon_audit" in script_text
    assert "--findings" in script_text
    assert "--sarif-out" in script_text
    assert "--fail-on" in script_text


def test_kryon_audit_job_tagged_kryon(template):
    """Banca-safety: the job is constrained to runners tagged
    `kryon` so the cluster's shared runners don't accidentally
    execute Kryon engagements."""
    job = template[".kryon-audit"]
    assert "tags" in job
    assert "kryon" in job["tags"]


def test_kryon_audit_does_not_allow_failure(template):
    """Default behaviour: a gate breach turns the pipeline red.
    Operators override per-job to soft-fail during rollout — but
    the template's default must NOT silently swallow gate
    failures."""
    job = template[".kryon-audit"]
    assert job.get("allow_failure") is False


# =====================================================================
# Variables (advertised defaults)
# =====================================================================


def test_template_declares_documented_variables(template):
    """Every variable in the docs/ci/gitlab-ci.md table must be
    declared at the top of the template with its advertised default."""
    variables = template["variables"]
    expected = {
        "KRYON_FINDINGS": "findings.json",
        "KRYON_SARIF_OUT": "kryon.sarif",
        "KRYON_FAIL_ON": "high",
        "KRYON_INCLUDE_EVIDENCE": "false",
        "KRYON_TOOL_VERSION": "2.1.0",
    }
    for name, default in expected.items():
        assert name in variables, f"variable {name} not declared"
        assert variables[name] == default, (
            f"variable {name} default drifted: docs say {default!r}, "
            f"template has {variables[name]!r}"
        )


def test_banca_safety_include_evidence_defaults_false(template):
    """If this flips to 'true', engagement evidence (potentially
    carrying token / PAN fragments) lands in the GitLab Security
    Dashboard for every job. Hard requirement: must default
    'false'."""
    assert template["variables"]["KRYON_INCLUDE_EVIDENCE"] == "false"


def test_optional_variables_declared_with_empty_default(template):
    """KRYON_ENGAGEMENT_ID + KRYON_CLIENT are optional; declared
    with empty string so users don't need to set them, but
    extending jobs can override."""
    variables = template["variables"]
    assert variables.get("KRYON_ENGAGEMENT_ID", None) == ""
    assert variables.get("KRYON_CLIENT", None) == ""


# =====================================================================
# Artifacts block (SARIF ingestion)
# =====================================================================


def test_artifacts_publish_sarif_path(template):
    job = template[".kryon-audit"]
    paths = job["artifacts"]["paths"]
    assert any("$KRYON_SARIF_OUT" in p for p in paths)


def test_artifacts_report_under_sast_key(template):
    """GitLab 16.8+ Premium recognizes a .sarif file under
    `reports:sast` for native Security Dashboard ingestion. Drift
    here means the dashboard goes blank."""
    job = template[".kryon-audit"]
    reports = job["artifacts"]["reports"]
    assert "sast" in reports
    assert "$KRYON_SARIF_OUT" in str(reports["sast"])


def test_artifacts_when_always(template):
    """SARIF must publish even when the gate fails — the auditor
    still wants to see findings on a failing MR."""
    job = template[".kryon-audit"]
    assert job["artifacts"]["when"] == "always"


def test_artifact_retention_at_least_30d(template):
    """Banking compliance: SARIF artifacts (the audit trail) need a
    reasonable retention. 30 days lets a weekly audit cycle
    complete + buffer."""
    job = template[".kryon-audit"]
    expire = str(job["artifacts"]["expire_in"])
    # GitLab accepts "30 days", "1 month", "1 week", etc. — check
    # for "30 days" verbatim since that's the documented default.
    assert "30 days" in expire


# =====================================================================
# Severity-gate alignment with F89.2
# =====================================================================


def test_template_fail_on_default_matches_github_action(template):
    """Both CI integrations must default to the same gate so
    multi-platform pipelines behave consistently."""
    assert template["variables"]["KRYON_FAIL_ON"] == "high"


def test_template_invokes_kryon_audit_module(template):
    job = template[".kryon-audit"]
    script_text = " ".join(job["script"])
    assert "scripts.ci.kryon_audit" in script_text


def test_template_propagates_include_evidence_flag(template):
    """The shell script in the template must conditionally append
    --include-evidence when KRYON_INCLUDE_EVIDENCE=true — otherwise
    the banca-safety opt-in path is broken."""
    job = template[".kryon-audit"]
    script_text = " ".join(job["script"])
    assert "--include-evidence" in script_text
    assert "KRYON_INCLUDE_EVIDENCE" in script_text


# =====================================================================
# Example pipeline
# =====================================================================


def test_example_includes_template(example):
    """The example pipeline must reference the template via
    `include:` — otherwise downstream users copy it and miss the
    template entirely."""
    assert "include" in example
    includes = example["include"]
    if isinstance(includes, dict):
        includes = [includes]
    template_refs = [
        i for i in includes
        if isinstance(i, dict) and "/.gitlab/ci/kryon-audit.gitlab-ci.yml" in str(i.get("file", ""))
    ]
    assert template_refs, "example pipeline doesn't reference the template"


def test_example_audit_job_extends_template(example):
    """Validates the canonical extends pattern users copy."""
    audit_job = example.get("kryon-security-audit")
    assert audit_job is not None
    assert audit_job["extends"] == ".kryon-audit"


def test_example_engage_job_emits_findings_artifact(example):
    """Pipeline contract: the engage job MUST produce
    findings.json as an artifact so the audit job can consume it."""
    engage_job = example.get("kryon-engage")
    assert engage_job is not None
    artifact_paths = engage_job["artifacts"]["paths"]
    assert "findings.json" in artifact_paths


def test_example_audit_job_needs_engage_artifacts(example):
    """The audit job MUST declare needs: with artifacts: true on
    the engage job — otherwise the SARIF path resolves to a missing
    file."""
    audit_job = example["kryon-security-audit"]
    needs = audit_job.get("needs", [])
    engage_dep = [
        n for n in needs
        if isinstance(n, dict) and n.get("job") == "kryon-engage"
    ]
    assert engage_dep, "audit job doesn't declare needs:[kryon-engage]"
    assert engage_dep[0].get("artifacts") is True
