"""F89.2 / F89.3 — CI/CD entrypoints for GitHub Action + GitLab CI.

This package isolates the CI-side orchestration from the rest of the
Kryon CLI surface. The entrypoint here takes a list of findings (as
JSON, typically produced by a prior `kryon engage` run) and:

  1. Writes a SARIF 2.1.0 file (via kryon.reporting.sarif).
  2. Applies the `--fail-on` severity gate.
  3. Emits GitHub-style step outputs / GitLab Job-log markers.
  4. Exits 0 (clean) or 1 (gate failed) for the CI to fail the job.

The orchestrator deliberately does NOT run the engagement itself.
Engagement orchestration is the runner-config problem (where's the
Ollama, which container, which network) and varies per
deployment. A separate `kryon engage --emit-findings` produces the
input file; the CI step composes them. This separation lets us
unit-test the CI logic without spinning up a real engagement.
"""
