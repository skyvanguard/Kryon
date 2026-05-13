# F89.3 — Kryon GitLab CI template

Sibling to the [GitHub Action](github-action.md). Same entrypoint
(`scripts.ci.kryon_audit`), same severity gate, same banca-safety
contract — different manifest shape because GitLab CI uses includes
+ extends instead of composite actions.

## Files

- `.gitlab/ci/kryon-audit.gitlab-ci.yml` — the reusable template
  defining the hidden `.kryon-audit` job.
- `.gitlab/ci/example.gitlab-ci.yml` — a complete downstream
  pipeline you can drop into your repository and adapt.

## Quick start

In your project's `.gitlab-ci.yml`:

```yaml
include:
  - project: 'kryon/kryon'
    ref: main
    file: '/.gitlab/ci/kryon-audit.gitlab-ci.yml'

stages:
  - engage
  - audit

kryon-engage:
  stage: engage
  tags: [kryon]
  script:
    - kryon engage --target "$KRYON_TARGET" --emit-findings findings.json
  artifacts:
    paths: [findings.json]

kryon-security-audit:
  extends: .kryon-audit
  stage: audit
  needs: [{ job: kryon-engage, artifacts: true }]
  variables:
    KRYON_FAIL_ON: high
```

## Requirements

- **Self-managed runner** tagged `kryon`. Kryon is proprietary and
  the `kryon-kali` image is 8-12 GB — GitLab.com SaaS shared
  runners can't host it.
- A prior step that produces the findings JSON. The template
  consumes the file; it does NOT orchestrate the engagement.

## CI variables

Override via `variables:` on the extending job.

| Variable                  | Default        | Description                                                       |
|---------------------------|----------------|-------------------------------------------------------------------|
| `KRYON_FINDINGS`          | `findings.json`| Path to the findings JSON.                                        |
| `KRYON_SARIF_OUT`         | `kryon.sarif`  | Where to write the SARIF output.                                  |
| `KRYON_FAIL_ON`           | `high`         | Severity gate (`info`/`low`/`medium`/`high`/`critical`/`never`).  |
| `KRYON_INCLUDE_EVIDENCE`  | `false`        | Surface evidence in SARIF (banca-safety: off by default).         |
| `KRYON_TOOL_VERSION`      | `2.1.0`        | SARIF tool driver version string.                                 |
| `KRYON_ENGAGEMENT_ID`     | _empty_        | Stamped into SARIF `run.properties.engagement_id`.                |
| `KRYON_CLIENT`            | _empty_        | Stamped into SARIF `run.properties.client`.                       |

## SARIF ingestion

- **GitLab 16.8+ Premium / Ultimate**: artifacts published under
  `reports:sast` with a `.sarif` extension are recognized natively.
  Findings appear on the Security Dashboard and MR widget.
- **GitLab Free / older**: SARIF is uploaded as a regular artifact;
  the job page shows a download link. Teams ingest into a
  third-party dashboard (DefectDojo, etc.) via a follow-up job.

## Severity gate behaviour

Same ladder as F89.2 (`info < low < medium < high < critical`). A
finding at or above the threshold returns exit code 1 from the
entrypoint, which the template's `allow_failure: false` propagates
to the pipeline status.

- `KRYON_FAIL_ON: critical` — only CRITICAL fails the build.
- `KRYON_FAIL_ON: high`     — CRITICAL or HIGH (default).
- `KRYON_FAIL_ON: never`    — gate disabled; SARIF still published.

For staged rollouts, define two audit jobs (the example shows
this): one strict (default `KRYON_FAIL_ON: high`, blocks merge) and
one soft (`KRYON_FAIL_ON: critical` + `allow_failure: true`, only
warns on MRs). Once the team has driven medium/high findings to
zero, drop the soft variant.

## Banca-safety notes

- **`KRYON_INCLUDE_EVIDENCE: false` is the default.** Engagement
  evidence frequently carries token / PAN fragments / partial
  request bodies. Surfacing those into SARIF means they end up in
  the Security Dashboard and the artifact archive — usually
  unacceptable for banking engagements.
- **Self-managed runner isolation.** The `kryon`-tagged runner has
  the LLM weights, Kali tools, and target credentials. Treat it as
  a tier-1 production host: network-segmented, hardened, no MR-
  trigger-on-fork.
- The template's `tags: [kryon]` constraint ensures only the
  designated runner picks up these jobs. If you remove the tag,
  any shared runner could potentially execute Kryon — make sure
  that's intentional.

## Troubleshooting

### "no runner picked up the job"

The job is constrained to runners tagged `kryon`. Either tag a
runner appropriately (Settings → CI/CD → Runners → edit → tags) or
override the `tags:` list on the extending job.

### "kryon: command not found"

The runner has the `kryon` tag but doesn't actually have Kryon
installed. Either install it (`pip install kryon` — proprietary,
needs license/keys) or exec into the `kryon-kali` container as the
job's image (`image: kryon/kali:latest`).

### "report.sast: file not found"

The audit step ran but the SARIF artifact wasn't produced — usually
means the entrypoint exited 2 (input error: missing findings file
or malformed JSON). Check the job log; the SARIF path would have
been printed.

### "findings show in artifact but not on Security Dashboard"

You're on GitLab Free / older. SARIF native ingestion requires
Premium / Ultimate 16.8+. Download the artifact and ingest into a
separate dashboard.
