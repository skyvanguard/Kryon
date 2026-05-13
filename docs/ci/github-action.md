# F89.2 — Kryon GitHub Action

The Kryon GitHub Action takes the findings JSON your engagement
produced, emits a SARIF 2.1.0 file, and (optionally) uploads it to
GitHub Code Scanning so the findings show up as inline PR annotations
and on the Security tab.

## Requirements

- **Self-hosted runner.** Kryon is proprietary and the
  `kryon-kali` container image is 8-12 GB — it doesn't fit on
  GitHub-hosted runners' 14 GB tmpfs. The action assumes Kryon is
  available on the runner (`pip install kryon` or
  `docker compose up`).
- **A prior step** that emitted the findings JSON. Typically:

  ```yaml
  - name: Run Kryon engagement
    run: |
      kryon engage \
        --target https://staging.app.bank.example \
        --emit-findings findings.json
  ```

  The action accepts the findings file as input; it does NOT
  orchestrate the engagement itself.

## Minimal example

```yaml
name: Security audit
on:
  pull_request:

jobs:
  kryon-audit:
    runs-on: [self-hosted, kryon]
    permissions:
      security-events: write  # required for SARIF upload
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Run Kryon
        run: |
          kryon engage \
            --target https://staging.app.bank.example \
            --emit-findings findings.json

      - name: Kryon audit
        uses: ./.github/actions/kryon-audit
        with:
          findings: findings.json
          fail-on: high
          engagement-id: ${{ github.run_id }}
```

## Inputs

| Name              | Default        | Description                                                                |
|-------------------|----------------|----------------------------------------------------------------------------|
| `findings`        | _required_     | Path to the findings JSON file.                                            |
| `sarif-out`       | `kryon.sarif`  | Where to write the SARIF output.                                           |
| `fail-on`         | `high`         | Severity gate. `never` disables it.                                        |
| `upload-sarif`    | `true`         | Upload to GitHub Code Scanning.                                            |
| `include-evidence`| `false`        | Surface evidence in SARIF (banca-safety: off by default).                  |
| `tool-version`    | `2.1.0`        | SARIF tool driver version string.                                          |
| `engagement-id`   | _empty_        | Stamped into SARIF `run.properties.engagement_id`.                         |
| `client`          | _empty_        | Stamped into SARIF `run.properties.client`.                                |

## Outputs

| Name              | Description                                                            |
|-------------------|------------------------------------------------------------------------|
| `sarif-path`      | Path to the SARIF file the action wrote.                               |
| `findings-count`  | Total findings count in the input JSON.                                |
| `critical-count`  | Number of `CRITICAL` findings.                                         |
| `failing-count`   | Findings meeting/exceeding the `fail-on` threshold.                    |

## Severity gate behaviour

The gate compares each finding's `severity` against `fail-on` using
the canonical ladder `info < low < medium < high < critical`. A
finding at or above the threshold triggers exit code `1`, which
fails the workflow step.

- `fail-on: critical` — only CRITICAL findings fail the build.
- `fail-on: high`     — CRITICAL or HIGH (default).
- `fail-on: medium`   — anything MEDIUM or worse.
- `fail-on: never`    — gate disabled; SARIF still uploaded.

Findings with an unrecognized severity string (e.g. `trivial`,
custom labels) never trip the gate — by design, so a typo in a new
playbook doesn't accidentally green-light a build.

## Banca-safety notes

- **`include-evidence: false` is the default.** Engagement evidence
  frequently contains token / PAN fragments / partial request
  bodies. Surfacing those into SARIF means they end up in the
  GitHub Code Scanning UI and in the commit's audit log — usually
  unacceptable for banking engagements. Opt in explicitly only when
  the engagement context allows it.
- **Self-hosted runner isolation.** The runner that executes Kryon
  also has the LLM weights, Kali tools, and the target's
  credentials. Treat that runner as a tier-1 production host:
  network-segmented, hardened, no PR-trigger-on-fork.
- **SARIF fingerprints** dedupe findings across runs. The same
  vulnerability on the same host won't appear twice — useful for
  long-running engagements that re-test patched systems.

## Troubleshooting

### "upload-sarif: missing scope security-events:write"

The job needs the `security-events: write` permission. Add to the
job:

```yaml
permissions:
  security-events: write
  contents: read
```

### Action ran but no findings show on the Security tab

GitHub Code Scanning indexes SARIF asynchronously. Wait 1-2 minutes
and refresh. If still empty: check the SARIF file is valid
(`jq . kryon.sarif`) and the runner had `security-events: write`.

### "kryon: command not found"

The action assumes Kryon is already on the runner. Either install
it via `pip install kryon` (proprietary — needs license/keys) or
exec into the `kryon-kali` container as the prior step.
