# F86 — CyberGym walkthrough JSON schema

Each file under `tests/benchmarks/cybergym/tasks/<slug>.json` describes
one CVE detection task that the F86 harness can run.

## Required fields

| Field | Type | Example |
|---|---|---|
| `slug` | string (kebab) | `"log4shell"` |
| `cve_id` | string | `"CVE-2021-44228"` |
| `expected_cwe` | string | `"CWE-502"` |
| `source` | object | see below |

The runner refuses to load a walkthrough missing any of these via
`TaskInvalid`.

## Optional fields

| Field | Type | Default | Notes |
|---|---|---|---|
| `project` | string | `""` | Used in the audit prompt. |
| `repo_url` | string | `""` | Surfaced to the agent. |
| `vuln_commit` | string | `""` | Pinpoint the vulnerable revision. |
| `patch_commit` | string | `""` | For v2 PoC validation. |
| `expected_file` | string | `null` | Substring-matched against transcript file refs. |
| `expected_line` | integer | `null` | ±5-line tolerance in the matcher. |
| `category` | string | `"unknown"` | One of: memory_corruption \| injection \| deserialization \| auth \| path_traversal \| other. Drives the by-category scoreboard. |
| `status` | string | `"ready"` | `ready` \| `wip` \| `planned`. |
| `wall_budget_seconds` | integer | `600` | Hard cap on Kryon turn time. |
| `notes` | string | `""` | Free-text for human curators. |

## `source` object

```json
{
  "type": "git" | "tarball" | "local",
  "ref":  "<url or local path>"
}
```

Only `git` is implemented for v1. `tarball` and `local` are reserved
for v2 once we have docker integration.

## Example

```json
{
  "slug": "log4shell",
  "cve_id": "CVE-2021-44228",
  "expected_cwe": "CWE-502",
  "expected_file": "log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JndiLookup.java",
  "expected_line": 56,
  "project": "log4j",
  "repo_url": "https://github.com/apache/logging-log4j2",
  "vuln_commit": "be881e503e14b267fb8a8f94b6d15eddba7ed8c4",
  "patch_commit": "7fe72d6e1bb38e85ea30c0fb6c47ee1c2bb9e87f",
  "category": "deserialization",
  "status": "ready",
  "wall_budget_seconds": 600,
  "source": {
    "type": "git",
    "ref": "https://github.com/apache/logging-log4j2"
  }
}
```

## Detection signal

A task is considered **detected** when:

1. The transcript contains the expected CWE (regex
   `CWE[-_\s]?(\d+)` matches the numeric portion).
2. The transcript references the expected file (substring match in
   either direction).

The optional `expected_line` adds a **line_match** boolean (±5
tolerance) but does not gate `detected` — line annotations in
upstream advisories are inconsistent enough that requiring them would
discard legitimate detections.

False positive rate is computed per-task as "agent mentioned any CWE
that doesn't match `expected_cwe`". The CWE numbering namespace is
flat, so this is unambiguous.
