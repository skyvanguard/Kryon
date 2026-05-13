# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**KRYON v2.1.0 "Hydra — Skillforge"** is an autonomous cybersecurity agent for the **financial services sector**. Python 3.10+, managed with `uv` (workspace member: `agents/`). License is **Proprietary** — do not reintroduce MIT references.

The architecture has evolved from 33 static Python agents (v1.x) to a **unified skill-based system** (v2.x): one agent called "Kryon" with **67 dynamic markdown playbooks** that load based on target profile and user intent. Focus is on **banking clients in LATAM/Paraguay** (BCP, SIB, Superintendencia de Bancos).

Entry point: `kryon = "kryon.cli:main"` (see `pyproject.toml`).

## Commands

All via `uv` (Makefile wraps them). On Windows bash, use forward slashes.

```bash
make sync                    # uv sync --all-extras --all-packages --group dev
make format                  # ruff format + ruff check --fix
make lint                    # ruff check
make mypy                    # mypy . (non-strict; many modules in ignore_errors override)
make tests                   # uv run pytest
make coverage                # coverage run + xml + report --fail-under=95
make snapshots-fix           # pytest --inline-snapshot=fix
make docker-build / docker-up / docker-down / docker-prod
make security-scan           # pip-audit + safety
```

Run a single test / subset:

```bash
uv run pytest tests/test_kryon_imports.py
uv run pytest tests/agents/ -k "pentest"
uv run pytest -m "unit and not slow"
uv run pytest --inline-snapshot=fix tests/path/to/test.py
```

`asyncio_mode = "auto"` — do not add `@pytest.mark.asyncio` manually; fixture loop scope is `session`.

Coverage target in `make coverage` is **95%** (stricter than the 80% global rule). `[tool.coverage.run] source = ["tests", "src/kryon/sdk/agents"]` — coverage is scoped to the SDK subtree, not the whole package.

## Architecture (v2.x — skill-based)

Top-level layout: `src/kryon/` (package), `tests/` (mirrors package layout), `docker/`, `helm/`, `k8s/`, `docs/`, `scripts/`, `agents/` (uv workspace member).

### Skill system (`src/kryon/skills/`) — primary interface in v2.x

- **`loader.py`** — `SkillLoader` scans `playbooks/` recursively, parses YAML frontmatter, matches by `triggers` (tech, ports, keywords) and user intent. Priority-based selection with token budget cap.
- **`unified_agent.py`** — `create_unified_agent()` builds a single "Kryon" agent with composed prompt (base identity + matched skill bodies) and budget-selected tools (max 30 to fit 32K context).
- **`tool_budget.py`** — Selects tools from the full registry based on active skills' `required_tools`.
- **`playbooks/`** — 67 markdown files with YAML frontmatter, three subdirectories:
  - **`(core)` 11 skills**: recon-scout, pentest, vuln-hunter, wordpress-audit, appsec, forensics, ctf-master, ssl-audit, server-hardening, safe-modification, rollback-recovery
  - **`imported/` 28 skills**: From `mukul975/Anthropic-Cybersecurity-Skills` (Apache 2.0, MITRE ATT&CK mapped). SQL injection, SSRF, JWT attacks, HTTP smuggling, AD attacks, cloud attacks, forensics, etc.
  - **`banking/` 8 skills**: Custom for financial clients. pci-dss-audit, core-banking-assessment, mobile-banking-audit, atm-security, payment-gateway-testing, fraud-detection, swift-network-security, open-banking-api.

**Critical**: Skills are **the primary way to add functionality** in v2.x. Do not create new Python agent files unless absolutely necessary. Prefer writing a `.md` playbook.

**Skill `pre_hooks:` — F80 deterministic-first execution**. A skill can declare a YAML
list of tool invocations that run BEFORE the LLM gets control of the turn. The
output is injected into `conversation_input` as authoritative context — the LLM
narrates findings, it can NOT skip the detector. Schema lives in
`src/kryon/skills/pre_hook_spec.py` (frozen dataclass, SSTI-guarded template
substitution, strict allowlist `{ctx.host, ctx.ssh_user, ctx.ssh_key_path,
ctx.ssh_port, ctx.target, ctx.session_id, ctx.client_name}`). Runner lives in
`src/kryon/skills/pre_hook_runner.py` (sync+async, timeouts, required vs
optional). Integration in `src/kryon/skills/pre_hook_integration.py` extracts
callables via `function_tool._raw_fn`. Currently used by: `fortigate-audit`,
`unifi-audit`, `proxmox-audit`, `pci-dss-audit`, `audit-bank-full`.

Two execution modes:
- **Declarative** (`tool: <name>` + `args: {...}`): YAML-driven, args support
  `{ctx.X}` template substitution from the whitelist. Use for 80% of cases.
- **Python escape hatch** (`python: ./<file>.py:<func>`): Fase 5. The file
  resolves relative to the skill `.md` directory and MUST stay inside the
  Kryon repo (path traversal blocked via `Path.resolve().relative_to`). The
  callable receives the full `ctx` dict and returns `str | dict | list`
  (dicts get JSON-encoded). Use only for hooks that need conditional logic
  the declarative form can't express.

### Other core subsystems

- **`learning/`** — Self-improving loop, **v2 closed**. v1 capture: `experiences.py` (ChromaDB), `profiler.py`, `chain_extractor.py`, `findings_library.py`. v2 closes the loop in three layers (full doc: `docs/LEARNING_LOOP.md` v2 section):
  - **F1 drafting** — `skill_synthesizer.py` + `draft_writer.py`. Every successful engagement auto-writes a draft `.md` to `~/.kryon/drafts/`. Operator promotes via `/skill promote`.
  - **F2 scoring** — `skill_scorer.py` (Wilson 95% lower bound) + `selection_telemetry.py` (JSONL log). Activate hybrid ranking with `KRYON_SKILL_RANKING=hybrid`. Off by default (banking-safe). **F77.G.5** adds a second reward axis (reusability — cuántas veces fue seleccionada cross-engagements), available via `KRYON_SKILL_RANKING=dual`. The combined score is `0.7 * wilson_lower + 0.3 * reusability_norm`; priority remains the primary sort, score only orders within a tier. Same banking-safety contract as hybrid.
  - **F3 auto-creation** — `pattern_detector.py` (Jaccard clustering) + `synthesize_from_cluster()` (LLM-assisted body, hallucinated tool names rejected) + `skill_evaluator.py` (CWE→tools eval gate, conservative precision-over-recall) + `auto_pipeline.py`. Manual trigger: `/skill auto detect`.
  - REPL commands: `/skill drafts|review|promote|discard|scores|auto`.
  - CWE map override: `~/.kryon/cwe_map.yaml` (template at `docs/examples/cwe_map.yaml`) or `KRYON_CWE_MAP` env var.
- **`services/`** — Context management. `micro_compact.py` (trim tool outputs ~85%), `session_memory.py` (Magic Doc auto-report), `auto_extract.py` (save experience on exit + auto-synth draft), `tool_output_cap.py` (save >5K outputs to disk).
- **`sdk/`** — Agent runtime SDK (under `sdk/agents/`). Run loop, tool executor, MCP integration, model adapters. Most of `mypy` and coverage is focused here.
- **`agents/`** — Legacy 33+ agents (still work for backward compat via `/agent select <name>`). In v2.x the default is `kryon` (unified).
- **`tools/`** — 204+ tool implementations by kill-chain category. Agents bind to categories/tools rather than individual files.
- **`server/`** — FastAPI application (`app.py`) with `routes/`, `auth/`, `middleware/`, JWT/RBAC. 136 endpoints.
- **`repl/` + `tui/` + `cli/`** — User interfaces. CLI is `kryon` entry point. Commands in `repl/commands/`:
  - `/skill` (list/show/search/import/reload) — manage playbooks
  - `/experiences` (list/show/search/close) — manage learning
  - `/flush`, `/compact`, `/memory`, `/agent`, etc.
- **`knowledge/`** — RAG. ExploitDB, NVD, GitHub writeups + ChromaDB with Ollama embeddings.
- **`compliance/`** — 9 frameworks (PCI-DSS, HIPAA, SOC2, NIST 800-53, ISO 27001, GDPR, OWASP, CIS, MITRE ATT&CK).

### Important cross-cutting rules

- **Ollama-first**: The recommended model is `kryon-14b` (Modelfile: `FROM qwen3:14b` + `num_ctx 32768` + `num_predict 4096`). Qwen3-14B dense fits 100% in 12GB VRAM and outperforms the older `kryon-30b-moe` (MoE 3.3B-active with 18GB Q4 → VRAM spillover). F20 bench proved the upgrade: Juice Shop 0/111 → 9/111 (8.1%) with no other change. Many fixes live in `sdk/agents/models/openai_chatcompletions.py` to make tool calling reliable with local models (tool name normalization, hallucination tolerance, schema fix, tool_choice forcing).
- **LiteLLM without `[proxy]`** — uvloop is not supported on Windows; do not re-add the proxy extra to `pyproject.toml`.
- **`openinference-instrumentation-openai`** is Python-version-gated (`< 3.14`) under the `tracing` extra.
- **Optional extras**: `voice`, `viz`, `tracing`, `rag`, `server`, `tui`, `reporting`, `orchestration`, `dev`.
- **Ruff per-file ignores** are deliberately loose for `agents/`, `tools/`, `repl/`, `sdk/`, `knowledge/`, `intelligence/`, `reporting/`, `server/`. Check `[tool.ruff.lint.per-file-ignores]` before "fixing" E501/E402/B904/B008 in those trees.
- **`mypy` `ignore_errors`** covers `kryon.tools.*`, `kryon.agents.*`, `kryon.knowledge.*`, `kryon.repl.*`, `kryon.cache.*`, `kryon.cli*`, and much of `kryon.sdk.agents.*`. Type-level work should target modules *outside* that override list.
- **Tests mirror the package**: `tests/<subsystem>/...`. Top-level integration/smoke tests exist too.

### Configuration

Runtime config via env vars (see `docker/.env.docker`):

```bash
KRYON_MODEL=kryon-14b              # Recommended (Qwen3-14B dense + 32K ctx)
KRYON_AGENT_TYPE=kryon             # Use unified agent (v2.x)
KRYON_UNIFIED=true
KRYON_FORCE_TOOL_TURNS=8           # Force tool use first N turns (Ollama reliability)
KRYON_MEMORY=true
KRYON_STREAM=false                 # Non-streaming REPL (stable)
KRYON_EMBEDDING_MODEL=nomic-embed-text
KRYON_TOOL_BUDGET=static           # F84.7: 'itr' enables per-turn embedding-based tool selection.
                                   # Default 'static' = banca-safe legacy skill-driven selection.
                                   # Build the index first: python -m scripts.build_itr_index
KRYON_BOLA_FIRE=                   # F87.2: 'true' enables live HTTP probes in detect_bola tool.
                                   # Default unset = dry-run only (no network traffic). Operator
                                   # MUST also pass fire=True in the tool call — both gates required.
KRYON_GRAPHQL_FIRE=                # F87.3: 'true' enables live HTTP probes in graphql_recon tool.
                                   # Same double-gate as KRYON_BOLA_FIRE. Default unset = dry-run.
```

## Docker / K8s

- `docker/docker-compose.kali.yml` + `docker/docker-compose.override.yml` is the dev stack (Kali + Ollama + Kryon).
- `helm/` and `k8s/` hold production manifests.
- The override adds memory limits (12G kryon, 20G ollama) and removes Claude Code CLI bind mounts.

## Conventions specific to this repo

- Conventional commits (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `perf:`, `ci:`).
- Do **not** commit `.kryon/`, `workspaces/`, `logs/`, `nohup.out`, `ci/`, or `tools/cut_the_rope/` — all excluded from the hatch build.
- When adding capabilities in v2.x: **prefer a skill** (`.md` in `skills/playbooks/`) over a new Python agent.
- Banking skills go in `skills/playbooks/banking/`. Imported upstream skills go in `skills/playbooks/imported/`. Core skills at the top level.
- When editing markdown (prompts or skills) on Windows: ensure LF line endings (Git will warn about CRLF).

## Working with banking clients

- Every financial engagement requires **written authorization** from the institution.
- Paraguay regulatory: **BCP Resoluciones** (SIB), **SEPRELAD** for AML, **Superintendencia de Bancos** for audits.
- Never commit or log **real PAN numbers** (tarjetas). Use test cards only (Stripe: 4242..., Bancard: 4005 5500 0000 0001).
- Client data handling: **NDA first**, data retention policy, secure destruction after engagement.
- For PCI-DSS audits, confirm the SAQ level (A, A-EP, B, B-IP, C, C-VT, D) before scoping.
- For SWIFT CSP audits, the attestation is annual — coordinate with the SWIFT CISO of the bank.

## Banking vertical — current reality vs pitch (F77.C)

The README and marketing surface may describe "Kryon for banking" as a
turnkey product. For internal development purposes, the honest status is:

| Playbook | Status | Notes |
|---|---|---|
| `pci-dss-audit.md` | **production-capable** | F15.1 + F39 + F85.E + F39.3: 46 deterministic checks wired to compliance runner. F85.E added 2.2.8 fail2ban, 6.3.4 unattended-upgrades, 6.5.1 disk capacity, 10.2.2 rsyslog after the proxmox2 ground-truth gap analysis. F39.3 added 6.4.3 (SRI+CSP scripts checkout) and 8.4.3 (phishing-resistant MFA / FIDO2 / WebAuthn) — both mandatorios desde 2025-03-31 bajo PCI-DSS v4.0.1. Reproducibility-hashed. Ready for SAQ B/C/D scoping. |
| `proxmox-audit.md` | **production-capable** | F23 + F23.1 + F85.E: 8 deterministic PVE checks (F85.E added PVE-6.1 cluster quorum tie-breaker). Validated in the F48 internal pilot. |
| `audit-bank-full.md` | **production-capable** | F46: orchestrates the three above + multi-framework PDF (F44). |
| `core-banking-assessment.md` | **template** | Vendor-specific (T24/Flexcube/Finacle/Bantotal): methodology + checklist only. No out-of-the-box scanner for any of these. Needs vendor sandbox + credentials per engagement. |
| `swift-network-security.md` | **template** | Maps CSP v2024 (32 controls). Execution is manual + with Alliance Access access. Not a KY3P replacement. |
| `atm-security.md` | **template** | Requires physical access + NCR/Diebold lab + PCI-PTS certified team. |
| `open-banking-api.md` | **template** | FAPI 1.0 Advanced methodology. Per-bank mTLS certs + client_id required. |
| `payment-gateway-testing.md` | **template** | Vendor-specific (Bancard/Infonet/Stripe/MercadoPago). Checklist only. |
| `fraud-detection.md` | **template** | Interview + rule-review guide, not a technical scan. |
| `mobile-banking-audit.md` | **template** | Needs Frida/objection/jailbroken device outside the Kryon container. |
| `fortigate-audit.md` | **production-capable** | F78: 21 checks deterministicos (FGT-1.1..FGT-5.3) cableados a `run_compliance_audit(framework="fortigate")`. CIS Fortinet Benchmark mapping + CVE catalog hardcoded (CVE-2022-42475, CVE-2024-21762, CVE-2024-23113). Read-only via SSH al CLI FortiOS. Hash de reproducibilidad estable. |
| `unifi-audit.md` | **production-capable (controller)** + **template (WiFi capture)** | F79: 18 controller checks deterministicos (UNF-1.1..UNF-4.2) cableados a `run_compliance_audit(framework="unifi")` via `mongo --port 27117 ace`. Hash estable. La captura activa WiFi (handshake / PMKID + crack offline) sigue siendo guiada y corre en el host del operador (no en el container — no hay raw 802.11). Deauth requiere autorización escrita explícita. |

**What Kryon actually runs end-to-end today**: local-network compliance
sweep (PCI-DSS + CIS + Proxmox + AD + FortiGate + Unifi) → multi-framework
consolidated PDF (F27.5) → deterministic reproducibility hash. Juice Shop
benchmark (F18-F73) at 85/111 and Juliet SAST (F74.C-F76.2) at 67.1%
recall + 15% FPR@HIGH are the proof-points. Edge-network audits (F78
FortiGate + F79 Unifi) extend coverage from the data center to the
perimeter and WiFi. Banking templates (T24/Flexcube/SWIFT/ATM) are
starter frames, not finished offerings.

Whenever recommending a banking playbook to the user, surface the
status. If it's `template`, say so — don't promise what isn't there.
