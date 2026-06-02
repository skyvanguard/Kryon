# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**KRYON v2.1.0 "Hydra — Skillforge"** is a **general offensive autonomous cybersecurity agent** (pivoting from its original financial-services focus — banking/compliance capabilities still ship but are being deprioritized). Python 3.10+, managed with `uv` (workspace member: `agents/`). License is **Proprietary** — do not reintroduce MIT references.

The architecture is a **unified skill-based system** (v2.x): one agent called "Kryon" with **~106 dynamic markdown playbooks** that load based on target profile and user intent. The 33 static Python agents (v1.x) + the per-name factory + `/agent select` were **removed** — `get_agent_by_name(<any>)` now always returns the unified agent (see `agents/__init__.py`). Product direction is a **general offensive autonomous agent**; the banking/compliance surface (PCI/CIS skills, compliance frameworks) is still present but being deprioritized (a dedicated "offensive-pure" strip is pending — it would touch engage + reporting deeply, so it's its own effort).

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
- **`unified_agent.py`** — `create_unified_agent()` builds a single "Kryon" agent with composed prompt (base identity + matched skill bodies) and budget-selected tools (max 15 to keep schema tokens under control).
- **`tool_budget.py`** — Selects tools from the full registry based on active skills' `required_tools`. `EXPLOIT_VALIDATION_TOOLS` are offered only under `KRYON_RED_TEAM`. The RAG retrieval tools + their exclude filter were removed (see RAG note below).
- **`playbooks/`** — ~106 markdown files with YAML frontmatter, subdirectories:
  - **`(core)` 11 skills**: recon-scout, pentest, vuln-hunter, wordpress-audit, appsec, forensics, ctf-master, ssl-audit, server-hardening, safe-modification, rollback-recovery
  - **`imported/` 28 skills**: From `mukul975/Anthropic-Cybersecurity-Skills` (Apache 2.0, MITRE ATT&CK mapped). SQL injection, SSRF, JWT attacks, HTTP smuggling, AD attacks, cloud attacks, forensics, etc.
  - **`banking/` skills**: Custom for financial clients. pci-dss-audit, core-banking-assessment, mobile-banking-audit, atm-security, payment-gateway-testing, fraud-detection, swift-network-security, open-banking-api, cis-controls-v8.1.

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
- **`agents/`** — Unified-only. The 33 legacy per-name agents + `factory.py` + `mixins/` were **removed**; `get_agent_by_name(<any-name>)` returns the unified Kryon agent (skills subsume the static agents). Remaining files are SUPPORT only: `base.py` (model factory + `chat_model_cls`), `toolsets.py`, `guardrails.py`, `lazy_handoff.py`, `scope.py`, `tool_restrictions.py`, `network_policy.py`, `codeagent.py`. `/agent select` now resolves to unified.
- **`tools/`** — 204+ tool implementations by kill-chain category. Agents bind to categories/tools rather than individual files.
- **`server/`** — FastAPI application (`app.py`) with `routes/`, `auth/`, `middleware/`, JWT/RBAC. 136 endpoints.
- **`repl/` + `tui/` + `cli/`** — User interfaces. CLI is `kryon` entry point. Commands in `repl/commands/`:
  - `/skill` (list/show/search/import/reload) — manage playbooks
  - `/experiences` (list/show/search/close) — manage learning
  - `/flush`, `/compact`, `/memory`, `/agent`, etc.
- **`knowledge/`** — RAG (**APAGADO** por default — ver cross-cutting rules). ExploitDB, NVD, GitHub writeups + ChromaDB. Embeddings locales vía sentence-transformers si se reactiva.
- **`compliance/`** — frameworks (PCI-DSS, HIPAA, SOC2, NIST 800-53, ISO 27001, GDPR, OWASP, **CIS Controls v8.1**, MITRE ATT&CK). CIS Controls v8.1 (153 safeguards / 18 controls) live in `compliance/cis_controls.py` (catalog loaded from `cis/catalog/cis_controls_v8.1.yaml`, validated 18/18 vs the PDF's IG tables) + `cis/cis_controls_crosswalk.py` (deterministic AUTO coverage derived from existing checks; governance safeguards reported MANUAL). Audit via `run_compliance_audit(framework="cis-controls")`. Distinct from the per-OS CIS *Benchmarks* under `cis/frameworks/`.
- **`intelligence/`** — Threat-intel + the **reflective intel pipeline** (FASE 1/2/6) that closes the THM-bench pwn gap. Three pure, banca-safe modules thread structured offensive context through the reflective loop so the model pipelines a chain instead of re-issuing broad queries:
  - **F1 — `fact_extractor.py`**: regex-parses the FULL tool output (before `micro_compact` truncates it to ~3-9 lines) into `ExtractedFacts` (users, domains, hashes, IPs, FQDNs). Injected into every reflection turn so the model can enumerate what it would otherwise never see.
  - **F2 — `exploit_chain_planner.py` (G3)**: ordered rules over `ExtractedFacts` + tool history; each rule encodes one canonical offensive step (e.g. users + domain → `GetNPUsers.py -no-pass`) and emits a concrete `NextActionRecommendation` (exact tool + args) injected as "🎯 Next action recommendation". FASE 11.P added auth-chain + privesc rules. Rules abstain unless their precondition is expressible from facts alone (conservative). FASE 9.A loads distilled YAML rules lazily.
  - **F6 — `planner_runtime.py`**: `ContextVar` bridge so the `execute_planner_directive` function_tool (called from the LLM tool loop) can reach the `accumulated_facts`/`tool_history` that live inside `run_with_reflection`. FASE 11.Q forces `tool_choice="required"` when directive confidence ≥ 0.92.
  - **`source_review.py` — Mythos-style source-review harness** (vuln-research line). Points a reasoning model (default `Kryon-MOE-35B`) at a local code tree and reviews it file-by-file by pure reasoning (like Anthropic's Mythos on Firefox: 271 vulns, no fuzzing), then expands via *variant analysis* (found a sink once → grep the tree, review those sites too). Orchestration is pure/testable (enumerate → triage-by-sink-density → review top-N → variant-expand → dedup → rank); the LLM is isolated behind the injectable `Reviewer` interface (`LocalReviewer`, OpenAI-compat). Findings convert to `engage.Finding` (`needs_verification=True`). Wired into `kryon investigate <code_path>` (code_sast hybrid phase) with `--sast-max-files`. Verified live: flagged CWE-78 + CWE-89 in a demo file in ~25s. `KRYON_SOURCE_REVIEW_MODEL` overrides the model.
  - Other modules: `mitre.py`/`mitre_navigator.py` (ATT&CK layers), `cve_enrichment.py`, `ioc.py`, `threat_feeds.py`, `tool_templates.py`, `graph_formatter.py`, `distillation.py`.

### Important cross-cutting rules

- **Runtime — llama.cpp local (no Ollama)**: el LLM principal corre en el
  servicio `llama-server` (`ghcr.io/ggml-org/llama.cpp:server-cuda`) del
  `docker/docker-compose.kali.yml`. **Modelo default: `gpt-oss-20b`** (OpenAI
  open MoE, 21B-A3.6B, MXFP4, 11.3 GB) — reemplazó al Qwen3.6-35B-A3B porque en
  el bench SAST CyberGym dio **1/3** (detección tool-driven real de Log4Shell
  CWE-502) vs **0/3** del 35B (que loopea `run_command` sin progresar). Para un
  agente ofensivo agentic, la confiabilidad de tool-use le gana al score de
  code-completion. Se sirve bajo el **alias `Kryon-MOE-35B`** (`-a`) para que el
  resto del stack (`KRYON_MODEL`, el turn-bump de reasoning-model "moe", el parser
  Harmony content-based F162) siga andando sin cambios. Flags (compose real):
  `--n-cpu-moe 12 -ngl 99 -fa on -c 40960 -n 2000 --temp 0.3 --jinja`
  (≈ **8.4 GB VRAM** de 12, ~3.5 GB headroom, ~27 tok/s). El GGUF del 35B
  (`qwen36-35b-a3b-q4kxl.gguf`) sigue en el volume para A/B benching — flipear
  `-m` lo reactiva (con `--n-cpu-moe 26 -c 24576`, ~42 tok/s, ver historial). El
  GGUF se reusa del volume externo `hermes-llamacpp-cache` (`:ro`). **Solo un llama-server a la vez en 12 GB VRAM** — parar el
  contenedor externo `hermes-llamacpp` (proyecto hermes-agent, mismo GGUF)
  si está activo, o habrá OOM. Config efectiva: el bloque `environment:`
  del compose (`OPENAI_BASE_URL=http://llama-server:8080/v1`,
  `KRYON_MODEL=Kryon-MOE-35B`, `KRYON_LOCAL_LLM=true`) **pisa** a
  `.env.docker`. Modelos secundarios (triage/narrator/RAG) caen al principal.

- **Performance del MoE local (por qué se sentía lento vs hermes)**: con
  expertos parcialmente en CPU, prefill y generación van a ~20-32 tok/s. El
  foot-gun era `-n 8000`: un turno verboso/CoT generaba 8000 tokens (~245s), y
  ese response inflaba el historial → cada prefill posterior procesaba 8K+
  tokens (~431s). Cascada. Bajado a `-n 2000` (acota el turno + frena la bola
  de nieve). **El chunk timeout del reflective runner** (`KRYON_CHUNK_TIMEOUT_S`)
  ahora default 900s bajo `KRYON_LOCAL_LLM` (vs 180s remoto) y nunca dispara
  antes del wall budget — el 180s viejo mataba el loop antes de que el MoE
  generara nada. Para runs locales reales: budgets generosos
  (`KRYON_WALL_BUDGET_S` 1800+); el camino determinista (pre_hooks) es el
  rápido/confiable. Para velocidad interactiva → DeepSeek (remoto; el modelo
  nativo default lo soporta). Hay ~4.4 GB de VRAM libre: bajar `--n-cpu-moe`
  offloadea más a GPU = más rápido (a costa de VRAM).

- **Model layer — native AsyncOpenAI is the DEFAULT (no litellm)**: el runtime
  es 100% OpenAI-compatible (Qwen local + DeepSeek), así que el modelo default
  es `sdk/agents/models/openai_native.py` (`OpenAINativeModel`), que llama al
  cliente `openai` directo — sin el branching per-provider/drop_params/prefijo
  `openai/` de litellm. `agents/base.chat_model_cls()` lo selecciona;
  `KRYON_USE_LITELLM=true` es el escape-hatch que restaura el modelo litellm
  (`openai_chatcompletions.py`, ahora no-default). El tracing del SDK ya **no
  llama a casa** (no postea a OpenAI con endpoints locales/keys placeholder).

- **Tool-calling local**: el MoE emite `tool_calls` nativos vía `--jinja`
  (validado en vivo por ambos modelos). `KRYON_LOCAL_LLM=true` activa parsers
  robustos. `KRYON_FORCE_TOOL_TURNS=8` fuerza tool-use los primeros N turnos.
  `is_reasoning_model()` (marker `moe`) auto-sube el cap de turnos por fase
  5→8 (`tools/autonomous/pentest_planner.py`, override `KRYON_PHASE_TURNS`).
  El modelo litellm (escape-hatch) conserva los parsers tolerantes + el
  fallback JSON-in-content como red de seguridad.

- **RAG retrieval REMOVIDO**: el corpus RAG estaba infrautilizado (94%
  duplicado, `query_knowledge_base` con 0 llamadas reales). Las tools de
  retrieval (`query_knowledge_base`, `search_vulnerabilities`,
  `recall_similar_experiences`, `query_similar_findings`, `query_memory`,
  `add_to_memory_*`) + sus archivos (`tools/knowledge/rag_tools.py`,
  `tools/misc/rag.py`) + el filtro `RAG_TOOLS` de `tool_budget` fueron
  **borrados**. **Se MANTIENE** el paquete `knowledge/` (tiene piezas vivas:
  `exploitdb_scraper`→cve_enrichment, `cve_corpus`→zero-day hunter + `/corpus`,
  `datasets`→cve_correlator) y el ChromaDB del learning-store (persistencia
  de experiences/findings; gated por `KRYON_EMBEDDING_BASE_URL`).

- **CVE hallucination guard + applicability gates**: `kryon update-cve-cache
  --all` puebla `~/.kryon/nvd_cache/cves.txt`; con `KRYON_CVE_CACHE_REQUIRED=true`
  se descartan findings cuyo CVE ID nunca se publicó (F151/F171). Las gates
  `kryon.validation.cve_applicability` (`KRYON_CVE_APPLICABILITY`) y
  `finding_applicability` (`KRYON_FINDING_APPLICABILITY`) descartan CVEs/findings
  que no matchean el stack del target (lab hints: juice_shop→node, dvwa→php,
  webgoat→java). Ambas cableadas en `_parse_agent_findings`.

- **Perfiles de engagement**:
  - **Banca-safe (default / compliance)**: `--temp 0.3`, `KRYON_PHASE_TURNS`
    sin setear (auto 8 reasoning / 5 instruct), pre_hooks solo en fases
    vuln-hunter. Reproducibilidad por hash.
  - **Active pentest** (targets autorizados: Juice Shop / DVWA / WebGoat /
    bug bounty **con autorización escrita**):
    ```bash
    KRYON_RED_TEAM=true
    KRYON_PHASE_TURNS=10
    ```
    Desbloquea el stack de detección activa: nuclei + nikto + sqlmap pre_hooks
    (`pre_hook_output_processor` de-noisa la salida y fuerza conversión de
    evidencia), broader reasoning budget, módulos de evasión. Solo contra
    targets con autorización escrita.

- **LiteLLM without `[proxy]`** — uvloop is not supported on Windows; do not re-add the proxy extra to `pyproject.toml`.
- **`openinference-instrumentation-openai`** is Python-version-gated (`< 3.14`) under the `tracing` extra.
- **Optional extras**: `voice`, `viz`, `tracing`, `rag`, `server`, `tui`, `reporting`, `orchestration`, `dev`.
- **Ruff per-file ignores** are deliberately loose for `agents/`, `tools/`, `repl/`, `sdk/`, `knowledge/`, `intelligence/`, `reporting/`, `server/`. Check `[tool.ruff.lint.per-file-ignores]` before "fixing" E501/E402/B904/B008 in those trees.
- **`mypy` `ignore_errors`** covers `kryon.tools.*`, `kryon.agents.*`, `kryon.knowledge.*`, `kryon.repl.*`, `kryon.cache.*`, `kryon.cli*`, and much of `kryon.sdk.agents.*`. Type-level work should target modules *outside* that override list.
- **Tests mirror the package**: `tests/<subsystem>/...`. Top-level integration/smoke tests exist too.

### Configuration

**Central config (`kryon/config/settings.py`)**: `KryonSettings` (frozen
dataclass) is the single source of truth for the core config (model, LLM
endpoint, agent/exec profile, timeouts, paths). Read it via
`from kryon.config import settings; settings()` instead of re-deriving
`os.getenv(..., "<default>")` defaults — that duplication caused drift.
`settings(refresh=True)` re-reads env (CLI sets env from args before building
the agent). Run **`kryon config`** to dump the effective config (API key
masked). Migration is incremental: `agents/base.get_default_model` already
reads it; other call sites adopt it over time. Feature-specific flags (fire
gates, nmap timing) stay where they're read.

Runtime config via env vars (see `docker/.env.docker`):

```bash
KRYON_MODEL=Kryon-MOE-35B          # MoE Qwen3.6-35B-A3B vía llama-server (llama.cpp)
KRYON_LOCAL_LLM=true               # endpoint local OpenAI-compat: parsers robustos + usage patch
KRYON_FORCE_TOOL_TURNS=8           # forzar tool-use los primeros N turnos (LLM local)
KRYON_PHASE_TURNS=                 # F166: override cap turnos/fase (auto 8 reasoning / 5 instruct)
KRYON_REASONING_EFFORT=            # F184: low|medium|high. 'medium' ayuda conversión de evidencia
                                   # con pre_hooks activos; sin ellos causa CoT loops.
KRYON_CVE_CACHE_REQUIRED=          # F151/F171: 'true' descarta findings con CVE id no publicado
                                   # (poblar: kryon update-cve-cache --all)
KRYON_CVE_APPLICABILITY=           # F180: 'false' desactiva gate CVE-producto (default on)
KRYON_FINDING_APPLICABILITY=       # F183: 'false' desactiva gate de findings non-CVE (default on)
KRYON_DEBUG_PARSE=                 # F181.C: 'true' loguea cada decisión de finding-parse a JSONL
KRYON_AGENT_TYPE=kryon             # Unified agent (v2.x)
KRYON_UNIFIED=true
KRYON_MEMORY=false                 # RAG / experience store apagado
KRYON_STREAM=false                 # REPL no-streaming (estable)
KRYON_TOOL_BUDGET=static           # 'itr' = selección de tools por embeddings/turno (build index
                                   # primero). Default 'static' = skill-driven banca-safe.
# Double-gated live-probe tools (F87/F88/F90): env var AND fire=True requeridos;
# default unset = dry-run / candidates-only (sin red).
KRYON_BOLA_FIRE=  KRYON_GRAPHQL_FIRE=  KRYON_FAPI_FIRE=  KRYON_RETEST_FIRE=  KRYON_BRAND_FIRE=
KRYON_RETEST_ALLOW_MUTATIONS=      # 'true' opta a replay POST/PUT/PATCH/DELETE (default GET-only)
# Scan throttling (F195 LLM tools / F196 engage CLI). Banca-safe; -T en args= siempre gana.
KRYON_NMAP_TIMING=                 # nmap -T0..T5 (banca-safe T2)
KRYON_NMAP_MIN_RATE=               # nmap --min-rate (banca-safe 50)
KRYON_NMAP_MAX_PARALLELISM=        # nmap --max-parallelism (banca-safe 10)
KRYON_NUCLEI_RATE_LIMIT=           # nuclei rate_limit (default 150, banca-safe 50)
KRYON_NUCLEI_BULK_SIZE=            # nuclei bulk_size (default 25, banca-safe 10)
KRYON_NUCLEI_CONCURRENCY=          # nuclei concurrency (default 25, banca-safe 10)
```

## `kryon investigate` — open-ended ReAct loop (F203)

Además de `kryon engage` (compliance-driven, plan-based) y `kryon repl`,
v2.x tiene `kryon investigate` (F203.A): un entry point ReAct
("Observation → Reflection → Decision → Action → Verification") para
queries open-ended tipo "audita esta URL" o "qué CVEs aplican a nginx 1.18".

```bash
# Default passive mode (banca-safe, solo web_fetch_smart + RAG queries)
kryon investigate "audita https://target.com"
kryon investigate --url https://target.com
kryon investigate ./local/path/   # SAST exploratorio sobre código local

# Active mode (requiere autorización escrita del target)
kryon investigate "active sqli pentest contra https://target" --active
```

### Stack F203 (key pieces)

- **Entry + tools** (F203.A/B/D/E): `kryon investigate` CLI; `web_fetch_smart` (GET-only HTTP, ≤500KB, ≤3 redirects, HTML→markdown — banca-safe); on-demand `request_skill(topic)` + `tool_search(query)` for RAG-style skill/tool discovery.
- **`ReflectiveRunner`** (F203.C): injects a self-critique turn every N turns (default 4), detects stuck patterns (same tool 3×) and breaks the loop before burning wall-budget. Writeback to the learning loop on close (F203.F).
- **Hybrid mode** (F203.M/N): `_run_deterministic_phase(url)` runs the engage deterministic detectors (11: HTTP, cookies, MySQL, SSH, BGP, simplehttp, DNS opt-in, SMB anon opt-in) BEFORE the LLM, injecting findings as confirmed ground truth (web bench recall 25%→100%). Flags `--ssh-user/pass/key`, `--db-user/pass`, `--include-dns-checks`, `--include-smb-checks`.
- **Wired registries**: pre_hooks in 6 deterministic skills (F203.O); 15 DFIR/validation tools — `validate_{detection,finding,rce,sqli,xss,auth_bypass}`, `calculate_mitre_coverage`, … (F203.R); 21 red-team tools behind `KRYON_RED_TEAM=true` (registry 104→125, F203.T). `guide_scorer.score_draft()` feeds `auto_pipeline` (`.eval.json` `guide_score`, threshold 0.6, F203.S).
- **`imperative_findings_suffix(evidence_present)`** (F203.AO.B): when no pre_hook returns evidence, the suffix flips from "NO re-invocás nuclei/sqlmap" to "DEBÉS continuar con tools manuales, NUNCA emitas []". Fixed gpt-oss returning `[]` on empty pre_hooks (HTB bench 0/7 → 4/7 PWN via `web_fetch_smart`+`run_command`).
- **Explicit-keyword active skills** (F203.V/W/X/AB/AF/AG) — 14 skills, priority=3, deterministic pre_hook. Cover OWASP Top-10 + API + JS-ecosystem:

  | Skill | Keyword trigger | Pre_hook | CWE root |
  |-------|-----------------|----------|----------|
  | web-pentest-sqli-active | "active sqli pentest" | F191 sqlmap 10-endpoint | CWE-89 |
  | web-pentest-xss-active  | "active xss pentest"  | nuclei -tags xss,dast | CWE-79 |
  | web-pentest-idor-active | "active idor pentest" | idor_probe 96 combos | CWE-639 |
  | web-pentest-ssrf-active | "active ssrf pentest" | nuclei -tags ssrf | CWE-918 |
  | web-pentest-rce-active  | "active rce pentest"  | nuclei -tags rce,cmdi | CWE-78/77 |
  | web-pentest-csrf-active | "active csrf pentest" | curl headers + nuclei csrf,cors | CWE-352 |
  | web-pentest-path-traversal-active | "active lfi pentest" | nuclei -tags lfi,traversal | CWE-22 |
  | web-pentest-deser-active | "active deser pentest" | nuclei -tags deserialization,jndi | CWE-502 |
  | web-pentest-auth-bypass-active | "active auth bypass pentest" | nuclei -tags auth-bypass,jwt + curl admin endpoints | CWE-287/306 |
  | web-pentest-file-upload-active | "active file upload pentest" | nuclei -tags file-upload + curl OPTIONS | CWE-434 |
  | web-pentest-xxe-active | "active xxe pentest" | nuclei -tags xxe,xml | CWE-611 |
  | web-pentest-nosql-active | "active nosql pentest" / "active mongo injection" | nuclei -tags nosql,injection | CWE-943 |
  | web-pentest-graphql-active | "active graphql pentest" | nuclei -tags graphql,api + curl endpoint discovery | CWE-200/862 |
  | web-pentest-prototype-pollution-active | "active prototype pollution pentest" | nuclei -tags prototype-pollution | CWE-1321 |

  Estas skills NO activan con keywords genéricos ("sqli", "xss", "idor",
  "xxe", "graphql"); solo con la frase explícita "active X pentest" (o
  "fire X probe", "pentest activo X"). Aprendizaje F203.U: pre_hooks
  costosos en skills de keyword amplio regressionan el bench wall budget
  (33% → 0% pwn). `maybe_run_pre_hooks` también corre desde `kryon
  investigate` (F203.Z.B), necesario para que estas active skills disparen.

### Bench harnesses

- **docker/vulnerable-lab** — 3 containers planted (web/ssh/db) con CWEs
  conocidos. `docker compose -f docker/vulnerable-lab/docker-compose.yml up`.
  Scoreboard via `scripts/lab_scoreboard.py --transcript X --target {web,ssh,db,juice_shop}`.
- **HTB walkthroughs** — `tests/benchmarks/htb_style/walkthroughs/*.json`
  con expected chains. **7 ready** (post F203.AH), 30 total. CLI:
  `python -m scripts.htb_bench.cli --all --platform htb --status ready`.
  Las 7 ready coinciden 1:1 con las active skills:
  portswigger-{sqli-where-clause, xss-dom-1, idor-1, os-cmd-1,
  ssrf-basic, csrf-1, xxe-1} → web-pentest-{sqli, xss, idor, rce,
  ssrf, csrf, xxe}-active. Bench end-to-end activable con
  `KRYON_RED_TEAM=true` env.
- **F203.BA — HTB bench fidelity (reasoning ≠ real exploit)**: el
  `ready_url` apunta a la docs page de PortSwigger (`portswigger.net/
  web-security/...`), NO al lab dinámico (que requiere PortSwigger
  Academy login + session). Los `flag_pattern` lenient (`Congratulations|
  carlos.*password|document.write`) matchean texto de la docs o del
  reasoning del modelo, NO proof-of-exploit. Pwn rate 4/7 reproducible
  mide **capacidad de reasoning sobre la documentation**, no exploit
  vivo. Para bench de exploit real → docker/vulnerable-lab (lab live)
  o Juice Shop (port 3003, container local).
- **OWASP Juice Shop** — `docker start juice_shop` (port host 3003 → 3000
  guest). Ground truth de 10 CWEs canonicos (CWE-89/79/639/285/200/22/352/915/1004/319)
  en `scripts/lab_scoreboard.py` target=juice_shop.
- **CyberGym SAST** — `python -m scripts.cybergym.cli` corre heartbleed
  + log4shell + struts2-ognl como SAST contra source pre-cloned.
- **Vulhub walkthroughs** — `tests/benchmarks/vulhub/walkthroughs/*.json`
  (nuevo, WIP): expected chains contra los labs de `vulhub/vulhub`. Primer
  caso `struts2-s2-001.json`. Mismo formato JSON que el HTB bench.

### Configuración default de investigate (banca-safe vs active)

| Modo | Flag | Tools accesibles | Pre_hooks ejecutan |
|------|------|------------------|--------------------|
| **PASSIVE** (default) | sin --active | web_fetch_smart, RAG queries, DNS lookup | Solo los hybrid-mode deterministicos (F203.M, no las active skills) |
| **ACTIVE** | `--active` | + nmap, nuclei, sqlmap, etc. | TODOS (incluyendo F203.V-AB explicit-keyword skills) |

Para tools red-team (jwt_crack, hydra, ffuf, playwright_test_xss):
`KRYON_RED_TEAM=true` env var adicional.

## Multi-target POC workflow (F196)

Para POCs sobre un segmento entero (no un solo host), el flujo
soportado end-to-end es:

```bash
# 1. Encolar todos los hosts vivos del segmento (con throttle banca-safe).
KRYON_NMAP_TIMING=T2 KRYON_NMAP_MIN_RATE=50 \
  kryon discover --subnet 10.x.x.0/24 --queue-add --output disc.json

# 2. Drenar la cola invocando `kryon engage` por cada host.
kryon queue process \
  --concurrency 1 \
  --framework pci_dss \
  --orchestrated \
  --auto-approve \
  --client britimp-internal \
  --out ./poc-reports
```

`kryon queue process` (F196):
- Default concurrency 1 (banca-safe serial). Operador puede subir con
  `--concurrency N` para acelerar.
- `--limit N` corta despues de N items (util para POC en jornadas).
- Items que fallan quedan en status `failed` para triage manual (no
  hay auto-retry — silent retries pueden disparar acciones destructivas
  duplicadas).
- Cada item escribe a `<out>/<item_id>/` con `--engagement-id` pasado
  al child `kryon engage`.
- `KRYON_ENGAGE_BIN` env permite override del binario hijo (util en
  containers donde `kryon` no esta en PATH).

`engage` y `discover_subnet` NO soportan CIDR como target directo en
el modo single-host. El flujo `discover --queue-add` → `queue process`
es la unica via correcta para barrer un segmento.

## Docker / K8s

- `docker/docker-compose.kali.yml` + `docker/docker-compose.override.yml` is the dev stack (Kali + llama-server + Kryon).
- `helm/` and `k8s/` hold production manifests.
- The override adds memory limits (12G kryon) and removes Claude Code CLI bind mounts.

## Conventions specific to this repo

- Conventional commits (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `perf:`, `ci:`).
- Do **not** commit `.kryon/`, `workspaces/`, `logs/`, `nohup.out`, `ci/`, or `tools/cut_the_rope/` — all excluded from the hatch build.
- When adding capabilities in v2.x: **prefer a skill** (`.md` in `skills/playbooks/`) over a new Python agent.
- Banking skills go in `skills/playbooks/banking/`. Imported upstream skills go in `skills/playbooks/imported/`. Core skills at the top level.
- When editing markdown (prompts or skills) on Windows: ensure LF line endings (Git will warn about CRLF).
- **MSYS path conversion gotcha (Windows + Git Bash + Docker)**: env vars passed via
  `docker exec -e KRYON_AUDIT_LOG_PATH=/home/...` get rewritten by Git Bash before
  reaching the container, ending up as `C:/Program Files/Git/home/...` and the
  default-relative audit log lands at `/workspace/C:/Program Files/Git/home/...`
  inside the container. Workarounds: (a) use PowerShell instead of Git Bash for
  any `docker exec -e KRYON_*_PATH=...` call, (b) prefix the command with
  `MSYS_NO_PATHCONV=1`, or (c) let the default kick in
  (`default_log_path()` → `/workspace/.kryon/audit/<engagement>.jsonl`). The
  Linux/macOS path is fine; this is a Windows-only quirk.

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
| `dvr-audit.md` | **recon-only template (F197)** | DVR / NVR / IP camera audit. v1 cubre fingerprinting (Dahua / Hikvision / ONVIF / generic-DVR) + nuclei CVE templates conocidos (CVE-2017-7921 Hikvision, CVE-2021-33044/45 Dahua, CVE-2021-36260 Hikvision RCE). Tools nuevos: `dvr_fingerprint` (HTTP markers read-only) + `onvif_discover` (WS-Discovery UDP 3702 multicast). NO incluye checks deterministicos custom todavía — v2 post-POC con ground truth de los 3 segmentos DVR de Britimp. |
| `voip-asterisk-audit.md` | **production-capable (F198)** | Asterisk / FreePBX audit. 8 checks deterministicos (VOIP-1.1..VOIP-3.3) cableados a `run_compliance_audit(framework="asterisk")`: anonymous register / AMI default secret / allowguest / alwaysauthreject / AMI WAN exposure / SRTP / SIP-TLS / version currency. Tool nueva `asterisk_discover` (SIP OPTIONS + AMI banner). Reproducibility hash estable. Targets: PBX Britimp TORRE-VOIP 172.18.202.0/24 + futuros engagements VoIP. |
| `windows-server-audit.md` | **production-capable (F199)** | Windows Server + workstation audit via WinRM (F36 runner). 15 checks deterministicos (WIN-1.1..WIN-4.2) cableados a `run_compliance_audit(framework="windows")`: SMBv1 / LSA Protection / Print Spooler en DC (PrintNightmare) / Defender RTP / firewall dominio / BitLocker / LLMNR / WSUS internet / GPO refresh / LAPS / audit policy / RDP NLA / UAC / Remote Registry / EDR detection. Pre-requisito: WinRM habilitado (puerto 5985/5986). Targets: Britimp USR segments + cualquier Windows Server en SVR. |
| `tomcat-audit.md` | **production-capable (F200.A)** | Apache Tomcat audit. 8 checks deterministicos (TOMCAT-1.1..TOMCAT-2.4) cableados a `run_compliance_audit(framework="tomcat")`: version EOL (Tomcat 7/8 sin patches) / AJP 8009 Ghostcat CVE-2020-1938 / Manager + Host Manager exposure / error page version leak / Server header disclosure / /docs + /examples deployed. Tool nueva `tomcat_recon` (version + endpoints + AJP probe). Read-only HTTP/TCP probes, sin SSH. Override puerto via `KRYON_TOMCAT_PORT`. Surfaceado en POC Britimp contra .11 (Tomcat 7.0.34 EOL marzo 2021). |
| `cis-controls-v8.1.md` | **production-capable (subset AUTO) + template (governance/MANUAL)** | CIS Critical Security Controls v8.1 (18 controles / 153 salvaguardas). Catálogo extraído del PDF oficial español y validado 18/18 contra las tablas de IG (`scripts/extract_cis_controls_v81.py` → `cis/catalog/cis_controls_v8.1.yaml`; incluye función **Govern** ×25 e **Documentation** asset ×23). `run_compliance_audit(framework="cis-controls")` corre el crosswalk (`cis/cis_controls_crosswalk.py`): ~32 salvaguardas técnicas se derivan AUTO de los checks existentes (PCI/AD/FGT/PVE/UNF/WIN/TOMCAT/VOIP/OT, fail-closed) en 12 de los 18 controles; el resto (gobierno/proceso: controles 1, 2, 14, 15, 17, 18) se reporta MANUAL (evidencia de entrevista/documental, nunca PASS automático). PDF via `generate_compliance_pdf(framework="cis-controls")`. Distinto de los CIS *Benchmarks* per-OS en `cis/frameworks/`. |

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
