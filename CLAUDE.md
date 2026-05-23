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

- **Ollama-first**: Two production models are available. The default for new
  engagements is **`kryon-gpt-oss`** (F162-F170, OpenAI gpt-oss-20b Q4_K_M
  ~10.8 GB + the official Harmony chat template). It detected 9 real
  findings + 1 false positive on the OWASP Juice Shop bench (SATISFIED in
  225s) vs `kryon-14b`'s 1 INFO placeholder (NOT_MET in 215s) under the
  same F165-F168 stack. The fallback is **`kryon-14b`** (Modelfile: `FROM
  qwen3:14b` + `num_ctx 32768` + `num_predict 4096`) for cases where
  `gpt-oss` reasoning is too verbose or the operator wants tighter
  determinism. Both fit in 12 GB VRAM. Many fixes live in
  `sdk/agents/models/openai_chatcompletions.py` to make tool calling
  reliable with local models (tool name normalization, hallucination
  tolerance, schema fix, tool_choice forcing, F162 Harmony parser).
- **gpt-oss Harmony stack (F162-F170)**:
  - F162: `sdk/agents/models/harmony_parser.py` translates Harmony
    `<|channel|>... to=NAMESPACE.FUNC ...<|message|>{...}<|call|>` tool
    calls to OpenAI ``tool_calls`` arrays (Ollama doesn't do it for us).
  - F163: `models/Modelfile.kryon-gpt-oss` ships the official Harmony
    template (TypeScript signatures + developer message) so the model
    respects real tool names instead of inventing `whatweb(host,port)`.
  - F166: reasoning models (gpt-oss, R1, o1/o3, deepseek-r1,
    Foundation-Sec-Reasoning) auto-bump per-phase `max_turns` from 5 to 8
    via `is_reasoning_model()` in `tools/autonomous/pentest_planner.py`.
    Override with `KRYON_PHASE_TURNS=<int>`.
  - F167: `Reasoning: low` is the in-template default for `kryon-gpt-oss`
    (canonical Harmony defaults to medium). Operator can override
    per-request via the Ollama `think_level` parameter.
  - F164: scan-cache decorator now skips failure outputs (binary missing,
    `[KRYON_TOOL_ERROR]`, empty), so one failed run doesn't poison the
    12-hour cache. Same commit pins nuclei v3.8.0 in `Dockerfile.kali`
    and downloads templates at build time.
  - F171: `kryon update-cve-cache --year YYYY|--years A-B|--all`
    populates `~/.kryon/nvd_cache/cves.txt`. With
    `KRYON_CVE_CACHE_REQUIRED=true`, F151 filters out hallucinated CVE
    IDs that pass format check but were never published.
- **gpt-oss anti-FP + active-detection stack (F178-F189)** —
  the F178-F189 sprint took the F170 bench (10 findings but 1 disguised
  CVE FP, single SATISFIED) to F189's reproducible 3/3 SATISFIED with
  avg=18 findings, 0 FPs, and 2/3 runs emitting CWE-89 real SQLi via
  sqlmap pre_hook.
  - F178/F179: `Modelfile.kryon-gpt-oss` parameters tuned to
    `num_ctx 16384` + `temperature 0.3`. The F170 bench peaked at
    `ctx 4% OK`, so 16K is 5× the working-set ceiling and frees
    ~0.5 GB VRAM (94% → 85% usage, 12% → 8% CPU spillover).
    `temperature 0.3` collapses run-to-run variance (n=3 with
    temp 1.0 = σ 2.83 → temp 0.3 = σ 0.0).
  - F180+F180.B+F181.C: `kryon.validation.cve_applicability` is wired
    into `_parse_agent_findings` and drops CVEs whose
    products don't apply to the target stack. Known lab targets get a
    curated host hint (juice_shop → node.js, dvwa → php, webgoat →
    java) that's authoritative over narration tokens — closes the
    self-confirmation loop where a JAMon CVE message would feed
    `jamon` back into the stack.
  - F183: `kryon.validation.finding_applicability` extends the gate to
    non-CVE-shaped rule_ids. After F180+F181.C the model started
    relabelling the JAMon FP as `WEB-XSS-001` to bypass the CVE-only
    filter; F183 scans `message`+`evidence` for product keywords
    (jamon, struts, log4j, ...) and drops the FP regardless of
    rule_id shape. `KRYON_FINDING_APPLICABILITY=false` to disable.
  - F185-F185.C: `pre_hooks:` wired into `engage.py:_run_phase`
    (previously only fired from the REPL flow). Each phase now
    re-matches skills against `phase_name + objective + target` and
    runs the matched skills' pre-hooks before the LLM. `vuln-hunter`
    keywords broadened to include `sqli`, `xss`, `rce`, `find`,
    `injection`, etc. so the bench objective `find SQLi or XSS or
    RCE` actually activates the skill.
  - F186-F186.B: `kryon.skills.pre_hook_output_processor` de-noises
    nuclei (severity-prioritized top-N) and nikto v2.6 (bracketed-id
    `+ [NNNNNN] /path:` regex) output before it reaches the model.
    Plus an imperative Spanish suffix: *"ACCIÓN OBLIGATORIA:
    convertí CADA línea ... NO re-invocás nuclei/nikto/sqlmap."*
    Forced the model to convert evidence instead of re-running tools.
  - F187-F187.B: `vuln-hunter` ships three pre_hooks today:
    `nuclei_scan(critical,high,medium)` + `nikto -Tuning x6 -maxtime 60`
    + `sqlmap` via the Python escape hatch
    (`./pre_hooks/sqlmap_rest_login_hook.py:run`). The Python form is
    required because the declarative `tool: run_command` argument
    validator (SSTI-guarded) rejects `{...}` literals — sqlmap's
    JSON POST body `{"email":"test","password":"test"}` tripped it.
    On Juice Shop the sqlmap hook detects the JSON `email` parameter
    as boolean-based blind SQLi against SQLite in ~25s, model emits
    CWE-89 finding.
  - F184: `KRYON_REASONING_EFFORT` env (`low|medium|high`) propagates
    to `model_settings.reasoning_effort` via `sdk/agents/run.py`. F189
    bench proved that `medium` reasoning is only contraproductive when
    the model has to DECIDE which tools to invoke. With pre_hooks
    deterministicos (F185-F187), the model only converts evidence and
    medium reasoning helps that conversion — n=3 went from 2/3 → 3/3
    SATISFIED + CWE-89 from 1/3 → 2/3.
- **Engagement configuration profiles (banca-safe vs active pentest)**:
  - **Default (banca-safe / compliance audits)**: keep Modelfile
    defaults — `Reasoning: low`, `KRYON_PHASE_TURNS` unset (auto 8 for
    reasoning models, 5 for instruct), pre_hooks fire only for
    vuln-hunter-activated phases (won't fire for pure compliance
    runs).
  - **Active pentest (authorized targets: Juice Shop / DVWA / WebGoat
    / bug bounty with written authorization)**:
    ```bash
    KRYON_MODEL=kryon-gpt-oss
    KRYON_REASONING_EFFORT=medium
    KRYON_PHASE_TURNS=10
    KRYON_RED_TEAM=true
    ```
    This unlocks the full F185-F189 active-detection stack: nuclei +
    nikto + sqlmap pre_hooks, broader reasoning budget, evasion
    modules. Use only against targets the operator has written
    authorization for.
- **LiteLLM without `[proxy]`** — uvloop is not supported on Windows; do not re-add the proxy extra to `pyproject.toml`.
- **`openinference-instrumentation-openai`** is Python-version-gated (`< 3.14`) under the `tracing` extra.
- **Optional extras**: `voice`, `viz`, `tracing`, `rag`, `server`, `tui`, `reporting`, `orchestration`, `dev`.
- **Ruff per-file ignores** are deliberately loose for `agents/`, `tools/`, `repl/`, `sdk/`, `knowledge/`, `intelligence/`, `reporting/`, `server/`. Check `[tool.ruff.lint.per-file-ignores]` before "fixing" E501/E402/B904/B008 in those trees.
- **`mypy` `ignore_errors`** covers `kryon.tools.*`, `kryon.agents.*`, `kryon.knowledge.*`, `kryon.repl.*`, `kryon.cache.*`, `kryon.cli*`, and much of `kryon.sdk.agents.*`. Type-level work should target modules *outside* that override list.
- **Tests mirror the package**: `tests/<subsystem>/...`. Top-level integration/smoke tests exist too.

### Configuration

Runtime config via env vars (see `docker/.env.docker`):

```bash
KRYON_MODEL=kryon-gpt-oss          # F170 default: gpt-oss-20b Q4_K_M (10.8 GB)
                                   # 10 findings on Juice Shop bench (SATISFIED in 225s)
                                   # Fallback: kryon-14b (Qwen3-14B dense)
KRYON_PHASE_TURNS=                 # F166: override per-phase turn cap (default
                                   # 8 for reasoning models / 5 for instruct).
                                   # Set 10 for active-pentest profiles.
KRYON_REASONING_EFFORT=            # F184: low|medium|high override of the
                                   # Modelfile's Reasoning: setting. Default
                                   # (unset) = Modelfile value (kryon-gpt-oss
                                   # ships 'low'). Use 'medium' ONLY when
                                   # pre_hooks are active (F185+); without
                                   # them medium causes CoT loops (see F184).
KRYON_CVE_CACHE_REQUIRED=          # F151+F171: 'true' drops findings whose CVE
                                   # rule_id is NOT in ~/.kryon/nvd_cache/cves.txt.
                                   # Populate with: kryon update-cve-cache --all
KRYON_CVE_APPLICABILITY=           # F173/F180: 'false' disables the
                                   # tech-stack/CVE-product applicability gate.
                                   # Default (unset) = enabled — drops CVEs
                                   # whose products don't match target stack
                                   # (e.g. JAMon JSP CVE on Node.js target).
KRYON_FINDING_APPLICABILITY=       # F183: 'false' disables the non-CVE
                                   # applicability gate (scans message+evidence
                                   # for product mentions; drops e.g. a
                                   # WEB-XSS-001 finding citing JAMonAdmin.jsp
                                   # on a Node.js host). Default = enabled.
KRYON_DEBUG_PARSE=                 # F181.C: 'true' writes one JSONL line per
                                   # finding-parse decision to
                                   # .kryon/debug/parse_<engagement>.jsonl
                                   # for post-mortem of FP escape paths.
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
KRYON_FAPI_FIRE=                   # F87.4: 'true' enables live fetch of OpenID Connect Discovery
                                   # documents in validate_fapi tool. Same double-gate. Default
                                   # unset = pass discovery JSON via mode='from_json' (air-gap path).
KRYON_RETEST_FIRE=                 # F88: 'true' enables live HTTP in retest_finding tool
                                   # (HackerOne Retester pattern). Same double-gate as F87.
KRYON_RETEST_ALLOW_MUTATIONS=      # F88: 'true' opts in to replay POST/PUT/PATCH/DELETE
                                   # findings. Default GET-only — avoids accidental re-submission
                                   # of mutation-side findings (e.g. a transfer endpoint).
KRYON_BRAND_FIRE=                  # F90.1: 'true' enables live DNS resolution in typosquat_scan
                                   # tool. Same double-gate as F87/F88. Default unset = generate
                                   # candidates only (pure, no network).
KRYON_NMAP_TIMING=                 # F195/F196: override nmap timing (T0..T5).
                                   # F195 cubre el function_tool del LLM
                                   # (tools/reconnaissance/nmap.py). F196 extiende
                                   # la misma var al CLI directo: engage._run_nmap
                                   # y discovery.assets.discover_subnet (los dos
                                   # tenian -T4 hardcoded). Banca-safe / POC en
                                   # horario laboral: T2. Caller-supplied -T flag
                                   # in args= always wins (F195); el CLI hace
                                   # override duro si el env esta seteado (F196).
KRYON_NMAP_MIN_RATE=               # F195/F196: override --min-rate. F195 en
                                   # function_tool, F196 en engage CLI + discover
                                   # subnet. Banca-safe: 50.
KRYON_NMAP_MAX_PARALLELISM=        # F195/F196: --max-parallelism. Banca-safe: 10.
KRYON_NUCLEI_RATE_LIMIT=           # F195: override nuclei_scan default rate_limit=150.
                                   # Banca-safe: 50. Only applies if the caller
                                   # left the function-tool default in place.
KRYON_NUCLEI_BULK_SIZE=            # F195: override nuclei_scan default bulk_size=25.
                                   # Banca-safe: 10.
KRYON_NUCLEI_CONCURRENCY=          # F195: override nuclei_scan default concurrency=25.
                                   # Banca-safe: 10.
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

### Stack F203

- **F203.A** — `kryon investigate` CLI entry point.
- **F203.B** — `web_fetch_smart` tool: GET-only HTTP, max 500KB, max 3
  redirects, HTML→markdown extraction (script/style stripping). Banca-safe.
- **F203.C** — `ReflectiveRunner`: inyecta turn de auto-crítica cada N
  turns (default 4). Detecta stuck patterns ("re-invocando misma tool 3x")
  y rompe el loop antes de gastar wall-budget.
- **F203.D** — `request_skill(topic)` tool: skill discovery on-demand
  cuando el agent decide que necesita methodology no cargada.
- **F203.E** — `tool_search(query)` tool: agent puede descubrir tools
  no cableadas en su current registry (RAG-style discovery).
- **F203.F** — writeback al learning loop al cerrar la run (mismo path
  que `auto_extract` post-engage).
- **F203.M (Hybrid mode)** — `_run_deterministic_phase(url)` corre
  detectors deterministicos (engage.py `_check_http` / `_check_mysql`
  etc.) ANTES del LLM agent. Findings se inyectan al prompt como
  "ground truth confirmado, el LLM extiende con semanticos".
  - Web bench: recall 25% → 100% (4/4 CWEs ground truth)
- **F203.N** — wire de TODOS los detectores deterministicos de engage
  (11 detectors: HTTP, cookies, MySQL, SSH, BGP, Python simplehttp,
  DNS battery opt-in, SMB anon shares opt-in). Flags: `--ssh-user/pass/key`,
  `--db-user/pass`, `--include-dns-checks`, `--include-smb-checks`.
- **F203.O** — pre_hooks deterministicos en 6 skills: `ssl-audit`,
  `appsec`, `wordpress-audit`, `banking/{core-banking,swift-network,payment-gateway}`.
- **F203.R** — 15 DFIR/validation tools cableados al registry
  (validate_detection, validate_finding, validate_rce, validate_sqli,
  validate_xss, validate_auth_bypass, calculate_mitre_coverage, etc).
- **F203.S** — `guide_scorer.score_draft()` wired al `auto_pipeline`:
  sidecar `.eval.json` ahora incluye `guide_score` (relevance +
  naturalness), threshold 0.6.
- **F203.T** — 21 red-team tools cableados bajo `KRYON_RED_TEAM=true`
  gate (api_attacks, browser/Playwright, evasion analytical). Registry
  104 default → 125 con RED_TEAM.
- **F203.V/W/X/AB/AF/AG** — 14 "explicit-keyword" active skills,
  priority=3, pre_hook deterministico. Cubre OWASP Top-10 + API + JS-ecosystem:

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

  Estas skills NO activan con keywords genéricos ("sqli", "xss",
  "idor", "xxe", "graphql"). Solo con la frase explícita
  "active X pentest" (o equivalentes: "fire X probe", "pentest activo X").
  Aprendizaje F203.U: pre_hooks costosos en skills de keyword amplio
  regressionan el bench wall budget (33% → 0% pwn rate observado).
- **F203.Z.B** — pre_hooks integration en `investigate.py`. Antes solo
  `engage._run_phase` invocaba pre_hooks; ahora `maybe_run_pre_hooks`
  también corre desde `kryon investigate` (necesario para que las
  active skills F203.V-AB funcionen).
- **F203.Y** — dead code cleanup real: -15 archivos en `src/kryon/tools/`
  con 0 references anywhere (script: `scripts/dead_code_audit.py`).
- **F203.AO.B** — `imperative_findings_suffix(evidence_present)` bifurcado.
  Antes: el suffix imperativo `"NO re-invocás nuclei/sqlmap"` aplicaba
  siempre, incluso cuando el pre_hook devolvía vacío → gpt-oss terminaba
  con `[]` sin intentar tools manuales (HTB bench 0/7 pre-fix). Ahora:
  cuando ningún pre_hook devuelve evidencia (JSON `[]`/`{}` empty o
  string vacío), el suffix muta a `"DEBÉS continuar con tools manuales,
  NUNCA emitas []"`. Bench HTB n=7 post-fix: **4/7 PWN (57%)** —
  SQLi/XSS/RCE/XXE pwned con chain_match=100% via `web_fetch_smart` +
  `run_command` después del pre_hook empty.

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

Wrapper completo del POC: `scripts/poc_britimp_segmento.sh`.

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
