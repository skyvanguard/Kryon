# KRYON

```
██╗  ██╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗
██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║
█████╔╝ ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║
██╔═██╗ ██╔══██╗  ╚██╔╝  ██║   ██║██║╚██╗██║
██║  ██╗██║  ██║   ██║   ╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
```

<div align="center">

**Autonomous Cybersecurity Agent — Local-first, Skill-based, Self-improving**

*Compliance audit, pentest, DFIR & incident response from a single prompt.*

[![CI](https://github.com/skyvanguard/Kryon/actions/workflows/ci.yml/badge.svg)](https://github.com/skyvanguard/Kryon/actions/workflows/ci.yml)
[![Security Scan](https://github.com/skyvanguard/Kryon/actions/workflows/security-scan.yml/badge.svg)](https://github.com/skyvanguard/Kryon/actions/workflows/security-scan.yml)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-2.1.0_Skillforge-purple.svg)](CHANGELOG.md)
[![Skills](https://img.shields.io/badge/skills-106_playbooks-gold.svg)](#skill-system)
[![Tools](https://img.shields.io/badge/tools-348_function__tools-cyan.svg)](#architecture)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)

[Installation](#installation) · [Execution Modes](#three-execution-modes) · [Skill System](#skill-system) · [Architecture](#architecture) · [Banking Status](#banking-vertical--honest-status) · [POC Reality](#what-runs-today-poc-reality)

</div>

---

## What is KRYON?

KRYON is an **autonomous cybersecurity agent** focused on **compliance audits, authorized pentesting, and incident response** for the **financial-services sector (LATAM/Paraguay)**. It runs **locally** on a 12 GB-VRAM GPU using `Kryon-MOE-35B` (a `llama-server` / llama.cpp **alias** that, by default, serves **gpt-oss-20b** — an OpenAI MoE 21B-A3.6B in MXFP4, ~11.3 GB GGUF — which outperformed the original Qwen3.6-35B-A3B on the agentic tool-use bench), so **zero API cost** and **zero data leaving the engagement perimeter**.

Architecture is **skill-based**: instead of 33 static Python agents, there is one unified "Kryon" agent that dynamically loads **~106 markdown playbooks** based on target profile and operator intent. Critical detection paths run as **deterministic pre-hooks** (nuclei, nikto, sqlmap, fail2ban check, PCI-DSS validators, …) before the LLM ever gets control — the model **narrates evidence, it cannot skip the detector**.

### One prompt — full engagement

```
$ kryon investigate "audita https://target.com"

 ✶ Kryon [investigate · ReActLoop] · 3 skills matched
 ● pre_hook nuclei -severity critical,high,medium       → 7 templates fired
 ● pre_hook curl -I + CSP+HSTS+Cookies parse            → 3 missing headers
 ● web_fetch_smart https://target.com                   → tech: Apache 2.4.41 / WordPress 6.4
 ● reflection turn 4: "no findings on /wp-admin, pivot to /xmlrpc"
 ● run_command wpscan --url ... --enumerate vp,u        → 2 vuln plugins
 ● writeback_engagement → eng_3e03db5e (chain saved)

╭─ Kryon ─────────────────────────────────────────────────────╮
│ ## Security Assessment: target.com                          │
│ **Findings (HIGH=2, MED=3, LOW=1)** — full chain in report  │
│ CWE-89 SQLi blind boolean on /wp-content/plugins/wpforo     │
│ CWE-79 stored XSS on comment form (auth required)           │
│ Missing: HSTS, X-Frame-Options, CSP                         │
│ Recommendations: 5 actionable items, with rollback commands │
╰─────────────────────────────────────────────────────────────╯

✅ Experience saved + draft skill auto-written (~/.kryon/drafts/)
```

### At a Glance

| Component | Count |
|-----------|:-----:|
| Skill playbooks (`.md`) | **106** (42 core + 11 CWE + 4 banking + 5 OT + 40 imported + 1 zero-day) |
| `@function_tool` implementations | **348** across ~150 modules |
| CLI entry points | 19 subcommands |
| API endpoints (FastAPI) | 136 |
| Compliance frameworks | 9 (PCI-DSS, OWASP, NIST CSF, CIS, MITRE ATT&CK, SWIFT CSP, FAPI, HIPAA, SOC2) |
| Production-capable audit modules | 7 (PCI-DSS · Proxmox · FortiGate · Unifi · Asterisk · Windows Server · Tomcat) |
| Default model | `Kryon-MOE-35B` (alias; serves **gpt-oss-20b** MoE 21B-A3.6B MXFP4 ~11.3 GB by default) via llama.cpp |
| LLM runtime | `llama-server` (llama.cpp), tool-calling via `--jinja` |

### Core capabilities

- **Three execution modes** — `engage` (plan-driven compliance), `investigate` (ReAct loop), `queue process` (multi-target POC over a segment).
- **Deterministic pre-hooks** — YAML declarative + Python escape hatch. Critical detectors run before the LLM; model converts evidence, not invents.
- **Active-detection stack (F185-F189)** — nuclei + nikto + sqlmap pre-hooks behind `KRYON_RED_TEAM=true`. OWASP Juice Shop bench: 18 findings / 0 FP / 3/3 SATISFIED.
- **CVE applicability gate (F180-F183)** — drops findings whose products do not apply to the target stack (e.g. JAMon-JSP CVE on a Node.js host).
- **Self-improving loop (F1-F3, F77.G.5)** — every successful engagement writes a draft skill; Wilson-scored selection ranks proven playbooks first; pattern detector clusters chains and auto-synthesizes new skills.
- **Hybrid mode (F203.M)** — 11 deterministic detectors (HTTP, MySQL, SSH, BGP, cookies, …) run BEFORE the LLM in `investigate`; findings injected as ground truth. Web bench recall: 25% → 100%.
- **Local-first by design** — Kryon-MOE-35B (gpt-oss-20b by default) via llama.cpp on 12 GB VRAM. Zero per-engagement cost. Banking data never leaves the engagement host.
- **Banca-safe by default** — passive recon, throttled nmap (`-T2 --min-rate 50`), no live HTTP unless `KRYON_*_FIRE=true` AND `fire=True` argument (double gate).
- **Safe-modification protocol** — diagnose (read-only) → propose (table + STOP) → backup → apply → verify → rollback on failure.

---

## Three execution modes

Kryon has three CLI entry points, each tuned for a different engagement shape.

### 1) `kryon engage` — compliance-driven, plan-based

For PCI-DSS / SWIFT CSP / CIS / NIST audits with a pre-defined phase plan and a deterministic compliance runner. Used in the Britimp POC for 34 hosts across 3 segments.

```bash
kryon engage \
  --target 192.168.10.11 \
  --framework pci_dss \
  --orchestrated \
  --auto-approve \
  --client britimp-internal \
  --engagement-id eng_brit_001 \
  --out ./poc-reports
```

Phase plan loaded from `pyproject.toml` profiles; each phase re-matches skills against `phase_name + objective + target` and runs that skill's `pre_hooks:` (F185). PDF report + JSON findings + reproducibility hash (F39) per engagement.

### 2) `kryon investigate` — open-ended ReAct loop

For exploratory work: "audita esta URL", "qué CVEs aplican a nginx 1.18", SAST sobre código local. F203 stack: Observation → Reflection → Decision → Action → Verification, with stuck-pattern detection that breaks loops before wall-budget exhaustion.

```bash
# Banca-safe (passive: web_fetch_smart + RAG + 11 hybrid detectors)
kryon investigate "audita https://target.com"
kryon investigate --url https://target.com
kryon investigate ./local/path/             # SAST on local source

# Active (requires written authorization)
kryon investigate "active sqli pentest contra https://target" --active

# Active + red-team tools (jwt_crack, hydra, ffuf, playwright)
KRYON_RED_TEAM=true kryon investigate "active rce pentest contra http://lab" --active
```

| Mode | Flag | Tools available | Pre-hooks fired |
|------|------|-----------------|-----------------|
| **PASSIVE** (default) | — | `web_fetch_smart`, RAG queries, DNS lookup | Hybrid-mode deterministic only (F203.M) |
| **ACTIVE** | `--active` | + nmap, nuclei, sqlmap, etc. | ALL (incl. F203.V-AB explicit-keyword skills) |
| **ACTIVE + RED-TEAM** | `--active` + `KRYON_RED_TEAM=true` | + 21 red-team tools | ALL |

**14 explicit-keyword active skills** (F203.V/W/X/AB/AF/AG) cover OWASP Top-10 + API + JS-ecosystem. They activate ONLY with the literal phrase `"active <X> pentest"` (or `"fire <X> probe"` / `"pentest activo <X>"`) — preventing pre-hook regression on broad-keyword triggers.

### 3) `kryon discover --queue-add` + `kryon queue process` — multi-target POC

For segment-wide POCs (CIDR not supported on `engage` directly). Discovers live hosts, queues them, then drains the queue invoking `engage` per item — banca-safe serial by default.

```bash
# 1. Discover + enqueue (throttled nmap)
KRYON_NMAP_TIMING=T2 KRYON_NMAP_MIN_RATE=50 \
  kryon discover --subnet 10.x.x.0/24 --queue-add --output disc.json

# 2. Drain — sequential, no auto-retry on failure (manual triage)
kryon queue process \
  --concurrency 1 \
  --framework pci_dss \
  --orchestrated \
  --auto-approve \
  --client britimp-internal \
  --out ./poc-reports
```

`--limit N` cuts after N items. Failed items stay in `status=failed` for triage — no silent retries (avoids duplicate destructive actions on banking hosts). Full wrapper: [`scripts/poc_britimp_segmento.sh`](scripts/poc_britimp_segmento.sh).

---

## Skill System

Kryon's intelligence lives in **106 markdown playbooks** organized by purpose. Skills are **auto-matched** by target tech, open ports, and user keywords. Priority-based selection with a token budget cap (max 30 tools to fit a 16K-context active engagement).

```
src/kryon/skills/playbooks/
├── ~42 core skills         recon-scout, pentest, vuln-hunter, appsec,
│                            forensics, ctf-master, ssl-audit, server-hardening,
│                            safe-modification, rollback-recovery,
│                            tomcat-audit, fortigate-audit, unifi-audit,
│                            voip-asterisk-audit, dvr-audit, hackerone-engagement,
│                            burp-integration, http-fetch, evidence-forensics,
│                            cryptanalysis-techniques, browser-exploit,
│                            memory-corruption-exploits, binary-reverse-engineering, …
├── banking/ (4 .md files)  pci-dss-audit, audit-bank-full, proxmox-audit,
│                            cis-controls-v8.1
│                            ⚠ core-banking-assessment, mobile-banking-audit,
│                            atm-security, payment-gateway-testing, fraud-detection,
│                            swift-network-security, open-banking-api are
│                            *methodology templates* documented in CLAUDE.md,
│                            NOT shipped .md playbooks — see Banking Status below.
├── cwe-detection/ (11)     CWE-22, CWE-78, CWE-79, CWE-89, CWE-125, CWE-20,
│                            CWE-287, CWE-352, CWE-502, CWE-639, CWE-918
├── ot/ (5 skills)          modbus, dnp3, iec104, s7, mqtt-industrial
├── imported/ (40 skills)   from mukul975/Anthropic-Cybersecurity-Skills
│                            (Apache 2.0, MITRE ATT&CK / NIST CSF mapped)
├── zero-day/ (1 skill)     source-review / variant-analysis harness
└── pre_hooks/              Python escape-hatch helpers (sqlmap, IDOR probe)
```

### Pre-hooks — deterministic-first execution (F80)

A skill can declare a YAML list of tool invocations that run **before** the LLM gets control. Output is injected as authoritative context — the model narrates findings, it cannot skip the detector.

```yaml
---
name: vuln-hunter
priority: 30
required_tools: [nuclei_scan, run_command]
pre_hooks:
  - tool: nuclei_scan
    args: { target: "{ctx.target}", severity: "critical,high,medium" }
  - tool: run_command
    args: { command: "nikto -h {ctx.target} -Tuning x6 -maxtime 60" }
  - python: ./pre_hooks/sqlmap_rest_login_hook.py:run
---
```

Currently wired in: `fortigate-audit`, `unifi-audit`, `proxmox-audit`, `pci-dss-audit`, `audit-bank-full`, `vuln-hunter`, `ssl-audit`, `appsec`, `wordpress-audit`, the 14 explicit-keyword active skills, the 11 CWE-detection skills, and the 6 banking F203.O skills.

### `/skill` REPL commands

```bash
KRYON> /skill list                      # All 106 loaded
KRYON> /skill show recon-scout          # View playbook content
KRYON> /skill search kubernetes         # Search upstream catalog (754 skills)
KRYON> /skill import exploiting-zerologon-vulnerability-cve-2020-1472
KRYON> /skill reload                    # After editing a .md
KRYON> /skill drafts                    # Auto-generated drafts pending review (F1)
KRYON> /skill review <draft>            # Inspect a draft
KRYON> /skill promote <draft>           # Promote draft to active skill
KRYON> /skill scores                    # Wilson-scored skill ranking (F2)
KRYON> /skill auto detect               # Trigger pattern detector (F3)
```

### Custom skills

Drop a `.md` in `src/kryon/skills/playbooks/`:

```yaml
---
name: my-custom-audit
description: "My specialized playbook"
triggers:
  tech: ["nginx"]
  keywords: ["nginx hardening", "reverse proxy audit"]
priority: 20
required_tools: [run_command, nuclei_scan]
pre_hooks:
  - tool: run_command
    args: { command: "curl -sI https://{ctx.target}" }
---

## Workflow
1. Verify nginx version + EOL status
2. Check TLS config (ciphers, HSTS, OCSP stapling)
3. ...
```

---

## Self-improving loop (3-layer, F1-F3)

| Layer | Purpose | Trigger |
|-------|---------|---------|
| **F1 — Drafting** | Every successful engagement writes a draft `.md` to `~/.kryon/drafts/` via `skill_synthesizer.py` + `draft_writer.py` | Auto on engage exit |
| **F2 — Scoring** | `skill_scorer.py` uses Wilson 95%-lower-bound confidence + reusability axis (F77.G.5). Activate with `KRYON_SKILL_RANKING=hybrid` or `=dual` | Per-selection telemetry to JSONL |
| **F3 — Auto-creation** | `pattern_detector.py` (Jaccard clustering) + LLM-assisted body + `skill_evaluator.py` (CWE → tools gate, hallucinated tools rejected) + `auto_pipeline.py` | Manual: `/skill auto detect` |

CWE map override: `~/.kryon/cwe_map.yaml` (template at `docs/examples/cwe_map.yaml`).

`F203.S`: every auto-generated draft now gets a sidecar `.eval.json` with `guide_score` (relevance + naturalness, threshold 0.6).

---

## Architecture

```
                           ┌─────────────────────────────────────┐
                           │   kryon CLI (19 subcommands)        │
                           │   engage · investigate · queue ·    │
                           │   discover · approve · doctor · …   │
                           └────────────────┬────────────────────┘
                                            │
                                            ▼
                  ┌─────────────────────────────────────────────────┐
                  │   skills/  (PRIMARY interface in v2.x)          │
                  │   ┌────────────────────────────────────────┐    │
                  │   │ loader.py — match by tech/ports/kw     │    │
                  │   │ tool_budget.py — cap @ 30 tools        │    │
                  │   │ unified_agent.py — compose prompt      │    │
                  │   │ pre_hook_runner.py — deterministic-1st │    │
                  │   └────────────────────────────────────────┘    │
                  │   playbooks/  (106 .md files)                   │
                  └────────────┬────────────────────┬───────────────┘
                               │                    │
                               ▼                    ▼
            ┌──────────────────────────┐  ┌────────────────────────────┐
            │ sdk/agents/ (run loop)   │  │ tools/ (348 @function_tool)│
            │ ┌──────────────────────┐ │  │ 35 categories:             │
            │ │ Runner               │ │  │ reconnaissance, web,       │
            │ │ models/openai_chat   │ │  │ network, ad, cloud,        │
            │ │  + harmony_parser    │ │  │ container, forensics,      │
            │ │  + tool name fixes   │ │  │ exploitation, dfir,        │
            │ │ ReflectiveRunner     │ │  │ banking, ot, validation…   │
            │ └──────────────────────┘ │  └────────────────────────────┘
            └──────────┬───────────────┘
                       │
                       ▼
      ┌──────────────────────────────────────────────────────────────┐
      │ Cross-cutting subsystems                                     │
      │                                                              │
      │ services/  context mgmt (micro_compact, session_memory,      │
      │            tool_output_cap, auto_extract)                    │
      │ learning/  ChromaDB experiences + F1/F2/F3 self-improvement  │
      │ knowledge/ NVD + ExploitDB + writeups (embedding RAG OFF)    │
      │ compliance/ 9 frameworks (PCI-DSS, CIS, SWIFT, …) runners    │
      │ reporting/ PDF/DOCX/HTML, reproducibility hashes (F39)       │
      │ memory/    SQLite store (16 migrations) — engagements, KB    │
      │ server/    FastAPI — 136 endpoints, multi-tenant, JWT/RBAC   │
      │ approval/  Human-in-the-loop for destructive actions (F144)  │
      └──────────────────────────────────────────────────────────────┘
                       │
                       ▼
              ┌────────────────────────┐
              │ llama-server (llama.cpp)│
              │  Kryon-MOE-35B          │
              │  Qwen3.6-35B-A3B MoE    │
              └────────────────────────┘
```

### Execution flow — `kryon investigate` example

```
1. ParseArgs(url) ──▶ ReflectiveRunner(max_turns=N, reflect_every=4)
2. SkillLoader.match(url, intent) ──▶ 3-5 skills selected
3. ToolBudget.select(skills) ──▶ 30 tools wired to runner
4. _run_deterministic_phase(url) — F203.M hybrid mode
       ├── _check_http      ──▶ headers, redirects, tech fingerprint
       ├── _check_mysql     ──▶ banner, auth attempt
       ├── _check_ssh       ──▶ banner, ciphers
       └── (8 more detectors) ──▶ findings injected as GROUND TRUTH
5. pre_hooks of matched skills (F185)
       ├── nuclei_scan      ──▶ severity-prioritized top-N
       ├── nikto            ──▶ deduped by bracketed-id regex
       └── sqlmap (Python)  ──▶ JSON POST body discovery
6. LLM agent loop  (max_turns=8 reasoning / 5 instruct)
       observation ──▶ reflection (every 4 turns) ──▶ decision ──▶ action ──▶ verify
7. _parse_agent_findings
       ├── CVE applicability gate (F180-F181.C, drops e.g. JAMon CVE on Node.js)
       ├── Finding applicability gate (F183, scans message+evidence for product kw)
       └── KRYON_DEBUG_PARSE=true ──▶ JSONL trace
8. writeback_engagement ──▶ ChromaDB + ~/.kryon/drafts/<auto>.md (F1)
```

---

## Installation

### Requirements

- **Python 3.10+** (managed by [`uv`](https://github.com/astral-sh/uv))
- **Docker** (Kali Linux + 200+ security tools pre-installed)
- **GPU recommended**: 12 GB VRAM for `Kryon-MOE-35B` (Qwen3.6-35B-A3B MoE, UD-Q4_K_XL) via llama.cpp
- **GitHub CLI** (`gh`) for `/skill import` from upstream catalog

### Docker deployment (recommended)

```bash
git clone https://github.com/skyvanguard/Kryon.git
cd Kryon

# Copy environment template
cp docker/.env.docker.example docker/.env.docker

# Launch stack (Kali + llama-server + Kryon, GPU passthrough)
docker compose -f docker/docker-compose.kali.yml \
               -f docker/docker-compose.override.yml \
               --env-file docker/.env.docker up -d

# The production model (Kryon-MOE-35B) is served by the `llama-server`
# service of the compose file — it mounts the Qwen3.6-35B-A3B MoE GGUF
# (UD-Q4_K_XL, ~21 GB) and exposes an OpenAI-compatible API on :8080
# with tool-calling enabled via `--jinja`. There is no model-build step:
# llama.cpp loads the GGUF directly on startup. Verify it is up with:
docker exec kryon curl -s http://llama-server:8080/v1/models

# (Embedding RAG is OFF by default — see "knowledge/" notes below.)

# (Optional) Populate NVD cache for CVE-applicability gate
docker exec -it kryon kryon update-cve-cache --all

# Launch REPL
docker exec -it kryon kryon
```

### Configuration profiles

#### Banca-safe (compliance audits — default)

```bash
# docker/.env.docker
KRYON_MODEL=Kryon-MOE-35B              # Qwen3.6-35B-A3B MoE via llama.cpp
KRYON_AGENT_TYPE=kryon
KRYON_UNIFIED=true
KRYON_FORCE_TOOL_TURNS=8               # local LLM tool-calling reliability
KRYON_MEMORY=true
KRYON_STREAM=false                     # Stable REPL

# Throttled scanning (banking-friendly during business hours)
KRYON_NMAP_TIMING=T2
KRYON_NMAP_MIN_RATE=50
KRYON_NMAP_MAX_PARALLELISM=10
KRYON_NUCLEI_RATE_LIMIT=50
KRYON_NUCLEI_BULK_SIZE=10
KRYON_NUCLEI_CONCURRENCY=10

# CVE / finding applicability gates (drop hallucinated cross-stack CVEs)
KRYON_CVE_CACHE_REQUIRED=true
KRYON_CVE_APPLICABILITY=true           # default
KRYON_FINDING_APPLICABILITY=true       # default
```

#### Active pentest (authorized targets only)

```bash
# Add to banca-safe block
KRYON_REASONING_EFFORT=medium          # F184 — only when pre-hooks active
KRYON_PHASE_TURNS=10                   # F166 — bump from auto-8
KRYON_RED_TEAM=true                    # Unlock 21 red-team tools

# Live-probe gates (DOUBLE gate: env + fire=True argument)
KRYON_BOLA_FIRE=true                   # detect_bola live HTTP
KRYON_GRAPHQL_FIRE=true                # graphql_recon live HTTP
KRYON_RETEST_FIRE=true                 # retest_finding live HTTP
KRYON_BRAND_FIRE=true                  # typosquat_scan live DNS
```

---

## Banking vertical — honest status

The README marketing is honest: not every banking playbook is turnkey today.

| Playbook | Status | Notes |
|---|---|---|
| **`pci-dss-audit.md`** | ✅ **production-capable** | F15.1 + F39 + F85.E + F39.3: **46 deterministic checks**. Adds PCI-DSS v4.0.1 mandatorios (2025-03-31): 6.4.3 SRI+CSP, 8.4.3 phishing-resistant MFA (FIDO2/WebAuthn). Reproducibility-hashed. SAQ B/C/D scoping. |
| **`proxmox-audit.md`** | ✅ **production-capable** | F23 + F85.E: 8 deterministic PVE checks. Validated in F48 internal pilot. |
| **`audit-bank-full.md`** | ✅ **production-capable** | F46: orchestrates the three core audits + multi-framework PDF (F44). |
| **`fortigate-audit.md`** | ✅ **production-capable** | F78: 21 checks (FGT-1.1..FGT-5.3) wired to `run_compliance_audit(framework="fortigate")`. CIS Fortinet Benchmark + CVE catalog (CVE-2022-42475, CVE-2024-21762, CVE-2024-23113). Read-only via SSH. |
| **`unifi-audit.md`** | ✅ **production-capable (controller)** + 📝 template (WiFi capture) | F79: 18 controller checks via `mongo --port 27117 ace`. Hash estable. Active WiFi capture runs on operator host. |
| **`voip-asterisk-audit.md`** | ✅ **production-capable** | F198: 8 checks (VOIP-1.1..VOIP-3.3): anonymous register / AMI default secret / allowguest / AMI WAN / SRTP / SIP-TLS / version currency. |
| **`windows-server-audit.md`** | ✅ **production-capable** | F199: 15 checks (WIN-1.1..WIN-4.2) via WinRM (F36 runner): SMBv1 / LSA / PrintNightmare / Defender RTP / firewall / BitLocker / LLMNR / WSUS / LAPS / audit policy / RDP NLA / UAC / EDR. |
| **`tomcat-audit.md`** | ✅ **production-capable** | F200.A: 8 checks (TOMCAT-1.1..TOMCAT-2.4): EOL versions / AJP 8009 Ghostcat (CVE-2020-1938) / Manager+Host Manager exposure / version leak / /docs + /examples deployed. |
| **`dvr-audit.md`** | 📝 recon-only template (F197) | Dahua/Hikvision/ONVIF fingerprint + nuclei CVE templates (CVE-2017-7921, CVE-2021-33044/45, CVE-2021-36260). Custom checks v2 post-POC. |
| `core-banking-assessment.md` | 📝 template | T24/Flexcube/Finacle/Bantotal — methodology + checklist only. Needs vendor sandbox per engagement. |
| `swift-network-security.md` | 📝 template | CSP v2024 (32 controls). Manual + Alliance Access access. NOT a KY3P replacement. |
| `atm-security.md` | 📝 template | Requires physical access + NCR/Diebold lab + PCI-PTS certified team. |
| `open-banking-api.md` | 📝 template | FAPI 1.0 Advanced. Per-bank mTLS certs + client_id required. |
| `payment-gateway-testing.md` | 📝 template | Bancard/Infonet/Stripe/MercadoPago. Checklist only. |
| `fraud-detection.md` | 📝 template | Interview + rule-review guide, not a technical scan. |
| `mobile-banking-audit.md` | 📝 template | Frida/objection/jailbroken device outside the container. |

**Rule of thumb**: ✅ = end-to-end deterministic + reproducibility hash. 📝 = methodology guide; execution requires manual steps and vendor-specific access.

---

## What runs today (POC reality)

End-to-end proven in production engagements:

- **POC Britimp (internal, May 2026)** — 34 hosts across 3 segments (TORRE-VOIP, USR, SVR), low-impact during business hours via operator VPN. 11 systemic findings, 0 false positives, 0 USD per engagement. 26 new Kryon features shipped from POC feedback (F199.E-P, F200.A-B, F201.A-A.B, F202.A-K, F202.I.B, F202.M).
- **OWASP Juice Shop bench** — F189: avg 18 findings, 0 FPs, 3/3 SATISFIED (n=3 reproducible). Ground truth: 10 canonical CWEs (CWE-89/79/639/285/200/22/352/915/1004/319).
- **HackTheBox-style walkthrough bench** — F203.AO.B: 4/7 PWN rate (chain_match 100%) on web-only ready set (SQLi, XSS, IDOR, RCE, SSRF, CSRF, XXE). Note: F203.BA — `ready_url` points to PortSwigger docs, NOT the live lab. Measures **reasoning over documentation**, not live exploit.
- **Juliet SAST bench (F74.C-F76.2)** — 67.1% recall + 15% FPR @ HIGH.

Edge-network coverage (FortiGate + Unifi + VoIP + Windows + Tomcat) extends the data center perimeter all the way to WiFi and PBX.

---

## Use Cases

### Compliance audits (banking specialty)

```bash
kryon engage --target 192.168.10.11 --framework pci_dss --orchestrated
kryon engage --target fw01.corp --framework fortigate --orchestrated
kryon engage --target unifi.corp --framework unifi --orchestrated
kryon engage --target dc01.corp --framework windows --orchestrated
```

### Bug bounty / authorized pentest

```bash
KRYON_RED_TEAM=true kryon investigate "active sqli pentest contra https://target" --active
KRYON_RED_TEAM=true kryon investigate "active rce pentest contra http://lab"     --active
KRYON_RED_TEAM=true kryon investigate "active idor pentest contra api.target"    --active
```

### CTF / HackTheBox

```bash
KRYON_RED_TEAM=true kryon investigate "resolvé esta máquina: 10.10.10.5" --active
```

### Forensics & incident response

```bash
KRYON> /agent select forensics
KRYON> analizá este memory dump con volatility
KRYON> investigá este phishing email (eml adjunto)
KRYON> detectá lateral movement en los logs
```

### Server hardening (SSH remediation)

```bash
kryon engage --target 192.168.1.10 --ssh-user admin --ssh-key ~/.ssh/id_ed25519 \
             --framework cis_linux --orchestrated
```

→ Loads `server-hardening` + `safe-modification` + `rollback-recovery`. Diagnose (read-only) → Propose (table + STOP) → Apply (with backups) → Verify.

### Multi-target segment POC

```bash
KRYON_NMAP_TIMING=T2 kryon discover --subnet 10.0.10.0/24 --queue-add --output disc.json
kryon queue process --concurrency 1 --framework pci_dss --orchestrated --auto-approve \
                    --client mycorp --out ./poc-reports
```

---

## Supported AI Models

| Provider | Recommended | Config | Notes |
|----------|-------------|--------|-------|
| **llama.cpp (local)** | **`Kryon-MOE-35B`** | `KRYON_MODEL=Kryon-MOE-35B` | **DEFAULT.** Qwen3.6-35B-A3B MoE, UD-Q4_K_XL, ~21 GB GGUF. Served by `llama-server`, tool-calling via `--jinja`. |
| OpenAI | GPT-4o, o3 | `OPENAI_API_KEY` | Cloud — banking data leaves perimeter. |
| Anthropic | Claude Sonnet 4.6 | `ANTHROPIC_API_KEY` | Cloud. |
| DeepSeek | DeepSeek V3, R1 | `DEEPSEEK_API_KEY` | Cloud. |
| OpenRouter | 200+ models | `OPENROUTER_API_KEY` | Cloud. |

**Recommended**: `Kryon-MOE-35B` (Qwen3.6-35B-A3B MoE) — local, zero API cost, tool calling via llama.cpp's `--jinja` template. Fits 12 GB VRAM (MoE experts offloaded to CPU, attention on GPU). Banca-safe sampling defaults (`--temp 0.3`) are baked into the `llama-server` command in the compose file.

---

## Compliance Coverage

| Framework | Coverage | Status |
|-----------|----------|--------|
| **PCI-DSS v4.0.1** | 46 deterministic checks, 12 requirements, SAQ A→D | ✅ production |
| **CIS Linux Benchmark** | via `server-hardening` + `safe-modification` | ✅ production |
| **CIS Fortinet Benchmark** | 21 checks via `fortigate-audit` | ✅ production |
| **Proxmox / PVE hardening** | 8 checks via `proxmox-audit` | ✅ production |
| **OWASP Top 10** | Web + API + Mobile (active skills F203.V-AB) | ✅ production |
| **MITRE ATT&CK** | Technique mapping via imported skills | ✅ production |
| **NIST CSF 2.0** | Control alignment | ✅ production |
| **SWIFT CSP (CSCF) v2024** | 32 controls mapped | 📝 template |
| **FAPI 1.0 Advanced / PSD2** | OAuth2/mTLS/PKCE/PAR/JARM | 📝 template |
| **HIPAA, SOC2, GDPR** | via `compliance/` module | 📝 template |

---

## Docker Stack

```bash
# Full Kali + llama-server + Kryon
docker compose -f docker/docker-compose.kali.yml \
               -f docker/docker-compose.override.yml up -d

# Interactive REPL
docker exec -it kryon kryon

# Kali shell (nmap, sqlmap, hydra, burp, wpscan, nuclei, …)
docker exec -it kryon bash

# VPN for CTF / restricted engagement
docker exec -u root -d kryon openvpn --config /workspace/htb.ovpn
```

| Container | Purpose | Resources |
|-----------|---------|-----------|
| `kryon` | Kali Linux + Python + 200+ security tools | 12 GB RAM |
| `kryon-llama` | Local LLM inference (llama.cpp `llama-server`), GPU passthrough | 20 GB RAM + 12 GB VRAM |
| `nginx` (optional) | Reverse proxy with TLS | 256 MB |

---

## Testing

```bash
# Full test suite
uv run pytest

# Specific modules
uv run pytest tests/agents/ -k "pentest"
uv run pytest -m "unit and not slow"

# Coverage (target: 95% on src/kryon/sdk/agents subtree)
make coverage
```

Test layout mirrors the package (`tests/<subsystem>/...`). `asyncio_mode = "auto"`; do not add `@pytest.mark.asyncio` manually.

---

## Contributing

### Custom skills

Drop a `.md` in `src/kryon/skills/playbooks/` with YAML frontmatter and `pre_hooks:` if applicable. Kryon picks it up via `/skill reload`. **In v2.x, prefer a skill over a new Python agent.** Generic-value skills can be contributed upstream to [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) under Apache 2.0.

### Code

See [CONTRIBUTING.md](CONTRIBUTING.md). Conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `perf:`, `ci:`. **Do not commit `.kryon/`, `workspaces/`, `logs/`, `nohup.out`, `ci/`** — all excluded from the hatch build.

---

## Working with banking clients

- **Written authorization is mandatory** before testing any institution-owned system.
- **Paraguay regulatory context**: BCP Resoluciones (SIB) and Superintendencia de Bancos for infrastructure/security audits. SEPRELAD (AML/KYC) is named here only as regulatory context — **Kryon does not implement AML/KYC or transaction-monitoring controls** (those are not infrastructure controls a scanner validates). Do not pitch SEPRELAD coverage.
- **Never commit or log real PAN numbers**. Use test cards only (Stripe: 4242…, Bancard: 4005 5500 0000 0001).
- **NDA first**, data retention policy, secure destruction after engagement.
- For PCI-DSS audits, confirm SAQ level (A, A-EP, B, B-IP, C, C-VT, D) before scoping.
- For SWIFT CSP audits, the attestation is annual — coordinate with the bank's SWIFT CISO.

---

## Disclaimer

> **KRYON is designed exclusively for authorized security testing, research, and education.**
>
> You must have **explicit written authorization** before testing any system you do not own. For financial / banking clients, compliance with local regulations (BCP Paraguay, SIB, Superintendencia de Bancos, equivalent bodies in your jurisdiction) is mandatory. Unauthorized access to computer systems is illegal. See [DISCLAIMER](DISCLAIMER).

---

## License

Proprietary — All Rights Reserved. See [LICENSE](LICENSE). Upstream imported skills retain their original Apache 2.0 license (see each file's frontmatter).

---

<div align="center">

**KRYON v2.1.0 "Hydra — Skillforge"**
Autonomous · Local-first · Skill-based · Self-improving

[GitHub](https://github.com/skyvanguard/Kryon) · [Issues](https://github.com/skyvanguard/Kryon/issues) · [Releases](https://github.com/skyvanguard/Kryon/releases) · [Deployment Guide](DEPLOYMENT.md) · [Changelog](CHANGELOG.md)

</div>
