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

**Autonomous Cybersecurity Agent for Financial Services**

*Specialized pentesting + compliance auditing + remediation for banks, fintech and payment processors*

[![CI](https://github.com/skyvanguard/Kryon/actions/workflows/ci.yml/badge.svg)](https://github.com/skyvanguard/Kryon/actions/workflows/ci.yml)
[![Security Scan](https://github.com/skyvanguard/Kryon/actions/workflows/security-scan.yml/badge.svg)](https://github.com/skyvanguard/Kryon/actions/workflows/security-scan.yml)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-2.1.0_Skillforge-purple.svg)](CHANGELOG.md)
[![Skills](https://img.shields.io/badge/skills-67_playbooks-gold.svg)](#skill-library)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)

[Installation](#installation) | [Banking Playbooks](#banking-playbooks) | [Quick Start](#quick-start) | [Skill System](#skill-system) | [Docker](#docker-deployment)

</div>

---

## What is KRYON?

KRYON is an **autonomous cybersecurity agent designed for the financial sector**. One prompt triggers a full security assessment with banking-specific playbooks (PCI-DSS, SWIFT CSP, FAPI, PSD2, core banking, mobile banking, ATMs, payment gateways, fraud detection). It **learns from every engagement** — the more pentests it runs, the better it gets.

Built for compliance officers, security teams, and pentesters who work with banks, fintech, payment processors, and any organization handling financial data.

### Optimized for Financial Clients

```
KRYON> quiero hacer PCI-DSS audit de banco.com.py

 ✶ Kryon [pci-dss-audit] Orchestrating…  (3s)
 ● recall_similar_experiences → 2 prior engagements
 ● nmap -sV -sC -T4 → 4 ports open
 ● whatweb_scan → Apache, Bootstrap, TLS 1.2+
 ● nuclei_scan → 1 finding (uploads.zip exposed)
 ● PCI compliance check → 12 requirements evaluated

╭─ Kryon ───────────────────────────────────────────╮
│ ## PCI-DSS Compliance Audit: banco.com.py          │
│ **Target**: 54.69.84.63 (Apache httpd)             │
│ **CDE Scope**: 3 systems                           │
│ **Finding (CRÍTICO)**: uploads.zip expuesto       │
│   - Req 3.4 (storage), Req 6.5.10 (insecure data) │
│ **Security headers**: ✅ CSP, HSTS, X-Frame        │
│ **TLS**: ✅ TLS 1.2+, strong ciphers               │
│ **Remediation timeline**: 30 días (CRÍTICO)       │
│ **Mappings**: PCI-DSS v4.0.1 Req 3.4.1, CVE list  │
╰────────────────────────────────────────────────────╯

✅ Experience auto-saved: eng_3e03db5ef859
```

### Platform at a Glance

| Component | Count |
|-----------|:-----:|
| Total Skills (playbooks) | **67** |
| Banking-specific Skills | 8 |
| Security Tools | 204+ |
| API Endpoints | 136 |
| Compliance Frameworks | 9 |
| Test Suite | 1896 passed |

---

## Banking Playbooks

Custom skills for **financial sector clients in LATAM/Paraguay**:

| Skill | What it covers |
|---|---|
| **`pci-dss-audit`** | PCI-DSS v4.0.1 full audit — 12 requirements, 6 objectives, PAN detection, CDE scoping, compensating controls |
| **`core-banking-assessment`** | T24 (Temenos), Flexcube (Oracle), Finacle (Infosys), Bantotal, IBS. SIPAP/SINACOFI integrations (Paraguay). BCP regulatory framework |
| **`mobile-banking-audit`** | iOS/Android apps — static + dynamic analysis, cert pinning bypass, biometric validation, transaction signing, deep link abuse, secure storage audit |
| **`atm-security`** | Jackpotting (Tyupkin, Ploutus, Alice), skimming detection, ISO 8583 message analysis, black box attacks, NCR/Diebold/Wincor/Hyosung hardening |
| **`payment-gateway-testing`** | Stripe, Bancard, MercadoPago, PSE, Wompi integrations. Webhook security, amount tampering, 3DS bypass, idempotency, refund abuse |
| **`fraud-detection`** | Velocity rules, UEBA, ML models, AML screening (OFAC/UN), money mule patterns, KYC bypass testing. FATF compliance |
| **`swift-network-security`** | SWIFT CSP 32 controls, Alliance Access/Gateway hardening, operator workstation audit, MT/MX message security. Bangladesh-type attack prevention |
| **`open-banking-api`** | FAPI 1.0 Advanced, OAuth 2.0, OpenID Connect, mTLS, PKCE, PAR, JARM, consent management. PSD2 RTS compliance |

Each playbook includes:
- Pre-engagement checklist (authorization, scope, NDA)
- Step-by-step workflow with real commands
- Findings taxonomy with severity
- Compliance mapping (PCI-DSS, PSD2, BCP, FATF)
- LATAM-specific regulatory context

---

## Skill System

KRYON uses **67 dynamic markdown playbooks** organized into three tiers:

```
src/kryon/skills/playbooks/
├── core/ (11 skills)         # Recon, pentest, safety, rollback, CTF, forensics
├── imported/ (28 skills)     # From mukul975/Anthropic-Cybersecurity-Skills (Apache 2.0)
│                             # MITRE ATT&CK mapped, NIST CSF aligned
└── banking/ (8 skills)       # Financial clients (PCI, SWIFT, FAPI, ATMs, etc.)
```

Skills are **auto-matched** to targets by tech/port/keyword triggers. When you say *"audit the WordPress site"*, Kryon loads `wordpress-audit` + `recon-scout`. When you say *"PCI audit of the bank"*, it loads `pci-dss-audit` + `safe-modification` + `core-banking-assessment`.

### `/skill` command — dynamic library

Any of the **754 upstream skills** can be installed during a session:

```bash
KRYON> /skill list                          # Show all 67 loaded
KRYON> /skill show pci-dss-audit            # View full playbook
KRYON> /skill search swift                  # Search upstream catalog
KRYON> /skill import analyzing-swift-mt-messages  # Install from upstream
KRYON> /skill reload                        # After editing a .md
```

No rebuilds. No restarts. Just drop a `.md` file in `playbooks/` or use the command.

### Creating custom skills

Write a markdown file with YAML frontmatter:

```yaml
---
name: my-custom-audit
description: "Client-specific audit playbook"
triggers:
  tech: ["nginx"]
  keywords: ["nginx", "reverse proxy"]
priority: 20
required_tools:
  - run_command
  - nuclei_scan
---

## My Custom Audit
1. Verify nginx version and config
2. ...
```

Kryon loads it automatically on next session.

---

## Self-Improving Loop

Every engagement is stored in ChromaDB with:
- **Target profile**: host, IP, ports, services, tech stack
- **Attack chain**: ordered sequence of tools + arguments + outcomes
- **Outcome classification**: success / partial / recon-only / fail
- **Signals**: CVEs found, directories discovered, findings per severity

On the next engagement, the agent queries `recall_similar_experiences` and **optimizes its approach based on what worked against similar targets**.

```
Session 1: audit banco.com.py → nmap→whatweb→gobuster→nuclei → saved

Session 2: audit similar-bank.com.py
  → recall: "Against Apache+Bootstrap+Paraguay banks, nmap→whatweb→nuclei 
             found uploads.zip backup exposure in 5 min"
  → Kryon skips redundant steps, goes straight to PCI checks → faster engagement
```

### REPL Commands

| Command | Action |
|---------|--------|
| `/skill list/show/search/import` | Manage playbook library |
| `/experiences list/show/close` | Manage engagement learning |
| `/flush` | Clear agent history + session memory |
| `/compact` | Manual conversation compaction |
| `/report` | Display auto-generated Magic Doc report |

---

## Installation

### Requirements

- **Python 3.10+**
- **Docker** (recommended for Kali Linux security tools)
- **GPU recommended** for local models (12+ GB VRAM for Gemma 4 26B)
- **GitHub CLI** (`gh`) for `/skill import` from upstream

### Docker Deployment

```bash
git clone https://github.com/skyvanguard/Kryon.git
cd Kryon

# Copy environment template
cp docker/.env.docker.example docker/.env.docker
# Edit docker/.env.docker as needed

# Launch stack (Kali + Ollama + Kryon)
docker compose -f docker/docker-compose.kali.yml \
               -f docker/docker-compose.override.yml \
               --env-file docker/.env.docker up -d

# Pull Gemma 4 26B (recommended model for local deployment)
docker exec kryon-ollama ollama pull gemma4:26b

# Create 32K context variant
docker exec kryon-ollama sh -c 'printf "FROM gemma4:26b\nPARAMETER num_ctx 32768\n" > /tmp/Modelfile && ollama create gemma4:26b-32k -f /tmp/Modelfile'

# Pull RAG embedding model
docker exec kryon-ollama ollama pull nomic-embed-text

# Launch REPL
docker exec -it kryon kryon
```

### Configuration

Key settings in `docker/.env.docker`:

```bash
# Model — Gemma 4 26B-A4B (MoE, 3.8B active params, tool calling, thinking, 262K ctx)
KRYON_MODEL=gemma4:26b-32k
OPENAI_API_KEY=ollama
OPENAI_BASE_URL=http://ollama:11434/v1
OLLAMA=true

# Unified agent with dynamic skills
KRYON_AGENT_TYPE=kryon
KRYON_UNIFIED=true

# Runtime tuning
KRYON_MAX_TURNS=50
KRYON_FORCE_TOOL_TURNS=8          # Force tool use for first N turns
KRYON_MEMORY=true
KRYON_STREAM=false                # Use non-streaming REPL (stable)

# RAG embeddings
KRYON_EMBEDDING_MODEL=nomic-embed-text
KRYON_EMBEDDING_BASE_URL=http://ollama:11434

# SSH credentials (for server-hardening remediation)
# KRYON_SSH_USER=admin
# KRYON_SSH_HOST=192.168.1.10
# KRYON_SSH_PASS=your-password-here
```

---

## Quick Start

### Financial Audit (primary use case)

```bash
docker exec -it kryon kryon

# PCI-DSS compliance audit
KRYON> haceme un PCI-DSS audit de banco.com.py

# Core banking security assessment
KRYON> evaluá el core banking de t24.banco.com.py

# Mobile banking app audit
KRYON> auditá la app móvil del banco (apk en /workspace/banco.apk)

# Payment gateway testing
KRYON> testeá la pasarela de pago con tarjeta 4005550000000001

# Fraud detection system evaluation
KRYON> auditá el sistema antifraude del banco

# SWIFT CSP compliance
KRYON> hacé SWIFT CSP audit de la infraestructura

# Open Banking / PSD2 API testing
KRYON> testeá las APIs Open Banking del banco según FAPI
```

### Generic Pentesting

```bash
# Full security assessment
KRYON> haceme un analisis de seguridad de www.target.com

# CTF mode
KRYON> resolvé esta máquina de HackTheBox: 10.10.10.5

# Server hardening via SSH
KRYON> audita y corrige mi servidor admin@192.168.1.10

# OSINT collection
KRYON> quiero hacer OSINT de acme-corp.com
```

### View Learning

```bash
KRYON> /experiences list           # Past engagements
KRYON> /skill show pci-dss-audit   # View playbook content
KRYON> /report                      # Current engagement auto-report
```

---

## Supported AI Models

| Provider | Recommended | Config |
|----------|-------------|--------|
| **Ollama (local)** | **gemma4:26b-32k** (MoE, zero cost) | `OLLAMA=true` |
| Ollama | qwen3:8b, dolphin-mistral:7b | `OLLAMA=true` |
| OpenAI | GPT-4o, O3 | `OPENAI_API_KEY` |
| Anthropic | Claude Sonnet 4.6 | `ANTHROPIC_API_KEY` |
| DeepSeek | DeepSeek V3, R1 | `DEEPSEEK_API_KEY` |

**Recommended for production**: Gemma 4 26B via Ollama. MoE architecture (3.8B active/26B total) runs fast on 12+ GB VRAM with 26B quality. Native tool calling, thinking, 262K context. Zero API cost per engagement — critical for client work where you run many assessments.

---

## Compliance Coverage

| Framework | Coverage |
|-----------|----------|
| **PCI-DSS v4.0.1** | All 12 requirements, CDE scoping, SAQ A through D |
| **PSD2 / Open Banking UK** | RTS Article 4, SCA, CSC |
| **FAPI 1.0 Advanced** | OAuth/OIDC, mTLS, PKCE, PAR, JARM |
| **SWIFT CSP (CSCF)** | 32 mandatory + advisory controls |
| **FATF Recommendations** | AML/CFT 40 recommendations |
| **BCP Paraguay** | Resoluciones SIB + SEPRELAD |
| **MITRE ATT&CK** | Technique coverage in imported skills |
| **NIST CSF 2.0** | Mapping in imported skills |
| **OWASP Top 10** | Web + API + Mobile |
| **CIS Benchmarks** | Linux, Windows, Docker, Kubernetes |

---

## Architecture

```
src/kryon/
├── skills/             # 67 dynamic playbooks (core + imported + banking)
│   ├── loader.py       #   SkillLoader — matches by tech/port/keyword
│   ├── unified_agent.py#   Single agent with composed prompt
│   └── playbooks/      #   *.md files with YAML frontmatter
├── learning/           # Self-improving loop
│   ├── experiences.py  #   ChromaDB engagement store
│   ├── profiler.py     #   Target profile extraction
│   └── chain_extractor.py # Tool chain + outcome mining
├── services/           # Context management
│   ├── micro_compact.py   # Trim tool outputs (~85% reduction)
│   ├── session_memory.py  # Magic Doc auto-report
│   ├── auto_extract.py    # Save experience on exit
│   └── tool_output_cap.py # Cap tool results (save to disk)
├── tools/              # 204+ security tools in 35 categories
├── knowledge/          # RAG: ChromaDB + Ollama embeddings + auto-updater
├── server/             # FastAPI — 136 endpoints, multi-tenant, JWT/RBAC
├── repl/               # Interactive CLI + Claude Code-style spinner
├── sdk/                # Agent SDK (Agent, Runner, Handoff, Guardrail, MCP)
├── compliance/         # 9 frameworks (PCI-DSS, PSD2, SWIFT, etc.)
├── reporting/          # PDF/DOCX/HTML report generation
└── memory/             # SQLite store (16 migrations)
```

---

## Docker Stack

```bash
# Full Kali + Ollama + Kryon stack
docker compose -f docker/docker-compose.kali.yml \
               -f docker/docker-compose.override.yml up -d

# REPL
docker exec -it kryon kryon

# Kali shell (nmap, metasploit, sqlmap, hydra, burp, etc.)
docker exec -it kryon bash

# VPN for restricted client engagements
docker exec -u root -d kryon openvpn --config /workspace/client.ovpn
```

| Container | Purpose |
|-----------|---------|
| `kryon` | Kali Linux + Python + all security tools |
| `kryon-ollama` | Local LLM inference (GPU passthrough) |
| `nginx` (optional) | Reverse proxy with TLS |

---

## Testing

```bash
# Full test suite
uv run pytest

# Specific modules
uv run pytest tests/agents/ -k "pentest"
uv run pytest -m "unit and not slow"

# Coverage (target: 95%)
make coverage
```

Current: **1896 passed, 24 skipped, 0 failed**

---

## Contributing

### Custom skills for your client

Drop a `.md` in `src/kryon/skills/playbooks/` (or subdirectory):

```yaml
---
name: custom-pentest
description: "Client X specific playbook"
triggers:
  tech: ["specific-stack"]
  keywords: ["client-x", "custom audit"]
priority: 15
required_tools: [run_command, nuclei_scan]
---

## Workflow
1. ...
```

### Contribute back upstream

If you write generic-value skills (not client-specific), consider contributing to [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) under Apache 2.0.

---

## Disclaimer

> **KRYON is designed exclusively for authorized security testing, research, and education.**
>
> For banking/financial clients, you must have **explicit written authorization** from the institution AND comply with local regulations (BCP Paraguay, SIB, Superintendencia de Bancos). Unauthorized access to financial systems is a serious crime. See [DISCLAIMER](DISCLAIMER).

---

## License

Proprietary — All Rights Reserved. See [LICENSE](LICENSE).

Upstream imported skills retain their original Apache 2.0 license (see each file).

---

<div align="center">

**KRYON** — Autonomous Cybersecurity Agent for Financial Services

[GitHub](https://github.com/skyvanguard/Kryon) · [Issues](https://github.com/skyvanguard/Kryon/issues) · [Releases](https://github.com/skyvanguard/Kryon/releases) · [Deployment Guide](DEPLOYMENT.md)

</div>
