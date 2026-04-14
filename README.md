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

**Self-Improving Autonomous Cybersecurity Agent**

*One prompt. Full engagement. Learns from every pentest.*

[![CI](https://github.com/skyvanguard/Kryon/actions/workflows/ci.yml/badge.svg)](https://github.com/skyvanguard/Kryon/actions/workflows/ci.yml)
[![Security Scan](https://github.com/skyvanguard/Kryon/actions/workflows/security-scan.yml/badge.svg)](https://github.com/skyvanguard/Kryon/actions/workflows/security-scan.yml)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-2.1.0_Skillforge-purple.svg)](CHANGELOG.md)
[![Skills](https://img.shields.io/badge/skills-67_playbooks-gold.svg)](#skill-library)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)

[Installation](#installation) | [Use Cases](#use-cases) | [Skill System](#skill-system) | [Quick Start](#quick-start) | [Learning Loop](#self-improving-loop)

</div>

---

## What is KRYON?

KRYON is an **autonomous cybersecurity agent** that executes full security engagements from a single prompt. Give it a target and it chains tools (nmap, whatweb, gobuster, nuclei, wpscan, hashcat, volatility, frida...), produces a professional report, and **remembers what worked** for next time.

Built on a **dynamic skill system with 67 playbooks** covering offensive security, defensive security, forensics, CTFs, compliance auditing, server hardening, and specialized domains like banking and mobile apps. Runs locally on Gemma 4 (zero cost per engagement) or any major cloud LLM.

### One prompt, full engagement

```
KRYON> haceme un analisis de seguridad de www.target.com

 ✶ Kryon [recon-scout] Investigating…  (3s)
 ● recall_similar_experiences → 2 prior engagements
 ● nmap -sV -sC -T4 → 4 ports open
 ● whatweb_scan → Apache, Bootstrap, WordPress?
 ● run_command → 12 directories found
 ● nuclei_scan → 1 finding (uploads.zip exposed)

╭─ Kryon ────────────────────────────────────────────╮
│ ## Security Assessment: www.target.com              │
│ **IP:** 54.69.84.63 | **Stack:** Apache, Bootstrap │
│ **Ports:** 80, 110, 443, 993                       │
│ **Finding (MEDIUM):** uploads.zip publicly exposed │
│ **Recommendations:** 4 actionable items            │
╰────────────────────────────────────────────────────╯

✅ Experience auto-saved: eng_3e03db5ef859
```

### At a Glance

| Component | Count |
|-----------|:-----:|
| Skills (dynamic playbooks) | **67** |
| Security Tools | 204+ |
| API Endpoints | 136 |
| Compliance Frameworks | 9 |
| Supported LLM Providers | 7 |
| Test Suite | 1896 passed |

### Core Capabilities

- **Autonomous tool chaining** — one prompt, full recon+exploit chain, no manual intervention
- **Self-improving loop** — ChromaDB experience store; recalls similar past targets to optimize new engagements
- **Dynamic skill system** — 67 markdown playbooks, hot-reloadable, `/skill import` from 754-skill upstream catalog
- **Local-first** — designed for Gemma 4 26B (MoE) via Ollama with 12 GB VRAM. Zero API cost. Full privacy.
- **Multi-model** — works with GPT-4o, Claude, DeepSeek, Groq, Azure, etc.
- **Context management** — tool output capping, micro-compaction, session memory, magic-doc auto-reports
- **Safe remediation** — `safe-modification` + `rollback-recovery` skills ensure diagnose→propose→backup→apply→verify flow for any system change
- **204+ tools** across 35 categories covering the full kill chain
- **Enterprise features** — multi-tenancy, JWT/RBAC, audit logging, SIEM integration

---

## Use Cases

Kryon adapts to the engagement. Matched skills change based on what you ask for.

### Bug Bounty & Pentesting

```
KRYON> pentesta www.target.com
KRYON> buscá vulnerabilidades en este WordPress
KRYON> hacé SSRF testing de api.target.com
KRYON> probá auth bypass en la app
```
→ Loads: recon-scout, vuln-hunter, wordpress-audit, sqli-exploit, ssrf-exploit, jwt-attacks, etc.

### CTF Competitions

```
KRYON> resolvé esta máquina de HackTheBox: 10.10.10.5
KRYON> este challenge tiene un flag, el binario está en /tmp/chall
```
→ Loads: ctf-master, pentest, linux-privesc, exploitation-specific skills.

### Forensics & Incident Response

```
KRYON> analizá este memory dump con volatility
KRYON> investigá este phishing email (eml adjunto)
KRYON> detectá lateral movement en los logs
KRYON> contain este breach activo
```
→ Loads: memory-forensics, wireshark-analysis, disk-imaging, browser-forensics, phishing-investigation, active-breach-containment, ir-playbook.

### Server Hardening (SSH remediation)

```
KRYON> audita y corrige mi servidor admin@192.168.1.10
```
→ Loads: server-hardening + safe-modification + rollback-recovery.
→ Diagnose (read-only) → Propose (table + STOP) → Apply (with backups) → Verify.

### Financial & Banking (specialty)

```
KRYON> haceme un PCI-DSS audit de banco.com.py
KRYON> auditá la app móvil del banco
KRYON> evaluá el core banking T24
KRYON> testeá la pasarela de pago
KRYON> hacé SWIFT CSP audit
```
→ Loads: pci-dss-audit, core-banking-assessment, mobile-banking-audit, payment-gateway-testing, swift-network-security, fraud-detection.

### Cloud / Container Security

```
KRYON> audita los buckets S3 de mi cuenta AWS
KRYON> buscá privilege escalation en AWS
KRYON> analizá logs de Kubernetes audit
KRYON> hardeneá estos containers Docker
```
→ Loads: aws-s3-audit, aws-privesc, k8s-audit, docker-hardening, trivy-scan.

### Active Directory / Windows

```
KRYON> hacé Kerberoast en el DC
KRYON> testeá DCSync exploit
KRYON> buscá AD CS ESC1
```
→ Loads: active-directory-recon, dcsync-attack, detect-kerberoast, ad-cs-esc1.

### OSINT & Threat Intel

```
KRYON> hacé OSINT de acme-corp.com
KRYON> mapeá los TTPs de este APT
```
→ Loads: osint, mitre-attack-mapping.

---

## Skill System

Kryon's intelligence lives in **67 markdown playbooks** organized by purpose:

```
src/kryon/skills/playbooks/
├── (11 core skills)          — recon, pentest, vuln-hunter, ctf-master,
│                                appsec, forensics, ssl-audit,
│                                server-hardening, safe-modification, …
├── imported/ (28 skills)     — from mukul975/Anthropic-Cybersecurity-Skills
│                                (Apache 2.0, MITRE ATT&CK / NIST CSF mapped)
│                                web offensive, AD, cloud, container,
│                                forensics, detection, IR, …
└── banking/ (8 skills)       — specialization: pci-dss-audit, core-banking,
                                 swift-csp, mobile-banking, atm-security,
                                 payment-gateway, fraud-detection, open-banking
```

Skills are **auto-matched** by target tech, open ports, and user keywords. Priority-based selection with a token budget to fit the 32K context window. A request like *"auditá la seguridad web"* loads `recon-scout`. *"investigá este phishing email"* loads `phishing-investigation`. *"hacé PCI-DSS audit"* loads `pci-dss-audit` + `safe-modification` + `core-banking-assessment`.

### `/skill` command — dynamic library

Any of the **754 upstream skills** can be installed during a session without rebuild:

```bash
KRYON> /skill list                      # All 67 loaded
KRYON> /skill show recon-scout          # View playbook content
KRYON> /skill search kubernetes         # Search upstream catalog
KRYON> /skill import exploiting-zerologon-vulnerability-cve-2020-1472
KRYON> /skill reload                    # After editing a .md
```

### Custom skills

Drop a `.md` in `src/kryon/skills/playbooks/` — Kryon picks it up automatically:

```yaml
---
name: my-custom-audit
description: "My specialized playbook"
triggers:
  tech: ["nginx"]
  keywords: ["nginx", "reverse proxy"]
priority: 20
required_tools: [run_command, nuclei_scan]
---

## Workflow
1. Verify nginx version
2. ...
```

---

## Self-Improving Loop

Every engagement is stored in ChromaDB with target profile, attack chain, outcome, and signals. On the next engagement, Kryon queries `recall_similar_experiences` and **optimizes its plan based on what worked before**.

```
Session 1: scan target-a.com → nmap→whatweb→gobuster→nuclei → saved

Session 2: scan similar-site.com
  → recall: "Against Apache+Bootstrap targets, 
             nmap→whatweb→nuclei found CVE in 5 min"
  → Kryon goes straight to nuclei, skipping redundant recon → 3x faster
```

### REPL Commands

| Command | Action |
|---------|--------|
| `/skill list/show/search/import/reload` | Manage playbook library |
| `/experiences list/show/search/close` | Manage engagement learning |
| `/flush` | Clear agent history + session memory |
| `/compact` | Manual conversation compaction |

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

# Launch stack
docker compose -f docker/docker-compose.kali.yml \
               -f docker/docker-compose.override.yml \
               --env-file docker/.env.docker up -d

# Pull recommended model (Gemma 4 26B MoE — runs like 4B, quality of 26B)
docker exec kryon-ollama ollama pull gemma4:26b

# Create 32K context variant
docker exec kryon-ollama sh -c 'printf "FROM gemma4:26b\nPARAMETER num_ctx 32768\n" > /tmp/Modelfile && ollama create gemma4:26b-32k -f /tmp/Modelfile'

# Pull embedding model for RAG
docker exec kryon-ollama ollama pull nomic-embed-text

# Launch REPL
docker exec -it kryon kryon
```

### Configuration

Key settings in `docker/.env.docker`:

```bash
# Model (recommended: Gemma 4 26B MoE — zero API cost)
KRYON_MODEL=gemma4:26b-32k
OPENAI_API_KEY=ollama
OPENAI_BASE_URL=http://ollama:11434/v1
OLLAMA=true

# Unified agent with dynamic skills
KRYON_AGENT_TYPE=kryon
KRYON_UNIFIED=true

# Runtime tuning
KRYON_MAX_TURNS=50
KRYON_FORCE_TOOL_TURNS=8
KRYON_MEMORY=true
KRYON_STREAM=false

# RAG embeddings
KRYON_EMBEDDING_MODEL=nomic-embed-text
KRYON_EMBEDDING_BASE_URL=http://ollama:11434

# Optional: SSH credentials for server-hardening remediation
# KRYON_SSH_USER=admin
# KRYON_SSH_HOST=192.168.1.10
# KRYON_SSH_PASS=your-password
```

---

## Quick Start

```bash
docker exec -it kryon kryon

# Autonomous security assessment (one prompt, full chain)
KRYON> haceme un analisis de seguridad de www.target.com

# CTF mode
KRYON> resolvé esta máquina: 10.10.10.5

# Server hardening
KRYON> audita y corrige mi servidor admin@192.168.1.10

# Forensics
KRYON> analizá este memory dump con volatility

# Financial / banking (specialty)
KRYON> haceme un PCI-DSS audit de banco.com.py

# View what Kryon learned
KRYON> /experiences list
KRYON> /skill list

# Exit (auto-saves experience)
KRYON> /exit
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
| OpenRouter | 200+ models | `OPENROUTER_API_KEY` |

**Recommended**: Gemma 4 26B via Ollama. MoE architecture (3.8B active/26B total) runs fast on consumer GPU (12 GB VRAM) with near-26B quality. Native tool calling, thinking, 262K context. Zero per-engagement cost.

---

## Compliance Coverage

Skills map findings to frameworks automatically:

| Framework | Coverage |
|-----------|----------|
| **PCI-DSS v4.0.1** | 12 requirements, CDE scoping, SAQ A→D (via banking/pci-dss-audit) |
| **OWASP Top 10** | Web + API + Mobile |
| **MITRE ATT&CK** | Technique mapping via imported skills |
| **NIST CSF 2.0** | Control alignment |
| **CIS Benchmarks** | Linux, Windows, Docker, Kubernetes |
| **SWIFT CSP (CSCF)** | 32 controls (for banking clients) |
| **FAPI / PSD2** | Open Banking API security |
| **FATF AML** | Money mule, KYC bypass (for fraud detection) |
| **HIPAA, SOC2, GDPR** | Via compliance/ module |

---

## Architecture

```
src/kryon/
├── skills/             # 67 dynamic playbooks (primary interface in v2.x)
│   ├── loader.py       #   Matches skills by tech/port/keyword triggers
│   ├── unified_agent.py#   Single "Kryon" agent with composed prompt
│   └── playbooks/      #   *.md files — core, imported/, banking/
├── learning/           # Self-improving loop (ChromaDB experiences)
├── services/           # Context mgmt (compact, session memory, tool cap)
├── sdk/                # Agent runtime SDK (Agent, Runner, Handoff, MCP)
├── agents/             # Legacy 33 agents (backward compat via /agent select)
├── tools/              # 204+ security tools in 35 categories
├── knowledge/          # RAG: ChromaDB + Ollama embeddings + auto-updater
├── server/             # FastAPI — 136 endpoints, multi-tenant, JWT/RBAC
├── repl/               # Interactive CLI + Claude Code-style spinner
├── compliance/         # 9 frameworks (PCI-DSS, OWASP, ATT&CK, etc.)
├── reporting/          # PDF/DOCX/HTML report generation
└── memory/             # SQLite store (16 migrations)
```

---

## Docker Stack

```bash
# Full Kali + Ollama + Kryon
docker compose -f docker/docker-compose.kali.yml \
               -f docker/docker-compose.override.yml up -d

# Interactive REPL
docker exec -it kryon kryon

# Kali shell (nmap, metasploit, sqlmap, hydra, burp, wpscan, etc.)
docker exec -it kryon bash

# VPN for CTF / restricted engagement
docker exec -u root -d kryon openvpn --config /workspace/htb.ovpn
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

### Custom skills

Drop a `.md` in `src/kryon/skills/playbooks/` (or subdirectory) with YAML frontmatter. Kryon picks it up automatically. Generic-value skills can be contributed upstream to [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) under Apache 2.0.

### Code

See [CONTRIBUTING.md](CONTRIBUTING.md) for code contributions.

---

## Disclaimer

> **KRYON is designed exclusively for authorized security testing, research, and education.**
>
> You must have **explicit written authorization** before testing any system you do not own. For financial / banking clients, compliance with local regulations (BCP Paraguay, SIB, Superintendencia de Bancos, equivalent bodies in your jurisdiction) is mandatory. Unauthorized access to computer systems is illegal. See [DISCLAIMER](DISCLAIMER).

---

## License

Proprietary — All Rights Reserved. See [LICENSE](LICENSE).

Upstream imported skills retain their original Apache 2.0 license (see each file).

---

<div align="center">

**KRYON** — Self-Improving Autonomous Cybersecurity Agent

[GitHub](https://github.com/skyvanguard/Kryon) · [Issues](https://github.com/skyvanguard/Kryon/issues) · [Releases](https://github.com/skyvanguard/Kryon/releases) · [Deployment Guide](DEPLOYMENT.md)

</div>
