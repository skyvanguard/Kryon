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

**Autonomous Cybersecurity Intelligence Platform**

[![CI](https://github.com/skyvanguard/Kryon/actions/workflows/ci.yml/badge.svg)](https://github.com/skyvanguard/Kryon/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/skyvanguard/Kryon)](https://github.com/skyvanguard/Kryon/releases)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![AI Models](https://img.shields.io/badge/AI_Models-300+-purple.svg)](#supported-ai-models)
[![Stars](https://img.shields.io/github/stars/skyvanguard/Kryon?style=social)](https://github.com/skyvanguard/Kryon)

[Installation](#installation) | [Quick Start](#quick-start) | [Agents](#security-agents) | [Contributing](#contributing)

</div>

---

## What is KRYON?

KRYON is an open-source platform for building and deploying autonomous AI agents specialized in cybersecurity operations. It combines:

- **Autonomous Agents** - 20+ pre-built security agents for pentesting, forensics, and security research
- **Multi-Model Support** - Works with 300+ LLMs including GPT-4o, Claude, DeepSeek, Llama, and local models via Ollama
- **Security Tools Integration** - Native integration with nmap, metasploit, nuclei, and 50+ security tools
- **Agent SDK** - Build your own custom security agents with the KRYON SDK
- **Multi-Agent Patterns** - Swarm, Parallel, Hierarchical, Sequential, and Conditional execution
- **RAG Knowledge Base** - ExploitDB, NVD, and GitHub security scrapers with ChromaDB vector search

### Use Cases

- Automated penetration testing
- Bug bounty hunting
- CTF competitions
- Security research and education
- Incident response and forensics
- Vulnerability assessment

---

## Installation

### Requirements

- Python 3.10 or higher
- API key for at least one LLM provider (OpenAI, Anthropic, DeepSeek, etc.)

### Install from Source

```bash
git clone https://github.com/skyvanguard/Kryon.git
cd Kryon
pip install -e .

# With optional features
pip install -e .[rag,tracing,viz,voice]
```

### Configuration

Create a `.env` file:

```bash
# Choose your AI model (default: gpt-4o)
KRYON_MODEL="gpt-4o"  # or claude-3-5-sonnet, deepseek-chat, ollama/qwen2.5

# API Keys (add the ones you need)
OPENAI_API_KEY="sk-..."
ANTHROPIC_API_KEY="sk-ant-..."
DEEPSEEK_API_KEY="..."

# Optional: Local LLM via Ollama (no API key needed)
# OPENAI_BASE_URL="http://localhost:11434/v1"
# KRYON_MODEL="qwen2.5:7b"

# Optional: Default agent
KRYON_AGENT=pentest_agent
```

---

## Quick Start

```bash
# Launch KRYON
kryon

# Select an agent
KRYON> /agent pentest_agent

# Run a security assessment
KRYON> Scan 192.168.1.0/24 and identify vulnerabilities

# Parallel operations (Swarm Mode)
KRYON> /parallel 3
KRYON> Perform comprehensive assessment of target.com
```

---

## Security Agents

| Agent | Description |
|-------|-------------|
| `pentest_agent` | System infiltration and exploitation |
| `vuln_hunter` | Bug hunting and vulnerability research |
| `recon_scout` | Reconnaissance and enumeration |
| `guardian_protocol` | Defensive security and hardening |
| `forensic_analyzer` | Incident response and forensics |
| `network_analyst` | Network traffic analysis |
| `memory_analyst` | Memory forensics |
| `reverse_engineer` | Reverse engineering |
| `mobile_infiltrator` | Mobile security testing |
| `wireless_infiltrator` | WiFi security assessment |
| `ctf_master` | CTF competition solver |
| `central_core` | Mission coordination |

---

## Building Custom Agents

```python
from kryon.sdk.agents import Agent, function_tool

@function_tool
async def my_scan(target: str) -> str:
    """Run a custom scan against the target."""
    # your logic here
    return result

my_agent = Agent(
    name="Custom Scanner",
    instructions="You are a network security scanner...",
    tools=[my_scan],
)
```

---

## Supported AI Models

| Provider | Models | Config |
|----------|--------|--------|
| OpenAI | GPT-4o, O1, O3-mini | `OPENAI_API_KEY` |
| Anthropic | Claude 3.5/3.7 Sonnet | `ANTHROPIC_API_KEY` |
| DeepSeek | DeepSeek V3, R1 | `DEEPSEEK_API_KEY` |
| Ollama | Qwen, Llama, Mistral | `OPENAI_BASE_URL` |
| OpenRouter | 200+ models | `OPENROUTER_API_KEY` |
| Azure | Azure OpenAI | `AZURE_OPENAI_*` |

---

## Project Structure

```
Kryon/
├── src/kryon/
│   ├── agents/          # 20+ security agents
│   ├── sdk/             # Agent SDK (Agent, Runner, Handoff, Guardrail)
│   ├── tools/           # 31 tool categories
│   ├── knowledge/       # RAG engine + vector DB
│   ├── repl/            # Interactive CLI + commands
│   └── prompts/         # System prompts (markdown)
├── tests/               # Test suite
├── dashboard/           # Svelte web dashboard
├── docker/              # Production deployment
└── scripts/             # Utilities and validation
```

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
git clone https://github.com/skyvanguard/Kryon.git
cd Kryon
pip install -e .[dev]
pytest
```

---

## Disclaimer

**KRYON is for authorized security testing only.** Never use on systems without explicit authorization.

See [DISCLAIMER](DISCLAIMER) for full legal notice.

---

## License

MIT License - see [LICENSE](LICENSE)

---

<div align="center">

**KRYON** - Autonomous Cybersecurity Intelligence

[GitHub](https://github.com/skyvanguard/Kryon) | [Issues](https://github.com/skyvanguard/Kryon/issues)

</div>
