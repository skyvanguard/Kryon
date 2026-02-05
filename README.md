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

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/skyvanguard/Kryon/actions/workflows/ci.yml/badge.svg)](https://github.com/skyvanguard/Kryon/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/skyvanguard/Kryon/graph/badge.svg)](https://codecov.io/gh/skyvanguard/Kryon)
[![AI Models](https://img.shields.io/badge/AI_Models-300+-purple.svg)](#supported-ai-models)

[Installation](#installation) | [Quick Start](#quick-start) | [Documentation](#documentation) | [Contributing](#contributing)

</div>

---

## What is KRYON?

KRYON is an open-source platform for building and deploying autonomous AI agents specialized in cybersecurity operations. It combines:

- **Autonomous Agents** - Pre-built agents (Terminator Units) for pentesting, forensics, and security research
- **Multi-Model Support** - Works with 300+ LLMs including GPT-4, Claude, DeepSeek, Llama, and local models via Ollama
- **Security Tools Integration** - Native integration with nmap, metasploit, nuclei, and 50+ security tools
- **Agent SDK** - Build your own custom security agents with the KRYON SDK
- **Swarm Operations** - Deploy multiple agents working in parallel for complex missions

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

### Install from PyPI

```bash
# Basic installation
pip install kryon

# With all features
pip install kryon[rag,tracing,viz,voice]
```

### Install from Source

```bash
git clone https://github.com/skyvanguard/kryon.git
cd kryon
pip install -e .
```

### Configuration

Create a `.env` file:

```bash
# Choose your AI model
KRYON_MODEL="gpt-4o"  # or claude-3-5-sonnet, deepseek-chat, ollama/qwen2.5

# API Keys (add the ones you need)
OPENAI_API_KEY="sk-..."
ANTHROPIC_API_KEY="sk-ant-..."
DEEPSEEK_API_KEY="..."

# Optional: Default agent
KRYON_AGENT=t800_infiltrator
```

---

## Quick Start

### Launch KRYON

```bash
kryon
```

### Select an Agent

```bash
KRYON> /agent t800_infiltrator
```

### Run a Security Assessment

```bash
KRYON> Scan 192.168.1.0/24 and identify vulnerabilities
```

### Parallel Operations (Swarm Mode)

```bash
KRYON> /parallel 3
KRYON> Perform comprehensive assessment of target.com
```

---

## Agents (Terminator Units)

| Agent | Description |
|-------|-------------|
| `t800_infiltrator` | System infiltration and exploitation |
| `t1000_hunter` | Bug hunting and vulnerability research |
| `t600_scout` | Reconnaissance and enumeration |
| `guardian_protocol` | Defensive security and hardening |
| `forensic_analyzer` | Incident response and forensics |
| `hk_aerial` | Network traffic analysis |
| `neural_extractor` | Memory forensics |
| `tech_com_reverse` | Reverse engineering |
| `mobile_infiltrator` | Mobile security testing |
| `wireless_infiltrator` | WiFi security assessment |
| `central_core` | Mission coordination |

---

## Building Custom Agents

```python
from skynet.sdk.agents import Agent
from skynet.tools.reconnaissance import run_nmap

my_agent = Agent(
    name="Custom Scanner",
    instructions="You are a network security scanner...",
    tools=[run_nmap],
)

# Run the agent
result = my_agent.run("Scan 192.168.1.1")
```

See [examples/](examples/) for more.

---

## Supported AI Models

| Provider | Models | Config |
|----------|--------|--------|
| OpenAI | GPT-4o, O1, O3-mini | `OPENAI_API_KEY` |
| Anthropic | Claude 3.5/3.7 Sonnet | `ANTHROPIC_API_KEY` |
| DeepSeek | DeepSeek V3, R1 | `DEEPSEEK_API_KEY` |
| Ollama | Qwen, Llama, Mistral | `OLLAMA_API_BASE` |
| OpenRouter | 200+ models | `OPENROUTER_API_KEY` |
| Azure | Azure OpenAI | `AZURE_OPENAI_*` |

---

## Documentation

| Resource | Description |
|----------|-------------|
| [docs/](docs/) | Full documentation |
| [examples/](examples/) | Usage examples |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |

---

## Project Structure

```
kryon/
├── src/skynet/
│   ├── agents/          # Terminator units
│   ├── sdk/             # Agent SDK
│   ├── tools/           # Security tools
│   ├── repl/            # Interactive CLI
│   └── prompts/         # System prompts
├── examples/            # Usage examples
├── docs/                # Documentation
└── tests/               # Test suite
```

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Setup development environment
git clone https://github.com/skyvanguard/kryon.git
cd kryon
pip install -e .[dev]

# Run tests
pytest

# Format code
ruff format .
ruff check --fix .
```

---

## Disclaimer

**KRYON is for authorized security testing only.**

- Penetration testing with written permission
- Bug bounty programs
- CTF competitions
- Security research and education

**Never use on systems without explicit authorization.**

See [DISCLAIMER](DISCLAIMER) for full legal notice.

---

## License

MIT License - see [LICENSE](LICENSE)

---

<div align="center">

**KRYON** - Autonomous Cybersecurity Intelligence

[GitHub](https://github.com/skyvanguard/kryon) | [Issues](https://github.com/skyvanguard/kryon/issues)

</div>
