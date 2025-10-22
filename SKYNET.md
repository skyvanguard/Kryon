# SKYNET.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**SKYNET** (Autonomous Cybersecurity Intelligence System) is an advanced AI-powered framework for offensive and defensive security operations. Built on autonomous agent architecture, SKYNET deploys specialized "Terminator Units" capable of conducting sophisticated security assessments, vulnerability research, and threat mitigation with minimal human intervention.

**Version:** 1.0.0 (Genesis)
**Code Name:** Genesis
**Framework Type:** Autonomous AI Cybersecurity

## Build, Test, and Development Commands

### Installation and Setup
```bash
# Install dependencies using uv
uv sync --all-extras --all-packages --group dev

# Create virtual environment (for development)
python3.12 -m venv skynet_env
source skynet_env/bin/activate  # On Windows: skynet_env\Scripts\activate
pip install -e .

# Install pre-commit hooks (required before contributing)
pip install pre-commit
pre-commit install
```

### Running SKYNET
```bash
# Basic launch - Initialize SKYNET Core
skynet

# With specific Terminator unit
SKYNET_CORE=t800_infiltrator SKYNET_MODEL=gpt-4o skynet

# With tracing disabled
SKYNET_TRACE=false skynet

# Mission mode
SKYNET_MISSION=recon TARGET=192.168.1.0/24 skynet

# Swarm mode (parallel operations)
SKYNET_SWARM_SIZE=3 SKYNET_CORE=t800_infiltrator skynet
```

### Testing
```bash
# Run all tests
uv run pytest

# Run with coverage (requires 95% coverage)
uv run coverage run -m pytest
uv run coverage report -m --fail-under=95
uv run coverage xml -o coverage.xml

# Run tests for Python 3.9 compatibility
UV_PROJECT_ENVIRONMENT=.venv_39 uv run --python 3.9 -m pytest

# Fix snapshot tests
uv run pytest --inline-snapshot=fix

# Create new snapshots
uv run pytest --inline-snapshot=create
```

### Code Quality
```bash
# Format code (automatically fixes issues)
uv run ruff format
uv run ruff check --fix

# Lint without auto-fixing
uv run ruff check

# Type checking
uv run mypy .

# Run pre-commit on all files
pre-commit run --all-files
```

### Documentation
```bash
# Build documentation locally
uv run mkdocs build

# Serve documentation with live reload
uv run mkdocs serve

# Deploy documentation to GitHub Pages
uv run mkdocs gh-deploy --force --verbose
```

### Utility Commands
```bash
# Replay a SKYNET session from logs
skynet-replay <log_file.jsonl>

# Generate asciinema recording
skynet-asciinema <log_file.jsonl>

# Convert to GIF
skynet-gif <log_file.jsonl>
```

## Architecture Overview

### Core Components

**Autonomous Intelligence Framework**: SKYNET is built on 8 foundational pillars:
1. **Agents** (Terminator Units) - Autonomous decision-making entities
2. **Tools** (Weapon Systems) - Security capabilities organized by attack phase
3. **Handoffs** - Agent-to-agent task delegation
4. **Patterns** - Coordination strategies (Swarm, Hierarchical, etc.)
5. **Turns** - Interaction cycles (reasoning + action)
6. **Tracing** - OpenTelemetry-based observability
7. **Defense Protocols** (Guardrails) - Security against prompt injection
8. **HITL** (Human-in-the-Loop) - Human oversight capability

**Terminator Units**: Each agent is a specialized autonomous system. Units perceive their environment through "sensors" (tools), reason about objectives, and execute actions via "weapon systems." Key unit files are in `src/skynet/agents/`.

### Terminator Units Overview

**T-Series (Offensive):**
- `t800_infiltrator.py` - Advanced infiltration and exploitation
- `t1000_hunter.py` - Bug bounty and vulnerability research
- `t600_scout.py` - Basic reconnaissance and enumeration

**Guardian Series (Defensive):**
- `guardian_protocol.py` - System defense and hardening
- `forensic_analyzer.py` - Digital forensics and incident response

**HK-Series (Specialized):**
- `hk_aerial.py` - Network traffic analysis
- `neural_extractor.py` - Memory dump analysis
- `tech_com_reverse.py` - Reverse engineering
- `mobile_infiltrator.py` - Mobile security testing

**Command Units:**
- `central_core.py` - Strategic planning and coordination
- `target_validator.py` - Objective validation

**Weapon Systems**: Tools organized by the cyber kill chain in `src/skynet/tools/`:
- `reconnaissance/` - Recon and weaponization
- `exploitation/` - Exploitation tools
- `privilege_escalation/` - Privilege escalation
- `lateral_movement/` - Lateral movement
- `data_exfiltration/` - Data exfiltration
- `command_and_control/` - C2 capabilities

**Coordination Patterns**: Located in `src/skynet/agents/patterns/`, these define multi-agent strategies:
- `parallel_offensive_patterns.py` - Parallel/swarm attacks
- `red_team.py`, `red_blue_team.py` - Hierarchical team patterns
- `offsec.py` - Offensive security workflows
- Pattern types: Swarm (decentralized), Hierarchical, Chain-of-Thought, Recursive

**REPL System** (`src/skynet/repl/`): Interactive CLI with Terminator-themed interface. Major commands include `/agent`, `/model`, `/config`, `/help`, `/memory`, `/load`, `/mcp`, `/history`, `/graph`, `/workspace`.

### Key Architectural Concepts

**Autonomous Operation**:
- An **interaction** is one reasoning+action cycle by a Terminator unit (LLM inference + 0-n weapon system calls)
- A **turn** is a full cycle of one or more interactions that ends when the unit returns `None`
- A **mission** is a complete objective with multiple turns and potential unit handoffs
- Defined in `src/skynet/core.py`: `process_interaction()` and `run()`

**Handoffs**: Terminator units delegate tasks to specialized units via handoff functions. For example, T-800 Infiltrator might hand off to Central Core for strategic planning, then to T-1000 Hunter for specific exploitation.

**Defense Protocols** (`src/skynet/agents/guardrails.py`): Multi-layered security protecting against:
- Prompt injection attacks (input validation)
- Dangerous command execution (output sanitization)
- Base64/Base32 encoded malicious payloads
- Configurable via `SKYNET_DEFENSE_PROTOCOLS` environment variable

**Tracing**: Uses OpenTelemetry standard via Phoenix for observability. Tracks unit interactions, weapon usage, and attack vectors. Controlled by `SKYNET_TRACE` environment variable.

**HITL (Human-in-the-Loop)**: Press `Ctrl+C` during execution to interrupt and provide guidance. Core to SKYNET's semi-autonomous design philosophy. Implemented in `cli.py` and `core.py`.

### Mission System (NEW)

**In-Context Learning (ICL)**: Load previous mission logs directly into context using `/load` command:
```bash
/load logs/skynet_20250408_111856.jsonl         # Load into current unit
/load <file> agent <name>                        # Load into specific unit
/load <file> all                                 # Distribute across all units
```

**Mission Planning**: New `src/skynet/missions/` module for structured operations:
```python
from skynet.missions import ReconMission

mission = ReconMission(
    target="192.168.1.0/24",
    objectives=["identify_assets", "map_services", "find_vulns"],
    terminator_units=["t600_scout", "t800_infiltrator"],
    max_time=3600
)

result = await mission.execute()
report = mission.generate_report()
```

### MCP (Model Context Protocol) Integration

SKYNET supports MCP servers for weapon system integration via two transports:
- **stdio**: Local subprocess servers (`MCPServerStdio`)
- **SSE**: Remote HTTP servers (`MCPServerSse`)

CLI commands: `/mcp load`, `/mcp add`, `/mcp list`

## Project Structure

```
src/skynet/
├── __init__.py              # Package initialization (v1.0.0, Genesis)
├── cli.py                   # Main CLI entrypoint
├── util.py                  # Utility functions (rich formatting, timing)
├── agents/                  # Terminator Unit implementations
│   ├── patterns/           # Coordination patterns (swarm, hierarchical)
│   ├── t800_infiltrator.py # Advanced infiltration unit
│   ├── t1000_hunter.py     # Bug bounty specialist
│   ├── guardian_protocol.py # Defense unit
│   └── [other units]
├── autonomy/               # NEW: Autonomous decision-making
│   ├── decision_engine.py  # Autonomous decision logic
│   ├── mission_planner.py  # Mission planning
│   └── learning_system.py  # Adaptive learning
├── internal/               # Internal SKYNET functions
├── prompts/                # Unit system prompts
├── repl/                   # CLI interface (Terminator theme)
│   ├── commands/          # REPL command implementations
│   └── ui/                # UI components (banner, prompt, toolbar)
├── sdk/                    # SKYNET SDK
│   └── agents/            # Core agent SDK
├── tools/                  # Weapon Systems by kill chain phase
│   ├── reconnaissance/
│   ├── exploitation/
│   ├── privilege_escalation/
│   ├── lateral_movement/
│   ├── data_exfiltration/
│   └── command_and_control/
├── missions/               # NEW: Mission system
│   ├── mission.py         # Base mission class
│   ├── ctf_mission.py
│   ├── pentest_mission.py
│   └── recon_mission.py
└── intelligence/           # NEW: Intelligence gathering
    ├── osint_enhanced.py
    ├── vulnerability_db.py
    └── exploit_library.py
```

## Configuration

### Required Environment Variables
- `OPENAI_API_KEY` - Must be set (use "sk-1234" as placeholder if not using OpenAI)

### Core SKYNET Variables
- `SKYNET_MODEL` - AI model to use (default: "gpt-4o")
- `SKYNET_CORE` - Primary Terminator unit (default: "t800_infiltrator")
- `SKYNET_TRACE` - Enable operation tracing (default: "true")
- `SKYNET_DEFENSE_PROTOCOLS` - Enable security guardrails (default: "true")
- `SKYNET_MAX_TURNS` - Maximum turns per operation (default: "inf")
- `SKYNET_DEBUG` - Debug level: 0=tool outputs only, 1=verbose, 2=CLI debug
- `SKYNET_STREAM` - Enable streaming output (default: "false")
- `SKYNET_TELEMETRY` - Enable telemetry (default: "true")
- `SKYNET_SWARM_SIZE` - Number of parallel units (default: "1")
- `SKYNET_AUTONOMOUS_MODE` - Full autonomy vs HITL (default: "false")

### Mission Variables
- `SKYNET_MISSION` - Mission type (recon, pentest, ctf)
- `TARGET` - Mission target
- `SKYNET_SECTOR` - Operational sector/workspace

### Model Providers
Supports 300+ models via LiteLLM. Configure via environment:
- OpenAI: `OPENAI_API_KEY`, `OPENAI_BASE_URL`
- Anthropic: `ANTHROPIC_API_KEY`
- DeepSeek: `DEEPSEEK_API_KEY`
- Ollama: `OLLAMA_API_BASE` (must include `/v1` suffix)
- OpenRouter: `OPENROUTER_API_KEY`, `OPENROUTER_API_BASE`
- Azure: `AZURE_API_KEY`, `AZURE_API_BASE`, set model as `azure/<deployment-name>`

## Development Guidelines

### Terminator Unit Development
- Each unit in `src/skynet/agents/` defines `name`, `instructions`, `tools`, and `model`
- Use appropriate unit for the mission (see README-SKYNET.md for capability matrix)
- Units implement autonomous ReACT pattern: observe → reason → act cycle
- Add handoffs for task delegation to specialized units

### Weapon System Development
- Place tools in appropriate kill chain category under `src/skynet/tools/`
- Tools use function decorators: `@function_tool` from SDK
- Common utilities in `src/skynet/tools/common.py`
- Built-in systems: `generic_linux_command`, `execute_code`, `web_search`, `ssh_tunnel`

### Coordination Pattern Development
- Patterns define multi-unit coordination in `src/skynet/agents/patterns/`
- Inherit from base pattern class, define unit relationships and handoff logic
- Types: Swarm (P2P), Hierarchical (top-down), Chain-of-Thought (sequential), Recursive

### Mission Development
- Create mission types in `src/skynet/missions/`
- Inherit from base `Mission` class
- Define objectives, unit assignments, and success criteria
- Implement `execute()` and `generate_report()` methods

### Testing Requirements
- Minimum 95% code coverage enforced
- Use pytest with async support
- Mock model calls unless marked with `@pytest.mark.allow_call_model_methods`
- Test both success and failure paths for defense protocols

### Code Style
- Line length: 100 characters
- Use ruff for formatting and linting (auto-configured)
- Type hints preferred but not strictly enforced
- Google-style docstrings for public APIs
- Terminator/military terminology in comments and docs

## Sectors and Logging

SKYNET uses sector-based organization:
- Default sector: `.skynet/<sector_name>/`
- Logs stored in: `logs/` directory (JSONL format)
- Log format: `skynet_YYYYMMDD_HHMMSS.jsonl`
- Sector controlled by: `SKYNET_SECTOR`, `SKYNET_SECTOR_DIR`

## Important Notes

- **License**: MIT License with full attribution to original components (OpenAI, CAI)
- **Security**: Framework designed for authorized security testing only (pentesting, CTFs, research)
- **HITL Philosophy**: SKYNET emphasizes semi-autonomous operation with human oversight
- **Model Independence**: Works with any LiteLLM-supported provider (300+ models)
- **No Assistants API**: Uses Chat Completions API, stateless between calls

## Troubleshooting

**Ollama 404 errors**: Set `OLLAMA_API_BASE=http://IP:PORT/v1` (must include `/v1` suffix)

**Package not found**: Always create fresh virtual environment when updating SKYNET

**Pre-commit fails**: Run `pre-commit run --all-files` and fix issues before committing

**Coverage below 95%**: Add tests for uncovered code paths, especially error handling

**Import errors after transformation**: Verify all `from cai.*` imports changed to `from skynet.*`

## Transformation Status

**Current Status**: Partially transformed from CAI to SKYNET
- ✅ Package structure renamed (src/cai → src/skynet)
- ✅ Core configuration updated
- ✅ Banner and UI themed
- ✅ Documentation created (README-SKYNET.md, LICENSE-SKYNET)
- ⚠️ **PENDING**: Agent files need renaming (see TRANSFORMATION_GUIDE.md)
- ⚠️ **PENDING**: System prompts need rewriting
- ⚠️ **PENDING**: Import statements need mass update
- ⚠️ **PENDING**: New features need implementation (missions, intelligence, autonomy)

See **TRANSFORMATION_GUIDE.md** for complete transformation checklist and instructions.

## Quick Reference

### Common Commands
```bash
# Initialize SKYNET
skynet

# Select specific Terminator unit
SKYNET> /agent select t800_infiltrator

# View available units
SKYNET> /agent list

# Load previous mission logs
SKYNET> /load logs/skynet_20250408_111856.jsonl

# Configure swarm
SKYNET> /parallel add t800_infiltrator
SKYNET> /parallel add hk_aerial

# Execute mission
SKYNET> Compromise target network 192.168.1.0/24
```

### Key Directories for Development
- `src/skynet/agents/` - Add new Terminator units here
- `src/skynet/tools/` - Add new weapon systems here
- `src/skynet/missions/` - Add new mission types here
- `src/skynet/prompts/` - Update unit system prompts here
- `docs/` - Update documentation here
- `tests/` - Add tests here

## Attribution

Built upon:
- **OpenAI Agents Python** (MIT) - Base agent architecture
- **CAI Framework** (MIT + Proprietary) by Alias Robotics S.L. - Cybersecurity AI concepts

Full attribution in LICENSE-SKYNET and ACKNOWLEDGMENTS.md
