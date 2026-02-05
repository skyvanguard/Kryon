# KRYON Configuration Reference

Complete reference for all KRYON configuration options.

## Environment Variables

### AI Provider Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `OPENAI_API_KEY` | OpenAI API key | - | One of these |
| `ANTHROPIC_API_KEY` | Anthropic API key | - | is required |
| `DEEPSEEK_API_KEY` | DeepSeek API key | - | |
| `OLLAMA_API_BASE` | Ollama server URL | `http://localhost:11434/v1` | |
| `OPENROUTER_API_KEY` | OpenRouter API key | - | |
| `AZURE_API_KEY` | Azure OpenAI key | - | |
| `AZURE_API_BASE` | Azure OpenAI endpoint | - | |

### Core Settings

| Variable | Description | Default | Values |
|----------|-------------|---------|--------|
| `KRYON_MODEL` | AI model to use | `gpt-4o` | Any supported model |
| `KRYON_CORE` | Security agent | `t800_infiltrator` | See agents list |
| `KRYON_GUARDRAILS` | Enable security guardrails | `true` | `true`/`false` |
| `KRYON_STREAM` | Enable streaming output | `false` | `true`/`false` |
| `KRYON_DEBUG` | Debug verbosity | `1` | `0`, `1`, `2` |

### Security & Privacy

| Variable | Description | Default | Recommendation |
|----------|-------------|---------|----------------|
| `KRYON_GUARDRAILS` | Security guardrails | `true` | Always `true` in prod |
| `KRYON_TELEMETRY` | Anonymous telemetry | `true` | `false` for enterprise |
| `KRYON_TRACING` | Operation tracing | `true` | `false` unless debugging |
| `KRYON_PRICE_LIMIT` | Max cost per session ($) | `1` | Set appropriate limit |

### Operational Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `KRYON_WORKSPACE_DIR` | Workspace directory | `.kryon` |
| `KRYON_SECTOR` | Operational sector name | `default` |
| `KRYON_MAX_TURNS` | Max conversation turns | `inf` |
| `KRYON_SWARM_SIZE` | Parallel agents count | `1` |
| `KRYON_AUTONOMOUS_MODE` | Less human approval | `false` |

### Memory Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `KRYON_MEMORY` | Memory mode | `false` |
| `KRYON_MEMORY_ONLINE` | Online memory updates | `false` |
| `KRYON_MEMORY_OFFLINE` | Offline processing | `false` |
| `KRYON_MEMORY_ONLINE_INTERVAL` | Update interval (turns) | `5` |

---

## Available Agents

| Agent | Specialization | Best For |
|-------|----------------|----------|
| `t800_infiltrator` | Offensive security | Penetration testing |
| `t1000_hunter` | Bug bounty hunting | Web security testing |
| `t600_scout` | Reconnaissance | Initial enumeration |
| `guardian_protocol` | Defensive security | System hardening |
| `forensic_analyzer` | Digital forensics | Incident response |
| `hk_aerial` | Network security | Traffic analysis |
| `codeagent` | Code analysis | Exploit development |
| `central_core` | Strategic planning | High-level analysis |

---

## Supported Models

### OpenAI

- `gpt-4o` (recommended)
- `gpt-4o-mini`
- `gpt-4-turbo`
- `o1-preview`
- `o1-mini`

### Anthropic

- `claude-3-5-sonnet`
- `claude-3-opus`
- `claude-3-haiku`

### DeepSeek

- `deepseek-chat`
- `deepseek-coder`

### Ollama (Local)

- `qwen2.5:14b`
- `qwen2.5:72b`
- `llama3.1:70b`
- `codellama:34b`
- `mistral:7b`

---

## Configuration Examples

### Enterprise (High Security)

```bash
OPENAI_API_KEY="sk-..."
KRYON_MODEL="gpt-4o"
KRYON_CORE="guardian_protocol"
KRYON_GUARDRAILS="true"
KRYON_TELEMETRY="false"
KRYON_TRACING="false"
KRYON_DEBUG="0"
KRYON_PRICE_LIMIT="100"
KRYON_AUTONOMOUS_MODE="false"
```

### Bug Bounty

```bash
ANTHROPIC_API_KEY="sk-ant-..."
KRYON_MODEL="claude-3-5-sonnet"
KRYON_CORE="t1000_hunter"
KRYON_GUARDRAILS="true"
KRYON_STREAM="true"
KRYON_DEBUG="1"
```

### CTF Competition

```bash
OPENAI_API_KEY="sk-..."
KRYON_MODEL="gpt-4o"
KRYON_CORE="t600_scout"
KRYON_SWARM_SIZE="3"
CTF_NAME="hackthebox"
CTF_IP="10.10.10.1"
```

### Air-Gapped (Offline)

```bash
OLLAMA_API_BASE="http://localhost:11434/v1"
KRYON_MODEL="qwen2.5:14b"
KRYON_CORE="t800_infiltrator"
KRYON_TELEMETRY="false"
KRYON_TRACING="false"
```

---

## Command Line Options

```bash
kryon [OPTIONS]

Options:
  --model MODEL      Override KRYON_MODEL
  --agent AGENT      Override KRYON_CORE
  --workspace DIR    Override KRYON_WORKSPACE_DIR
  --debug LEVEL      Override KRYON_DEBUG
  --version          Show version
  --help             Show help
```

---

## See Also

- [Deployment Guide](deployment.md)
- [Security Hardening](security.md)
- [Troubleshooting](troubleshooting.md)
