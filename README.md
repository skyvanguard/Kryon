# Skynet - CTF Agent Framework with RAG

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

> **⚡ Diseñado para Claude Code** - No necesita API calls, funciona directamente con tu terminal

**Skynet** is a powerful CTF (Capture The Flag) automation framework that combines specialized AI agents with Retrieval-Augmented Generation (RAG) for solving security challenges. Inspired by [CAI](https://github.com/aliasrobotics/cai), Skynet provides a modular, agent-based architecture optimized for Claude Code integration.

## 🎯 Key Features

- **Specialized AI Agents**: Multiple expert agents for different CTF categories
  - 🔍 **ReconAgent**: Network reconnaissance and enumeration
  - 🌐 **WebAgent**: Web application exploitation
  - 🔐 **CryptoAgent**: Cryptography and cryptanalysis
  - 🔬 **ForensicsAgent**: Digital forensics and file analysis
  - 💥 **ExploitAgent**: Binary exploitation and pwn challenges

- **🚩 Automatic Flag Detection**: Auto-detects and logs flags in all outputs
  - Supports HTB, CTFd, PicoCTF, and custom formats
  - Persistent flag tracking
  - Never lose a flag again!

- **RAG System**: Knowledge base with semantic search for CTF techniques
  - Store and retrieve previous CTF solutions
  - Augment agent context with relevant techniques
  - Support for multiple embedding providers (OpenAI, local)

- **Safety First**: Sandboxed command execution with whitelist
- **Extensive Tooling**: Wrappers for common security tools
- **Flexible CLI**: Interactive and command-line modes
- **Detailed Logging**: Full tracing of agent reasoning and actions

## Architecture

```
skynet/
├── core/              # Core framework components
│   ├── config.py      # Configuration management
│   ├── logging.py     # Logging and tracing
│   ├── executor.py    # Safe command execution
│   └── agent_manager.py # Agent orchestration
│
├── rag/               # RAG system
│   ├── embeddings.py  # Embedding generation
│   ├── vector_store.py # Vector database (ChromaDB)
│   └── retriever.py   # Context retrieval
│
├── agents/            # Specialized agents
│   ├── base_agent.py  # Base agent (ReAct pattern)
│   ├── recon_agent.py
│   ├── web_agent.py
│   ├── crypto_agent.py
│   └── forensics_agent.py
│
├── tools/             # Tool wrappers
│   ├── network.py     # Network tools (nmap, etc.)
│   ├── web.py         # Web tools (gobuster, sqlmap)
│   └── analysis.py    # Analysis tools (binwalk, etc.)
│
└── cli/               # Command-line interface
    └── main.py
```

## Installation

### Prerequisites

- Python 3.8+
- Common security tools (optional but recommended):
  - nmap, gobuster, sqlmap, nikto
  - john, hashcat, binwalk, exiftool
  - dig, curl, netcat

### Install Skynet

**Para instalación en tu notebook/máquina local, ver: [NOTEBOOK_SETUP.md](NOTEBOOK_SETUP.md)** ⭐

```bash
# 1. Clone the repository
git clone https://github.com/skyvanguard/Skynet.git
cd Skynet

# 2. Install dependencies
pip install -r requirements.txt

# 3. Verify installation
python scripts/verify_installation.py

# 4. Initialize knowledge base
python scripts/init_knowledge.py
```

### Configuration (Optional)

Las API keys son **opcionales** - solo necesarias si usas embeddings de OpenAI:

```bash
cp .env.example .env
# Edit .env only if using OpenAI
OPENAI_API_KEY=your_key_here  # Optional
```

**Nota**: Skynet funciona perfectamente sin API keys usando herramientas locales.

## Quick Start

### 🚀 Quick Commands for Claude Code

Estos comandos devuelven JSON para fácil parsing:

```bash
# Port scan rápido
python -m skynet.cli.quick scan 10.0.0.1

# Web enumeration
python -m skynet.cli.quick enum-web http://target.com

# File analysis
python -m skynet.cli.quick analyze suspicious.bin

# Search knowledge
python -m skynet.cli.quick search "sql injection"

# Crack hash
python -m skynet.cli.quick crack abc123...

# View flags
python -m skynet.cli.quick flags list

# Check binary security
python -m skynet.cli.quick exploit-check ./binary
```

📖 **Ver [CLAUDE_CODE_GUIDE.md](CLAUDE_CODE_GUIDE.md) para más ejemplos**

### Interactive Mode

```bash
python skynet.py interactive
```

In interactive mode, you can use commands like:

```
skynet> recon Scan 192.168.1.1 for open ports
skynet> web Test http://example.com for SQL injection
skynet> crypto Crack MD5 hash: 5d41402abc4b2a76b9719d911017c592
skynet> forensics Analyze file suspicious.png
skynet> exploit Analyze ./challenge binary
```

### Command-Line Mode

```bash
# Reconnaissance
python skynet.py run recon "Enumerate services on 10.0.0.1" --target 10.0.0.1

# Web exploitation
python skynet.py run web "Test for SQLi" --url "http://target.com/login.php?id=1"

# Cryptography
python skynet.py run crypto "Decrypt this ciphertext: SGVsbG8gV29ybGQ="

# Forensics
python skynet.py run forensics "Extract hidden data" --file suspicious.png
```

### Knowledge Management

Build your CTF knowledge base:

```bash
# Add knowledge manually
python skynet.py knowledge add --content "Use gobuster for directory enumeration" --category web

# Import from file
python skynet.py knowledge add --file techniques.txt --category crypto

# Import from directory
python skynet.py knowledge add --directory ./ctf_writeups/ --category general

# Search knowledge
python skynet.py knowledge search --query "SQL injection bypass techniques"

# Export/Import knowledge base
python skynet.py knowledge export --output my_knowledge.json
python skynet.py knowledge import --input my_knowledge.json
```

## Usage Examples

### Example 1: Network Reconnaissance

```bash
python skynet.py run recon \
  "Perform full reconnaissance on target" \
  --target hackthebox.com \
  --verbose
```

### Example 2: Web Application Testing

```bash
python skynet.py run web \
  "Test for common web vulnerabilities" \
  --url "http://vulnerable-app.com" \
  --verbose
```

### Example 3: Hash Cracking

```bash
python skynet.py run crypto \
  "Crack this password hash: \$2b\$12\$..." \
  --verbose
```

### Example 4: File Analysis

```bash
python skynet.py run forensics \
  "Analyze this file for hidden data" \
  --file challenge.png \
  --verbose
```

## Agent Types

### ReconAgent
- Port scanning (nmap)
- DNS enumeration
- Service identification
- Web server fingerprinting

### WebAgent
- Directory bruteforcing
- SQL injection testing
- XSS detection
- LFI/RFI testing
- WAF detection

### CryptoAgent
- Cipher identification
- Classical cipher breaking
- Hash cracking
- Encoding/decoding
- Frequency analysis

### ForensicsAgent
- File type analysis
- Metadata extraction
- Steganography detection
- String extraction
- PCAP analysis

## Advanced Configuration

Create a custom `config.json`:

```json
{
  "default_model": "claude-sonnet-4",
  "temperature": 0.7,
  "max_iterations": 25,
  "sandbox_mode": true,
  "allowed_commands": [
    "nmap", "gobuster", "sqlmap", "john",
    "binwalk", "strings", "curl", "dig"
  ],
  "log_level": "INFO"
}
```

Load custom config:

```bash
python skynet.py --config config.json run recon "Scan target"
```

## Development

### Adding a New Agent

1. Create a new agent class in `skynet/agents/`:

```python
from skynet.agents.base_agent import BaseAgent

class MyAgent(BaseAgent):
    def __init__(self, name: str = "MyAgent"):
        super().__init__(
            name=name,
            agent_type="my_type",
            description="My custom agent"
        )

    def _default_system_prompt(self) -> str:
        return "Your agent's system prompt"

    def _get_available_tools(self) -> List[Dict[str, Any]]:
        return [...]

    def _solve(self, task: str, context: Dict[str, Any]) -> str:
        # Implement your agent logic
        pass
```

2. Register in `skynet/cli/main.py`:

```python
manager.register_agent_class("my_type", MyAgent)
```

### Running Tests

```bash
pytest tests/
```

## Comparison with CAI

| Feature | Skynet | CAI |
|---------|--------|-----|
| Claude Integration | Native (Claude Code) | Via LiteLLM |
| RAG System | Built-in ChromaDB | External |
| Agent Types | 4 specialized | Extensible |
| Sandbox Mode | Yes | Yes |
| Interactive CLI | Yes | No |
| Knowledge Base | Integrated | Separate |

## Security Considerations

- **Sandbox Mode**: By default, only whitelisted commands are allowed
- **Command Validation**: Dangerous patterns are blocked
- **Safe Execution**: All commands run with timeouts
- **Logging**: Full audit trail of all actions

To disable sandbox mode (not recommended):

```python
config.sandbox_mode = False
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file

## Acknowledgments

- Inspired by [CAI](https://github.com/aliasrobotics/cai) by Alias Robotics
- Powered by [Anthropic's Claude](https://www.anthropic.com/)
- Built with Claude Code

## Support

- Issues: [GitHub Issues](https://github.com/yourusername/skynet/issues)
- Discussions: [GitHub Discussions](https://github.com/yourusername/skynet/discussions)

---

**⚠️ Disclaimer**: This tool is for educational and authorized security testing only. Always obtain proper authorization before testing systems you don't own.