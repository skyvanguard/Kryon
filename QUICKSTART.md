# Skynet - Quick Start Guide

Get Skynet up and running in 5 minutes!

## 📋 Prerequisites

```bash
# Python 3.8+
python3 --version

# Git (already installed)
git --version
```

## ⚡ Installation (3 steps)

### 1. Install Python Dependencies

```bash
cd /home/user/Skynet

# Install core packages
pip install anthropic openai chromadb sentence-transformers numpy pandas python-dotenv

# This takes 2-3 minutes
```

### 2. Initialize Knowledge Base

```bash
# Import CTF techniques into RAG
python scripts/init_knowledge.py

# This adds ~200+ CTF techniques covering:
# - Web exploitation (SQL injection, XSS, LFI, etc.)
# - Linux privilege escalation
# - Cryptography and encoding
# - Binary exploitation (pwn)
```

### 3. Test It!

```bash
# Search for techniques
python -m skynet.cli.quick search "sql injection"

# You should see results about SQLi techniques
```

## 🎯 Your First CTF Challenge

### Scenario: Web Application

```bash
# 1. Enumerate web app
python -m skynet.cli.quick enum-web http://target.com

# Returns JSON with:
# - HTTP headers
# - Found directories
# - Any detected flags
# - Server info

# 2. Search for relevant techniques
python -m skynet.cli.quick search "directory traversal"

# 3. Test specific vulnerability
python -m skynet.cli.quick search "lfi bypass"
```

### Scenario: Binary Exploitation

```bash
# 1. Check binary security
python -m skynet.cli.quick exploit-check ./challenge

# Shows: NX, PIE, RELRO, Canary status

# 2. Get exploitation ideas
python -m skynet.cli.quick search "buffer overflow"

# 3. Find ROP gadgets (if needed)
python -m skynet.cli.quick search "rop chain"
```

### Scenario: Network Recon

```bash
# 1. Quick port scan
python -m skynet.cli.quick scan 10.10.10.100

# Returns JSON with:
# - Open ports
# - Services
# - Any detected flags

# 2. Get enumeration ideas
python -m skynet.cli.quick search "nmap enumeration"
```

## 🚩 Flag Tracking

Flags are **automatically detected** in all outputs!

```bash
# View all found flags
python -m skynet.cli.quick flags list

# Count flags
python -m skynet.cli.quick flags count

# Flags are saved to: ~/.skynet/flags.json
```

## 📚 Using with Claude Code

Since you're using Claude Code in terminal, here's the workflow:

### Workflow 1: Claude Code calls Skynet tools

```python
# In your Claude Code session:

from skynet.tools.network import NetworkTools
from skynet.tools.web import WebTools
from skynet.core.flag_detector import get_flag_detector

# Scan target
net = NetworkTools()
result = net.quick_scan("10.10.10.100")

# Auto-detect flags
detector = get_flag_detector()
flags = detector.detect(result.scan_output, "nmap_scan")

if flags:
    print(f"🚩 FLAG FOUND: {flags[0].value}")
```

### Workflow 2: Quick commands

```bash
# You (with Claude Code) run:
result=$(python -m skynet.cli.quick scan 10.10.10.100)

# Claude Code parses JSON and reasons about results
echo $result | jq '.open_ports'
```

### Workflow 3: Search knowledge

```bash
# When stuck, search the knowledge base
python -m skynet.cli.quick search "privilege escalation sudo"

# Returns relevant techniques instantly
```

## 🎓 Learning from CTFs

After each CTF, add what you learned:

```bash
# Add technique manually
python skynet.py knowledge add \
  --content "Technique X works well for scenario Y" \
  --category web \
  --source "HTB-Machine-Name"

# Import your writeup
python skynet.py knowledge add \
  --file ~/writeup.md \
  --category general

# Import directory of writeups
python skynet.py knowledge add \
  --directory ~/ctf_writeups/ \
  --category general
```

Your knowledge base grows with every CTF! 📈

## 🔧 Common Commands

```bash
# Search knowledge
python -m skynet.cli.quick search "<query>"

# Scan network
python -m skynet.cli.quick scan <target>

# Web enumeration
python -m skynet.cli.quick enum-web <url>

# File analysis
python -m skynet.cli.quick analyze <file>

# Hash cracking
python -m skynet.cli.quick crack <hash>

# Binary security check
python -m skynet.cli.quick exploit-check <binary>

# View flags
python -m skynet.cli.quick flags list

# Knowledge management
python skynet.py knowledge count
python skynet.py knowledge export --output backup.json
```

## 📖 Full Documentation

- **CLAUDE_CODE_GUIDE.md** - Complete usage with workflows
- **ARCHITECTURE_CLAUDE_CODE.md** - How it all works
- **EXAMPLES.md** - Detailed examples
- **ROADMAP.md** - Future enhancements

## 🐛 Troubleshooting

### Import errors

```bash
# Make sure you're in Skynet directory
cd /home/user/Skynet

# Try importing
python -c "from skynet.core.config import get_config; print('OK')"
```

### Empty search results

```bash
# Initialize knowledge base
python scripts/init_knowledge.py

# Check count
python skynet.py knowledge count
```

### Missing tools

```bash
# Install security tools (optional but recommended)
sudo apt-get install nmap gobuster sqlmap john binwalk exiftool
```

## ✨ You're Ready!

Start with:

```bash
# Test search
python -m skynet.cli.quick search "sql injection"

# Should return multiple techniques!
```

## 💡 Pro Tips

1. **Use JSON output** - All quick commands return JSON for easy parsing
2. **Build knowledge base** - Add techniques after every CTF
3. **Auto flag detection** - Never manually track flags again
4. **Combine with Claude Code** - Let Claude reason, Skynet execute
5. **Backup knowledge** - `python skynet.py knowledge export`

---

**Next Step**: Try solving a CTF challenge with Skynet! 🚀

See **CLAUDE_CODE_GUIDE.md** for complete workflows and examples.
