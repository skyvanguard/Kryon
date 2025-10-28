# Skynet - Windows Setup Guide

Complete guide for using Skynet on Windows with OpenVPN for CTF challenges.

## 🎯 Your Setup

- **OS**: Windows
- **Connection**: OpenVPN to CTF machines
- **No APIs**: Direct tool execution, no HTB/TryHackMe APIs needed

## ✅ What You Need

### 1. WSL2 (Strongly Recommended)

**Why WSL2?**
- All Linux security tools work perfectly
- Better compatibility with CTF tools
- Native Python environment
- Seamless integration with Windows

**Installation:**
```powershell
# In PowerShell (Administrator)
wsl --install -d kali-linux

# Restart computer

# Start WSL
wsl

# Update system
sudo apt update && sudo apt upgrade -y
```

### 2. Python Dependencies

```bash
# In WSL terminal
cd /mnt/c/Users/YourUsername/path/to/Skynet

# Install Python packages
pip install -r requirements.txt

# Verify installation
python scripts/verify_installation.py
```

### 3. Security Tools

```bash
# In WSL - Install CTF tools
sudo apt install -y \
    nmap \
    gobuster \
    sqlmap \
    nikto \
    john \
    hashcat \
    binwalk \
    exiftool \
    steghide \
    hydra \
    netcat-traditional \
    whois \
    dnsutils

# Binary exploitation tools
sudo apt install -y \
    gdb \
    gdb-peda \
    patchelf \
    checksec

# Install pwntools
pip install pwntools ropper
```

### 4. Initialize Skynet

```bash
# Initialize knowledge base
python scripts/init_knowledge.py

# Test
python -m skynet.cli.quick search "sql injection"
```

## 🌐 OpenVPN Integration

### Workflow

```bash
# 1. Connect to CTF lab (in WSL or Windows)
sudo openvpn --config ~/Downloads/lab.ovpn

# Keep this terminal open (VPN connection)
```

```bash
# 2. In another WSL terminal - Use Skynet
cd /mnt/c/Users/YourUsername/Skynet

# Scan target machine
python -m skynet.cli.quick scan 10.10.10.100

# Enumerate web app
python -m skynet.cli.quick enum-web http://10.10.10.100

# Search for techniques
python -m skynet.cli.quick search "linux privilege escalation"

# All flags auto-detected!
python -m skynet.cli.quick flags list
```

## 💻 Typical CTF Workflow

### Step 1: Connect
```bash
# Terminal 1: VPN connection
sudo openvpn --config htb.ovpn
```

### Step 2: Reconnaissance
```bash
# Terminal 2: Skynet
python -m skynet.cli.quick scan 10.10.10.100
```

### Step 3: Use Python for Advanced Tasks
```python
# In Python script or Jupyter
from skynet.tools.network import NetworkTools
from skynet.tools.web import WebTools
from skynet.core.flag_detector import get_flag_detector

net = NetworkTools()
web = WebTools()
detector = get_flag_detector()

# Detailed scan
scan = net.nmap_scan("10.10.10.100", ports="1-65535")
print(f"Open ports: {scan.open_ports}")

# Check for flags
flags = detector.detect(scan.scan_output, "nmap")
if flags:
    print(f"🚩 FLAG: {flags[0].value}")

# Web enum if port 80/443 open
if "80" in scan.open_ports:
    dirs = web.gobuster_dirs("http://10.10.10.100")
    print(f"Found directories: {dirs.found_directories}")
```

### Step 4: Track Progress
```bash
# View all found flags
python -m skynet.cli.quick flags list

# Export for writeup
python -m skynet.cli.quick flags list > found_flags.txt
```

## 🔧 Windows-Specific Considerations

### File Paths
```python
# Windows paths in WSL
windows_path = "/mnt/c/Users/YourUser/Desktop/file.bin"
linux_path = "/home/user/file.bin"

# Use Windows paths when accessing files from Windows
# Use Linux paths when inside WSL
```

### Running from VS Code
```bash
# VS Code with WSL extension (recommended)
# 1. Install "Remote - WSL" extension
# 2. Open folder in WSL: code .
# 3. Terminal automatically uses WSL

# All Skynet commands work normally
python -m skynet.cli.quick scan 10.10.10.100
```

### OpenVPN in Windows vs WSL

**Option A: OpenVPN in Windows**
```powershell
# Install OpenVPN GUI for Windows
# Connect via GUI
# Tools in WSL can access VPN targets
```

**Option B: OpenVPN in WSL (Recommended)**
```bash
# Install in WSL
sudo apt install openvpn

# Connect
sudo openvpn --config ~/lab.ovpn

# All tools in same environment
```

## 📊 Compatibility Matrix

| Component | Windows Native | WSL2 | Notes |
|-----------|---------------|------|-------|
| Skynet Core | ✅ | ✅ | Python works everywhere |
| Flag Detection | ✅ | ✅ | Pure Python |
| RAG System | ✅ | ✅ | ChromaDB works on Windows |
| Quick Commands | ✅ | ✅ | All CLI works |
| nmap | ⚠️ | ✅ | Windows version available |
| gobuster | ❌ | ✅ | Linux only |
| sqlmap | ⚠️ | ✅ | Python, works on Windows |
| john | ❌ | ✅ | Linux only |
| binwalk | ⚠️ | ✅ | Better on Linux |
| pwntools | ❌ | ✅ | Linux only |

**Legend:**
- ✅ Fully supported
- ⚠️ Partial support (may have issues)
- ❌ Not available

## 🚀 Quick Start (Complete Workflow)

```bash
# 1. Open WSL terminal
wsl

# 2. Navigate to Skynet
cd /mnt/c/Users/YourUser/Skynet

# 3. Start VPN in background
sudo openvpn --config ~/lab.ovpn &

# 4. Use Skynet
python -m skynet.cli.quick scan 10.10.10.100

# 5. View flags
python -m skynet.cli.quick flags list
```

## 🎓 Example: Complete CTF Challenge

```bash
# === Terminal 1: VPN ===
sudo openvpn --config htb.ovpn
# Keep running...

# === Terminal 2: Skynet ===

# Quick recon
python -m skynet.cli.quick scan 10.10.10.100
# Returns JSON with open ports and auto-detected flags

# Web enumeration (if port 80 open)
python -m skynet.cli.quick enum-web http://10.10.10.100
# Returns directories, headers, potential vulns

# Search for techniques
python -m skynet.cli.quick search "sql injection bypass waf"
# Returns relevant techniques from knowledge base

# Test SQLi
python -m skynet.cli.quick search "sqlmap techniques"

# Manual exploitation with Python
python
>>> from skynet.tools.web import WebTools
>>> web = WebTools()
>>> result = web.sqlmap_test("http://10.10.10.100/page?id=1")
>>> print(result.vulnerable)

# Check all found flags
python -m skynet.cli.quick flags list
```

## 💡 Pro Tips for Windows

### 1. Use VS Code with WSL
```bash
# Install VS Code extension: Remote - WSL
# Open Skynet folder in WSL
code /mnt/c/Users/YourUser/Skynet
```

### 2. Share Files Between Windows and WSL
```bash
# Access Windows files from WSL
cd /mnt/c/Users/YourUser/Desktop

# Access WSL files from Windows
# In File Explorer: \\wsl$\kali-linux\home\user
```

### 3. Multiple Terminals
```bash
# Use Windows Terminal with multiple tabs
# Tab 1: OpenVPN connection
# Tab 2: Skynet quick commands
# Tab 3: Python interactive session
```

### 4. Jupyter Notebook in WSL
```bash
# Install Jupyter
pip install jupyter

# Start notebook (accessible from Windows browser)
jupyter notebook --no-browser

# Use Skynet tools in notebook
```

## 🐛 Troubleshooting

### "Command not found: nmap"
```bash
# Install tools in WSL
sudo apt install nmap gobuster sqlmap
```

### "Permission denied" for OpenVPN
```bash
# Use sudo
sudo openvpn --config lab.ovpn
```

### Python module not found
```bash
# Make sure you're in WSL, not PowerShell
wsl

# Verify installation
python scripts/verify_installation.py
```

### Can't reach target after OpenVPN connect
```bash
# Verify VPN is connected
ip a  # Check for tun0 interface

# Test connectivity
ping 10.10.10.100

# Check routing
ip route
```

### ChromaDB issues on Windows
```bash
# Use WSL instead of native Windows
# ChromaDB works better on Linux
```

## 📖 Additional Resources

- **QUICKSTART.md** - Basic usage guide
- **NOTEBOOK_SETUP.md** - Jupyter integration
- **CLAUDE_CODE_GUIDE.md** - Complete workflows
- **GAP_ANALYSIS.md** - Missing features analysis

## ✅ Verification Checklist

Before your first CTF:

- [ ] WSL2 installed and updated
- [ ] Python dependencies installed (`pip install -r requirements.txt`)
- [ ] Security tools installed (`nmap`, `gobuster`, etc.)
- [ ] Knowledge base initialized (`python scripts/init_knowledge.py`)
- [ ] Verification passed (`python scripts/verify_installation.py`)
- [ ] OpenVPN can connect to test lab
- [ ] Quick commands work (`python -m skynet.cli.quick search "test"`)
- [ ] Flag detection works (`python -m skynet.cli.quick flags count`)

## 🎯 Summary

**Your setup (Windows + OpenVPN) is PERFECT for Skynet!**

**What you need:**
1. ✅ WSL2 with Kali Linux
2. ✅ Python dependencies (`pip install -r requirements.txt`)
3. ✅ Security tools (`nmap`, `gobuster`, etc.)
4. ✅ OpenVPN for connection
5. ✅ Skynet handles the rest!

**What you DON'T need:**
- ❌ HTB/TryHackMe APIs
- ❌ Anthropic API keys (for basic use)
- ❌ Complex setup

**Ready to compete!** 🚀🏴‍☠️

---

**Next Step**: Follow the Quick Start section above to verify everything works!
