# SKYNET Tool Dependencies

**Clearance Level:** Omega-Command
**Last Updated:** January 2025
**Version:** 3.3.0

---

## Overview

SKYNET autonomous operations rely on a combination of **CRITICAL** (required) and **OPTIONAL** (graceful degradation) tools.

The system is designed to **work with fallbacks** when optional tools are unavailable.

---

## Critical Dependencies (REQUIRED)

These modules MUST be available for SKYNET to function:

### Core Autonomous Modules ✅
- `skynet.tools.autonomous` - Main autonomous operations package
- `skynet.tools.autonomous.auto_recon` - Autonomous reconnaissance
- `skynet.tools.autonomous.decision_engine` - Exploit selection engine
- `skynet.tools.autonomous.orchestrator` - Operation orchestration
- `skynet.tools.autonomous.strategic_planner` - Mission planning
- `skynet.tools.autonomous.context_analyzer` - Intelligence extraction
- `skynet.tools.autonomous.learning_engine` - Operation learning
- `skynet.tools.autonomous.adaptive_strategy` - Adaptive execution

**Status:** ✅ ALL AVAILABLE

### Python Standard Library ✅
- `subprocess` - Command execution
- `json` - Data serialization
- `re` - Regular expressions
- `time` - Time operations
- `socket` - Network sockets (used for fallback port scanning)
- `ftplib` - FTP operations (used for FTP anonymous login)

**Status:** ✅ ALL AVAILABLE

---

## Optional Dependencies (Graceful Degradation)

These tools enhance functionality but are NOT required. The system will use fallbacks when unavailable.

### Reconnaissance Tools (OPTIONAL)

#### nmap (Command-line tool)
- **Purpose:** Port scanning and service detection
- **Fallback:** Socket-based port scanning (built-in)
- **Status:** Optional - used if available, otherwise fallback activates
- **Install:** `sudo apt-get install nmap`

#### gobuster (Command-line tool)
- **Purpose:** Web directory fuzzing
- **Fallback:** Common path enumeration with requests library
- **Status:** Optional - graceful fallback available
- **Install:** `go install github.com/OJ/gobuster/v3@latest`

### Exploitation Tools (OPTIONAL)

#### sqlmap (Command-line tool)
- **Purpose:** SQL injection testing and exploitation
- **Fallback:** Basic SQL injection detection only
- **Module:** `skynet.tools.web.sqlmap`
- **Status:** Optional - requires `cai` package
- **Install:** `sudo apt-get install sqlmap`

#### Metasploit Framework (Command-line tool)
- **Purpose:** Exploitation (EternalBlue, BlueKeep, etc.)
- **Fallback:** Skip Metasploit-specific exploits
- **Module:** `skynet.tools.exploitation.metasploit_wrapper`
- **Status:** Optional - requires `cai` package
- **Install:** See https://github.com/rapid7/metasploit-framework

#### nuclei (Command-line tool)
- **Purpose:** Template-based vulnerability scanning
- **Fallback:** Skip nuclei-specific scans
- **Module:** `skynet.tools.web.nuclei`
- **Status:** Optional - requires `cai` package
- **Install:** `go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest`

#### hydra (Command-line tool)
- **Purpose:** Credential brute forcing
- **Fallback:** Basic credential testing only
- **Module:** `skynet.tools.api_attacks.hydra`
- **Status:** Optional - requires `cai` package
- **Install:** `sudo apt-get install hydra`

### Third-Party Python Libraries (OPTIONAL)

#### requests
- **Purpose:** HTTP operations
- **Fallback:** Skip HTTP-based exploits
- **Status:** ✅ AVAILABLE
- **Install:** `pip install requests`

#### mysql-connector-python
- **Purpose:** MySQL credential testing
- **Fallback:** Skip MySQL exploits
- **Status:** ❌ NOT INSTALLED
- **Install:** `pip install mysql-connector-python`

#### paramiko
- **Purpose:** SSH operations
- **Fallback:** Skip SSH-based lateral movement
- **Status:** ❌ NOT INSTALLED (used by capture_traffic)
- **Install:** `pip install paramiko`

---

## Tool Integration Status

### Working with All Tools Available
When all tools are installed, SKYNET can:
- Execute 10+ exploit types with real tool integration
- Use nmap for fast, accurate port scanning
- Leverage Metasploit for Windows exploits
- Utilize sqlmap for SQL injection
- Employ hydra for credential attacks

### Working with Fallbacks (Current State)
Without optional tools, SKYNET can:
- ✅ Perform socket-based port scanning (slower but functional)
- ✅ Use common path enumeration for web discovery
- ✅ Test FTP anonymous login (ftplib built-in)
- ✅ Attempt basic credential combinations
- ✅ Search ExploitDB for references
- ✅ All core decision-making and orchestration functions

---

## Validation

### Run Validation Script
```bash
cd /path/to/cai
python scripts/validate_tools.py
```

### Expected Output
```
[CRITICAL] Core Autonomous Modules:
[+] skynet.tools.autonomous                                      OK
[+] skynet.tools.autonomous.auto_recon                           OK
[+] skynet.tools.autonomous.decision_engine                      OK
[+] skynet.tools.autonomous.orchestrator                         OK
... (all core modules should show OK)

[OPTIONAL] Tool Modules:
[-] Some may show MISSING (optional) - this is OK

[SUCCESS] All REQUIRED modules are available
```

---

## Installation Recommendations

### Minimal Installation (Core Only)
```bash
# Already working - no additional installation needed
# All critical modules available
python -c "from skynet.tools.autonomous import autonomous_ctf_solver; print('OK')"
```

### Standard Installation (Recommended for CTFs)
```bash
# Install common security tools
sudo apt-get update
sudo apt-get install -y nmap gobuster hydra sqlmap

# Install Python libraries
pip install requests mysql-connector-python paramiko
```

### Full Installation (Maximum Capability)
```bash
# Install all security tools
sudo apt-get install -y nmap gobuster hydra sqlmap masscan
pip install requests mysql-connector-python paramiko

# Install Go tools
go install github.com/OJ/gobuster/v3@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install Metasploit (if not already installed)
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

---

## How Fallbacks Work

### Example: Port Scanning

**With nmap (optimal):**
```python
# Fast, accurate, service version detection
result = full_auto_enumeration("10.10.10.5", deep_scan=True)
# Uses: nmap -p- -T4 -sV -O --version-intensity 5
# Time: ~2-5 minutes for full scan
```

**Without nmap (fallback):**
```python
# Slower but functional socket-based scanning
result = full_auto_enumeration("10.10.10.5", deep_scan=False)
# Uses: socket.connect_ex() for common ports
# Time: ~30-60 seconds for common ports
```

### Example: Web Enumeration

**With gobuster (optimal):**
```python
# Fast directory fuzzing with wordlists
# Uses: gobuster dir -u http://target -w wordlist.txt
```

**Without gobuster (fallback):**
```python
# Tests common paths with requests library
# Tests: /admin, /api, /robots.txt, /.git, etc.
```

---

## Error Handling

All tool integrations in `_execute_exploit_autonomous()` are wrapped in try-except blocks:

```python
try:
    from skynet.tools.web import nuclei
    nuclei_result = nuclei.run_nuclei_scan(...)
    # Use nuclei result
except Exception:
    # Gracefully skip nuclei scan
    pass
```

This ensures that missing tools never crash the autonomous operation - they simply get skipped.

---

## Troubleshooting

### Issue: "No module named 'cai'"
**Cause:** Tool modules depend on the `cai` package which may not be installed

**Solution:** This is EXPECTED and OK. The tools are optional and will be skipped gracefully.

### Issue: All exploits fail
**Cause:** Target may not be vulnerable or tools not installed

**Solution:**
1. Install recommended tools (see Standard Installation above)
2. Verify target is vulnerable manually
3. Check `TROUBLESHOOTING.md` for specific exploit debugging

### Issue: Port scan returns no results
**Cause:** Target unreachable or firewall blocking

**Solution:**
1. Verify network connectivity: `ping target_ip`
2. Try manual nmap: `nmap -p 80,443,22 target_ip`
3. Check VPN connection if testing CTF platforms

---

## Testing Tool Availability

### Check Individual Tools
```bash
# Check nmap
which nmap && nmap --version

# Check gobuster
which gobuster && gobuster version

# Check sqlmap
which sqlmap && sqlmap --version

# Check hydra
which hydra && hydra -h

# Check Metasploit
which msfconsole && msfconsole -v
```

### Test in Python
```python
import sys
sys.path.insert(0, 'src')

# Test core modules (should all succeed)
from skynet.tools.autonomous import (
    autonomous_ctf_solver,
    full_auto_enumeration,
    select_best_exploit
)
print("Core modules: OK")

# Test optional tools (may fail - OK)
try:
    from skynet.tools.web import sqlmap
    print("sqlmap: Available")
except:
    print("sqlmap: Not available (will use fallback)")
```

---

## Summary

✅ **Core autonomous system is FULLY FUNCTIONAL** with current dependencies

⚠️ **Optional tools** enhance capabilities but are NOT required

🎯 **Recommended action:** Install nmap and gobuster for best results in CTFs

🚀 **Current capability:** Autonomous CTF solving with socket-based scanning and common path enumeration

---

**🤖 SKYNET v3.3.0 - Tool Dependencies**

**Core Status:** ✅ OPERATIONAL
**Optional Tools:** ⚠️ Some missing (fallbacks active)
**Clearance:** Omega-Command
**Recommendation:** Standard Installation for optimal CTF performance
