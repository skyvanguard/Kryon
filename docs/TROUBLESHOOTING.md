# KRYON Troubleshooting Guide

**Clearance Level:** Omega-Command (Operational Support)
**Last Updated:** January 2025
**Version:** 3.2.0

---

## Table of Contents

1. [Quick Start Issues](#quick-start-issues)
2. [Autonomous Operation Failures](#autonomous-operation-failures)
3. [Reconnaissance Problems](#reconnaissance-problems)
4. [Exploitation Issues](#exploitation-issues)
5. [Privilege Escalation Failures](#privilege-escalation-failures)
6. [Flag Hunting Problems](#flag-hunting-problems)
7. [Network and Connectivity Issues](#network-and-connectivity-issues)
8. [Performance and Timeout Issues](#performance-and-timeout-issues)
9. [Common Error Messages](#common-error-messages)
10. [Advanced Debugging](#advanced-debugging)

---

## Quick Start Issues

### Module Import Errors

**Problem:**
```python
ModuleNotFoundError: No module named 'skynet.tools.autonomous.auto_recon'
```

**Solution:**
```bash
# Verify KRYON is properly installed
cd /path/to/kryon
pip install -e .

# Verify Python path
python -c "import sys; print('\n'.join(sys.path))"

# Check if module exists
ls -la src/skynet/tools/autonomous/auto_recon.py
```

**Root Cause:** Module not found in Python path or installation incomplete.

---

### Import Errors for Autonomous Functions

**Problem:**
```python
ImportError: cannot import name 'full_auto_enumeration' from 'skynet.tools.autonomous'
```

**Solution:**
```bash
# Check __init__.py exports
cat src/skynet/tools/autonomous/__init__.py | grep "full_auto_enumeration"

# Verify module integrity
python -c "from kryon.tools.autonomous import full_auto_enumeration; print('OK')"
```

**Root Cause:** `__init__.py` may not be exporting the function correctly.

---

## Autonomous Operation Failures

### Autonomous CTF Solver Returns Immediately with No Results

**Problem:**
```python
result = autonomous_ctf_solver("10.10.10.5")
# Returns: {"success": False, "error": "Reconnaissance failed or no open ports found"}
```

**Diagnostic Steps:**

1. **Check Target Connectivity:**
```bash
ping 10.10.10.5
nmap -p 80,443,22 10.10.10.5
```

2. **Run Manual Reconnaissance:**
```python
from kryon.tools.autonomous import quick_recon

recon_result = quick_recon("10.10.10.5")
print(recon_result)
```

3. **Check for Firewall/Network Issues:**
```bash
# Check if nmap is accessible
which nmap

# Test with verbose nmap
nmap -v -p- 10.10.10.5
```

**Common Causes:**
- Target is down or unreachable
- Firewall blocking scans
- nmap not installed or not in PATH
- Insufficient permissions for raw sockets

**Solutions:**
```bash
# Install nmap if missing
sudo apt-get install nmap

# Run with elevated privileges if needed
sudo python your_script.py

# Use fallback scanner (slower but works without nmap)
from kryon.tools.autonomous.auto_recon import full_auto_enumeration
result = full_auto_enumeration("10.10.10.5", deep_scan=False)
```

---

### Exploit Selection Returns "No Known Exploits"

**Problem:**
```python
from kryon.tools.autonomous import select_best_exploit

result = select_best_exploit("unknown_service", "version 1.0")
# Returns: {"exploit_recommended": False, "exploit_name": None}
```

**Solution:**

1. **Check Service Name:**
```python
# Supported services
from kryon.tools.autonomous.decision_engine import EXPLOIT_DATABASE

print("Supported services:", list(EXPLOIT_DATABASE.keys()))
# Output: ['apache', 'ssh', 'mysql', 'postgresql', 'smb', 'http', 'rdp', 'ftp']
```

2. **Add Custom Exploit:**
```python
from kryon.tools.autonomous import add_custom_exploit, ExploitType, ExploitDifficulty

custom_exploit = {
    "exploit_name": "my_custom_exploit",
    "exploit_type": ExploitType.RCE,
    "cve": "CVE-2024-12345",
    "severity": "critical",
    "success_rate": 0.85,
    "difficulty": ExploitDifficulty.MEDIUM,
    "description": "Custom exploit for my service",
    "metasploit_module": None,
    "public_exploit": True,
    "requirements": []
}

add_custom_exploit("my_service", "1.0", custom_exploit)
```

3. **Use Generic Exploit Approach:**
```python
# Force exploitation attempt even without specific exploit
from kryon.tools.autonomous.adaptive_strategy import execute_with_adaptation

result = execute_with_adaptation(
    target_ip="10.10.10.5",
    exploit={"name": "generic_web_exploit", "type": "rce"},
    service={"name": "http", "port": 80, "version": "unknown"},
    max_attempts=3
)
```

---

## Reconnaissance Problems

### Nmap Scan Timeout

**Problem:**
```
Reconnaissance phase hangs or times out during nmap scan
```

**Solution:**

1. **Reduce Scan Scope:**
```python
from kryon.tools.autonomous import quick_recon

# Use quick_recon instead of deep_recon
result = quick_recon("10.10.10.5")  # Only scans top 1000 ports
```

2. **Adjust Timeout:**
```python
from kryon.tools.autonomous.auto_recon import full_auto_enumeration

result = full_auto_enumeration(
    target_ip="10.10.10.5",
    deep_scan=False,
    timeout=300  # 5 minutes instead of default 30 minutes
)
```

3. **Use Fallback Scanner:**
```python
# Edit auto_recon.py to force fallback scanner
# Comment out nmap execution and use socket scanning directly
```

---

### Web Enumeration Finds No Directories

**Problem:**
```python
# Gobuster returns no found paths
result["http_endpoints"] = []
```

**Diagnostic:**
```bash
# Test gobuster manually
gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirb/common.txt

# Check if wordlist exists
ls -la /usr/share/wordlists/dirb/common.txt
```

**Solutions:**

1. **Install Wordlists:**
```bash
sudo apt-get install wordlists
sudo apt-get install seclists
```

2. **Use Custom Wordlist:**
```python
# Modify auto_recon.py _enumerate_web() function
# Change wordlist path to your custom wordlist
wordlist = "/path/to/your/wordlist.txt"
```

3. **Use Fallback Web Enum:**
```python
# The fallback web enumeration will try common paths
# It automatically activates if gobuster fails
```

---

## Exploitation Issues

### All Exploitation Attempts Fail

**Problem:**
```python
# exploitation_path shows all exploits failed
for step in result["exploitation_path"]:
    if step["phase"] == "exploitation":
        print(step["status"])  # All show "failed"
```

**Diagnostic Steps:**

1. **Check Individual Exploit Execution:**
```python
from kryon.tools.autonomous.orchestrator import _execute_exploit_autonomous

# Test specific exploit manually
test_result = _execute_exploit_autonomous(
    target_ip="10.10.10.5",
    exploit={"name": "apache_path_traversal_cve_2021_41773", "type": "rce"},
    service={"name": "http", "port": 80, "version": "Apache 2.4.49"}
)

print(f"Success: {test_result['success']}")
print(f"Output: {test_result['output']}")
```

2. **Check Tool Availability:**
```bash
# Verify required tools are installed
which sqlmap
which hydra
which metasploit
which nuclei
```

3. **Check Network Connectivity:**
```bash
# Test direct HTTP access
curl http://10.10.10.5

# Test with verbose
curl -v http://10.10.10.5
```

**Common Causes:**
- Target is patched/not vulnerable
- Exploitation tools not installed
- Firewall/IDS blocking exploitation attempts
- Incorrect service version detection

**Solutions:**

1. **Install Missing Tools:**
```bash
# Install sqlmap
sudo apt-get install sqlmap

# Install hydra
sudo apt-get install hydra

# Install nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install metasploit
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

2. **Use Adaptive Strategy:**
```python
from kryon.tools.autonomous import execute_with_adaptation

# Adaptive strategy will try multiple variations
result = execute_with_adaptation(
    target_ip="10.10.10.5",
    exploit={"name": "sql_injection", "type": "sqli"},
    service={"name": "http", "port": 80, "version": ""},
    max_attempts=10  # Try more variations
)
```

3. **Manual Exploitation:**
```bash
# Try manual exploitation first to verify vulnerability
sqlmap -u "http://10.10.10.5/page?id=1" --batch --dbs
```

---

### Metasploit Module Fails

**Problem:**
```python
# Metasploit wrapper returns error
Error: Metasploit module failed to execute
```

**Solution:**

1. **Check Metasploit Service:**
```bash
# Start PostgreSQL (required for Metasploit)
sudo service postgresql start

# Initialize Metasploit database
msfdb init

# Test msfconsole
msfconsole -q -x "version; exit"
```

2. **Check Module Exists:**
```bash
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; show options; exit"
```

3. **Use Alternative Approach:**
```python
# If Metasploit fails, use alternative tools
# For EternalBlue, try:
from kryon.tools.exploitation import exploit_db

# Search for public exploits
exploits = exploit_db.search_exploitdb(service="smb", version="SMBv1")
```

---

## Privilege Escalation Failures

### Privilege Escalation Returns "None" or "User"

**Problem:**
```python
result["privilege_level"] = "user"  # Expected "root"
```

**Diagnostic:**

1. **Check Initial Access Level:**
```python
# Verify we have shell access first
if not any(step.get("shell_obtained") for step in result["exploitation_path"]):
    print("No shell access - cannot escalate privileges")
```

2. **Run Manual Privesc Tools:**
```bash
# Linux privilege escalation
python3 linpeas.sh

# Windows privilege escalation
.\winPEAS.exe

# Check sudo permissions
sudo -l
```

**Solutions:**

1. **Use Specific Privesc Tools:**
```python
from kryon.tools.privilege_escalation import linux_privesc

privesc_result = linux_privesc.auto_privilege_escalation()

if privesc_result.get("quick_wins"):
    for win in privesc_result["quick_wins"]:
        print(f"Privesc method: {win['type']}")
        print(f"Command: {win['command']}")
```

2. **Check for Common Vectors:**
```bash
# SUID binaries
find / -perm -4000 2>/dev/null

# Writable /etc/passwd
ls -la /etc/passwd

# Kernel exploits
uname -a
searchsploit linux kernel 5.4
```

---

## Flag Hunting Problems

### No Flags Found

**Problem:**
```python
result["flags_found"] = []
```

**Diagnostic:**

1. **Check Access Level:**
```python
print(f"Privilege level: {result['privilege_level']}")
# If not 'root' or 'system', may not have access to all flags
```

2. **Manual Flag Search:**
```bash
# Search for common flag locations
find / -name "user.txt" 2>/dev/null
find / -name "root.txt" 2>/dev/null
find / -name "flag.txt" 2>/dev/null

# Search in home directories
find /home -name "*.txt" 2>/dev/null

# Search in /root
sudo find /root -name "*.txt" 2>/dev/null
```

**Solutions:**

1. **Use CTF Automation:**
```python
from kryon.tools.ctf import ctf_automation

# Comprehensive flag hunting
flag_result = ctf_automation.hunt_flags()

print(f"User flag: {flag_result.get('user_flag', {}).get('content')}")
print(f"Root flag: {flag_result.get('root_flag', {}).get('content')}")
```

2. **Check Specific Locations:**
```python
from kryon.tools.reconnaissance import filesystem

# Search specific directories
flag_search = filesystem.search_files(
    host_ip="10.10.10.5",
    patterns=["*.txt", "flag*", "*flag*"],
    directories=["/home", "/root", "/var/www", "/opt"]
)

for file in flag_search.get("found_files", []):
    print(f"Potential flag: {file['path']}")
```

---

## Network and Connectivity Issues

### Connection Refused or Timeout

**Problem:**
```
requests.exceptions.ConnectionError: Connection refused
```

**Solution:**

1. **Verify Target is Up:**
```bash
ping -c 4 10.10.10.5

# Check specific port
nc -zv 10.10.10.5 80
telnet 10.10.10.5 80
```

2. **Check Firewall Rules:**
```bash
# Check local firewall
sudo iptables -L

# Check if traffic is being blocked
sudo tcpdump -i eth0 host 10.10.10.5
```

3. **Use Different Interface:**
```python
import requests

# Try with different timeout
response = requests.get("http://10.10.10.5", timeout=30)

# Try with verify=False for SSL
response = requests.get("https://10.10.10.5", verify=False, timeout=30)
```

---

### VPN Connection Issues (TryHackMe/HackTheBox)

**Problem:**
```
Target unreachable - likely VPN issue
```

**Solution:**

1. **Verify VPN Connection:**
```bash
# Check VPN status
ip addr show tun0

# Check if you can reach VPN gateway
ping 10.10.10.1

# Check routing
ip route | grep tun0
```

2. **Restart VPN:**
```bash
# Kill existing VPN
sudo killall openvpn

# Restart VPN
sudo openvpn --config yourconfig.ovpn &

# Verify connection
ping 10.10.10.5
```

3. **DNS Issues:**
```bash
# Add DNS manually
echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
```

---

## Performance and Timeout Issues

### Operation Takes Too Long

**Problem:**
```python
# Autonomous CTF solver runs for hours without completing
```

**Solution:**

1. **Reduce Timeout:**
```python
result = autonomous_ctf_solver(
    target_ip="10.10.10.5",
    max_time_hours=1,  # Reduce from default 2 hours
    difficulty="easy"   # Use easier difficulty for faster execution
)
```

2. **Use Quick Recon Only:**
```python
from kryon.tools.autonomous import quick_recon

# Skip deep scanning
recon = quick_recon("10.10.10.5")  # Much faster than deep_recon
```

3. **Disable Slow Phases:**
```python
# Manually run phases to control execution
from kryon.tools.autonomous import (
    full_auto_enumeration,
    select_best_exploit
)

# Run only essential phases
recon = full_auto_enumeration("10.10.10.5", deep_scan=False, timeout=300)
```

---

### Memory Issues

**Problem:**
```
MemoryError: Unable to allocate array
```

**Solution:**

1. **Reduce Parallelism:**
```python
# Edit orchestrator.py or tool configs to reduce threads
# For example, in gobuster calls:
threads=10  # Instead of default 50
```

2. **Clear Cache:**
```python
from kryon.cache import cache_manager

# Clear old cache entries
cache_manager.clear_old_cache(days=7)
```

3. **Monitor Memory:**
```bash
# Check memory usage
free -h

# Monitor during execution
watch -n 1 free -h
```

---

## Common Error Messages

### "Tool Not Found" Errors

**Error:**
```
FileNotFoundError: [Errno 2] No such file or directory: 'nmap'
```

**Solution:**
```bash
# Install missing tool
sudo apt-get install nmap

# Verify installation
which nmap

# Add to PATH if needed
export PATH=$PATH:/usr/local/bin
```

---

### "Permission Denied" Errors

**Error:**
```
PermissionError: [Errno 13] Permission denied: '/tmp/kryon_ctf_report.md'
```

**Solution:**
```bash
# Check permissions
ls -la /tmp

# Change output location
result = autonomous_ctf_solver(
    target_ip="10.10.10.5",
    output_report="/home/user/reports/ctf_report.md"
)

# Or change permissions
chmod 777 /tmp
```

---

### "Exploit Database Empty" Errors

**Error:**
```
Warning: No exploits found in database for service
```

**Solution:**
```python
from kryon.tools.autonomous.decision_engine import EXPLOIT_DATABASE

# Verify database is populated
print(f"Services in DB: {list(EXPLOIT_DATABASE.keys())}")

# Add custom exploits if needed (see section above)
```

---

## Advanced Debugging

### Enable Verbose Logging

**Solution:**
```python
import logging

# Set logging level to DEBUG
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Run operation with verbose logging
result = autonomous_ctf_solver("10.10.10.5")
```

---

### Inspect Exploitation Path

**Solution:**
```python
result = autonomous_ctf_solver("10.10.10.5")

# Print detailed exploitation path
for step in result["exploitation_path"]:
    print(f"\nPhase: {step.get('phase')}")
    print(f"Status: {step.get('status')}")
    print(f"Details: {step}")
```

---

### Test Individual Components

**Solution:**
```python
# Test auto-recon
from kryon.tools.autonomous import full_auto_enumeration
recon = full_auto_enumeration("10.10.10.5", deep_scan=False)
print(f"Recon success: {recon['success']}")
print(f"Ports found: {len(recon['open_ports'])}")

# Test decision engine
from kryon.tools.autonomous import select_best_exploit
exploit = select_best_exploit("apache", "Apache 2.4.49", difficulty="medium")
print(f"Exploit recommended: {exploit['exploit_recommended']}")
print(f"Exploit name: {exploit['exploit_name']}")

# Test context analyzer
from kryon.tools.autonomous import analyze_context
context = analyze_context(
    text_data="Apache server running on port 80",
    objective="find_vulnerabilities"
)
print(f"Hints found: {len(context.get('hints', []))}")
```

---

### Capture Network Traffic

**Solution:**
```bash
# Start tcpdump before running KRYON
sudo tcpdump -i eth0 -w kryon_traffic.pcap host 10.10.10.5 &

# Run KRYON operation
python your_script.py

# Stop tcpdump
sudo killall tcpdump

# Analyze traffic
wireshark kryon_traffic.pcap
```

---

### Debug Exploit Execution

**Solution:**
```python
# Test exploit execution directly
from kryon.tools.autonomous.orchestrator import _execute_exploit_autonomous

result = _execute_exploit_autonomous(
    target_ip="10.10.10.5",
    exploit={"name": "test_exploit", "type": "rce"},
    service={"name": "http", "port": 80, "version": "Apache 2.4.49"}
)

print(f"Success: {result['success']}")
print(f"Method: {result['method']}")
print(f"Output: {result['output']}")
print(f"Error (if any): {result.get('error')}")
```

---

## Getting Help

If you're still experiencing issues after trying these troubleshooting steps:

1. **Check Logs:**
```bash
# Check KRYON logs
tail -f /var/log/kryon.log

# Check system logs
journalctl -u kryon -f
```

2. **Run Diagnostics:**
```python
from kryon.tools.misc import cli_utils

# Run system diagnostics
diagnostics = cli_utils.run_system_diagnostics()
print(diagnostics)
```

3. **Report Issue:**
- Include KRYON version
- Include Python version
- Include OS details
- Include error messages
- Include relevant logs
- Provide minimal reproduction example

---

**KRYON Troubleshooting Guide v3.2.0**

**Clearance Level:** Omega-Command
**Status:** Operational Support Active
**Last Updated:** January 2025
