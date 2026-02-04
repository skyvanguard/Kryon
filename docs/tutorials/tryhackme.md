# TryHackMe Quick Start Guide - KRYON CTF Master

**Version:** 1.0.0
**Status:** ✅ Ready to Use
**Estimated Setup Time:** 5-10 minutes

---

## 🎯 Prerequisites

Before starting, ensure you have:

- ✅ TryHackMe account (free or premium)
- ✅ OpenVPN config file downloaded from TryHackMe
- ✅ Docker/Kali environment running (or WSL/native Linux)
- ✅ KRYON installed (`pip install -e .`)

---

## 🚀 Quick Start (3 Steps)

### Step 1: Connect to TryHackMe VPN (2 minutes)

```bash
# In your Docker/Kali terminal:
sudo openvpn /path/to/your-thm-config.ovpn

# You should see:
# Initialization Sequence Completed
```

**Verify connection:**
```bash
# Check VPN interface exists
ip addr show tun0

# Should show IP like: inet 10.10.X.X
```

### Step 2: Launch KRYON CTF Master (1 minute)

```bash
# Navigate to KRYON directory
cd /workspace  # or your KRYON path

# Launch Python REPL
python3

# Import CTF Master
from skynet.agents.ctf_master import ctf_master, transfer_to_ctf_master
```

### Step 3: Start Your First TryHackMe Room (5 minutes)

```python
# Verify VPN connection
from skynet.tools.ctf.tryhackme_helpers import check_thm_vpn

vpn_status = check_thm_vpn()
print(f"Connected: {vpn_status['connected']}")
print(f"VPN IP: {vpn_status['vpn_ip']}")

# Auto-detect target IP (if you already scanned)
from skynet.tools.ctf.tryhackme_helpers import get_target_ip

target = get_target_ip(auto_detect=True)
print(f"Target: {target['target_ip']}")

# Or set manually
TARGET_IP = "10.10.245.67"  # Replace with your room's IP
```

---

## 📖 Complete CTF Workflow Example

### Scenario: Basic Pentesting Room on TryHackMe

```python
# ============================================
# KRYON CTF MASTER - Complete Workflow
# ============================================

from skynet.tools.ctf import *
from skynet.tools.privilege_escalation.linux_privesc import *

# --------------------------------------------
# PHASE 1: VPN & Target Verification
# --------------------------------------------

# Verify VPN
vpn = check_thm_vpn()
if not vpn['connected']:
    print("[!] Not connected to THM VPN!")
    print("Run: sudo openvpn /path/to/config.ovpn")
    exit()

print(f"[+] VPN Connected: {vpn['vpn_ip']}")

# Set target IP (get from TryHackMe room)
TARGET_IP = "10.10.245.67"  # CHANGE THIS

# Generate room notes
notes = generate_thm_notes(
    room_name="Basic Pentesting",
    target_ip=TARGET_IP
)
print(f"[+] Notes created: {notes['notes_path']}")

# --------------------------------------------
# PHASE 2: Enumeration
# --------------------------------------------

print("\n[*] Starting enumeration...")

# Comprehensive enumeration
enum = auto_enumerate_target(
    ip=TARGET_IP,
    quick_mode=False  # Full scan for thorough results
)

# Review results
print(f"\n[+] Found {len(enum['open_ports'])} open ports:")
for port in enum['open_ports']:
    print(f"  - {port['port']}/{port['protocol']}: {port['service']} {port['version']}")

if enum['web_services']:
    print(f"\n[+] Web services found:")
    for url in enum['web_services']:
        print(f"  - {url}")
        if url in enum['gobuster_results']:
            dirs = enum['gobuster_results'][url]
            if isinstance(dirs, list):
                print(f"    Directories: {len(dirs)}")

# --------------------------------------------
# PHASE 3: Exploit Search
# --------------------------------------------

print("\n[*] Searching for exploits...")

# Search for each service found
for port in enum['open_ports']:
    if port['version']:
        print(f"\n[*] Searching exploits for {port['service']} {port['version']}")

        exploits = search_exploits(
            service=port['service'],
            version=port['version']
        )

        if exploits['searchsploit_results']:
            print(f"  [+] Found {len(exploits['searchsploit_results'])} exploits")
            for exp in exploits['searchsploit_results'][:3]:
                print(f"    - {exp['title']}")

        if exploits['metasploit_modules']:
            print(f"  [+] Metasploit modules available:")
            for mod in exploits['metasploit_modules'][:2]:
                print(f"    - {mod['name']}")

# --------------------------------------------
# PHASE 4: Initial Access
# --------------------------------------------

# At this point, use the exploits found or manual techniques
# to gain initial access to the target

print("\n[*] Manual exploitation required here")
print("[*] Use exploits found above to gain shell access")
print("[*] Once you have shell access, continue to Phase 5")

# Example: After gaining shell access via SSH, web exploit, etc.
# You would be inside the target system

# --------------------------------------------
# PHASE 5: Privilege Escalation
# --------------------------------------------

print("\n[*] Running automated privilege escalation...")

# Comprehensive privesc analysis
privesc = auto_privilege_escalation(
    run_linpeas=True,      # Full LinPEAS scan
    check_sudo=True,       # Sudo exploits
    check_suid=True,       # SUID binaries
    check_capabilities=True,
    timeout_minutes=15
)

# Check for quick wins
if privesc['quick_wins']:
    print("\n[!] QUICK WIN FOUND!")
    for win in privesc['quick_wins']:
        print(f"\n  Type: {win['type']}")
        print(f"  Description: {win['description']}")
        print(f"  Command: {win['command']}")
        print("\n  [*] Execute the command above to escalate!")

# Review sudo exploits
if privesc['sudo_exploits']:
    print(f"\n[+] Found {len(privesc['sudo_exploits'])} sudo exploits:")
    for exp in privesc['sudo_exploits']:
        print(f"  - {exp['binary']}: {exp['technique']}")
        print(f"    Command: {exp['command']}")

# Review SUID exploits
if privesc['suid_exploits']:
    print(f"\n[+] Found {len(privesc['suid_exploits'])} SUID exploits:")
    for exp in privesc['suid_exploits']:
        print(f"  - {exp['binary']}: {exp['technique']}")
        print(f"    Command: {exp['command']}")

# Manual GTFOBins lookup if needed
print("\n[*] Manual GTFOBins lookup example:")
result = gtfobins_lookup("vim", escalation_type="sudo")
if result['found']:
    print(f"  vim sudo exploit: {result['command']}")

# --------------------------------------------
# PHASE 6: Flag Hunting
# --------------------------------------------

print("\n[*] Hunting for flags...")

flags = hunt_flags(
    search_paths=["/home", "/root", "/opt", "/var/www"],
    check_common_locations=True,
    search_files=True
)

# User flag
if flags['user_flag']:
    print(f"\n[+] USER FLAG FOUND!")
    print(f"  Location: {flags['user_flag']['location']}")
    print(f"  Content: {flags['user_flag']['content']}")

    # Format for submission
    formatted = submit_thm_answer(flags['user_flag']['content'])
    print(f"  Submit: {formatted['formatted_answer']}")

# Root flag
if flags['root_flag']:
    print(f"\n[+] ROOT FLAG FOUND!")
    print(f"  Location: {flags['root_flag']['location']}")
    print(f"  Content: {flags['root_flag']['content']}")

    # Format for submission
    formatted = submit_thm_answer(flags['root_flag']['content'])
    print(f"  Submit: {formatted['formatted_answer']}")

# Other flags
if len(flags['flags_found']) > 2:
    print(f"\n[+] Found {len(flags['flags_found'])} total flags")

# --------------------------------------------
# PHASE 7: Report Generation
# --------------------------------------------

print("\n[*] Generating walkthrough report...")

report = generate_ctf_report(
    target_ip=TARGET_IP,
    enumeration_results=enum,
    privesc_info=privesc,
    flags_found=flags,
    output_file=f"/tmp/thm_basic_pentesting_walkthrough.md"
)

print(f"\n[+] Report generated: {report['report_path']}")
print(f"  Sections: {report['sections']}")
print(f"  Commands documented: {report['commands_documented']}")

print("\n[✓] CTF WORKFLOW COMPLETE!")
```

---

## 🎓 Example: Room-Specific Workflow

### Easy Room Example (e.g., "Kenobi")

```python
from skynet.tools.ctf import *

# 1. Set target
TARGET = "10.10.245.67"

# 2. Quick enumeration
enum = auto_enumerate_target(TARGET, quick_mode=True)

# 3. If SMB found (port 445)
if any(p['port'] == 445 for p in enum['open_ports']):
    print("[+] SMB found - check for shares")
    # Manual: smbclient -L //10.10.245.67 -N

# 4. Search for service exploits
for port in enum['open_ports']:
    exploits = search_exploits(port['service'], port.get('version', ''))
    if exploits['searchsploit_results']:
        print(f"[+] Exploits for {port['service']}: {len(exploits['searchsploit_results'])}")

# 5. After gaining access - privesc
privesc = auto_privilege_escalation(run_linpeas=False, check_sudo=True)

# 6. Hunt flags
flags = hunt_flags()
if flags['user_flag']:
    print(f"User flag: {flags['user_flag']['content']}")
```

---

## 💡 Pro Tips

### 1. Save Your Session

```python
# Save enumeration results
import json

with open('/tmp/enum_results.json', 'w') as f:
    json.dump(enum, f, indent=2)

# Load later
with open('/tmp/enum_results.json', 'r') as f:
    enum = json.load(f)
```

### 2. Use Quick Mode for Timeouts

```python
# If full scan takes too long
enum = auto_enumerate_target(TARGET, quick_mode=True)
```

### 3. Manual GTFOBins Lookup

```python
# If you find a sudo/SUID binary
from skynet.tools.privilege_escalation.linux_privesc import gtfobins_lookup

# Check if it's exploitable
result = gtfobins_lookup("find", "sudo")
if result['found']:
    print(result['command'])  # Ready to execute!
```

### 4. Answer Formatting

```python
# Always format answers before submitting
from skynet.tools.ctf.tryhackme_helpers import submit_thm_answer

# Flag
answer = submit_thm_answer("THM{flag_here}")
print(answer['formatted_answer'])  # Copy this to THM

# Hash (auto-lowercase)
answer = submit_thm_answer("5F4DCC3B5AA765D61D8327DEB882CF99")
print(answer['formatted_answer'])  # 5f4dcc3b5aa765d61d8327deb882cf99

# Port number (validates range)
answer = submit_thm_answer("8080")
print(answer['formatted_answer'])  # 8080
```

---

## 🔧 Troubleshooting

### Issue 1: VPN Not Connected

**Symptom:** `check_thm_vpn()` returns `connected: False`

**Solution:**
```bash
# Check if openvpn is running
ps aux | grep openvpn

# Reconnect
sudo openvpn /path/to/config.ovpn

# Verify tun0 exists
ip addr show tun0
```

### Issue 2: Target IP Detection Fails

**Symptom:** `get_target_ip()` returns `None`

**Solution:**
```python
# Set manually
TARGET_IP = "10.10.X.X"  # Get from THM room page

# Or run nmap first
from skynet.tools.reconnaissance.nmap import run_nmap
run_nmap(TARGET_IP, scan_type="quick")

# Then try auto-detect again
target = get_target_ip()
```

### Issue 3: Import Errors

**Symptom:** `ModuleNotFoundError: No module named 'skynet'`

**Solution:**
```bash
# Install in development mode
cd /workspace  # or your KRYON directory
pip install -e .

# Verify
python3 -c "from skynet.tools.ctf import *; print('OK')"
```

### Issue 4: Permission Denied

**Symptom:** `Permission denied` when running tools

**Solution:**
```bash
# Use sudo for nmap, etc.
sudo python3 your_script.py

# Or run as root in Docker
docker exec -u root -it skynet_devcontainer-devenv-1 bash
```

---

## 📚 Learning Path

### Recommended TryHackMe Rooms for KRYON

**Beginner:**
1. ✅ "Basic Pentesting" - Practice all KRYON phases
2. ✅ "Kenobi" - SMB enumeration + privesc
3. ✅ "Startup" - Web + Linux privesc

**Intermediate:**
4. ✅ "Lazy Admin" - Web app enumeration
5. ✅ "Brooklyn Nine Nine" - Multi-vector attack
6. ✅ "Pickle Rick" - Web exploitation

**Advanced:**
7. ✅ "Internal" - Active Directory (Windows focus)
8. ✅ "Relevant" - Windows + Buffer Overflow
9. ✅ "Steel Mountain" - Metasploit + Windows

---

## 🎯 Success Checklist

Before starting a room:
- [ ] VPN connected (`check_thm_vpn()`)
- [ ] Target IP known
- [ ] Room notes generated (`generate_thm_notes()`)

During the room:
- [ ] Enumeration complete (`auto_enumerate_target()`)
- [ ] Exploits researched (`search_exploits()`)
- [ ] Initial access gained (manual or exploit)
- [ ] Privilege escalation attempted (`auto_privilege_escalation()`)
- [ ] Flags found (`hunt_flags()`)
- [ ] Answers formatted (`submit_thm_answer()`)

After completion:
- [ ] Report generated (`generate_ctf_report()`)
- [ ] Lessons learned documented
- [ ] Share walkthrough (if allowed by room)

---

## 🚀 Next Steps

1. **Connect to TryHackMe VPN**
2. **Pick an easy room** (Basic Pentesting, Kenobi, Startup)
3. **Follow the complete workflow above**
4. **Document friction points** - What worked? What didn't?
5. **Report back** - Share your experience!

---

## 📖 Additional Resources

- **Full CTF Master Prompt:** `src/skynet/prompts/system_ctf_master.md`
- **Phase 14 Documentation:** `docs/sessions/SESSION_TRYHACKME_CTF_OPTIMIZATION.md`
- **Testing Guide:** `docs/testing.md`
- **Tools Reference:** `docs/tools.md`

---

**Ready to hack? Let's go! 🚀**

*🤖 Generated with Claude Code*
*Co-Authored-By: Claude <noreply@anthropic.com>*

**Status: Ready for TryHackMe**
