---
description: "Emergency unstuck command - triggers creative problem-solving and web research"
---

# CTF Unstuck Command

When you hit a wall, this command activates emergency problem-solving mode.

## Activation

Immediately execute these steps:

### 1. Context Analysis
- What have we tried so far?
- What information do we have?
- What are we assuming that might be wrong?

### 2. Web Research Blitz
Search for:
- `"[challenge_name] tryhackme writeup"`
- `"[challenge_name] solution github"`
- `"[main_vulnerability] ctf technique"`
- `"[error_message] exploit"`
- `"[service] [version] bypass"`

### 3. Lateral Thinking
Try the "stupid" ideas:
- Default credentials (admin/admin, root/root, etc.)
- Hidden files (.git, .svn, .env, backup.zip)
- Parameter fuzzing (try common params: id, file, page, debug)
- Steganography in images/files
- Encoding tricks (base64, hex, rot13, etc.)

### 4. Re-enumeration
Scan again with different tools:
- `nmap` → `masscan` → `rustscan`
- Check UDP ports (often ignored!)
- Deeper web fuzzing with larger wordlists
- Check for virtual hosts: `ffuf -w vhosts.txt -u http://$TARGET -H "Host: FUZZ"`

### 5. Exploit Chain Thinking
Combine vulnerabilities:
- LFI → Log Poisoning → RCE
- SSRF → Internal Service Access → RCE
- SQL Injection → File Write → Shell
- XXE → File Read → Credentials → SSH

### 6. Community Intelligence
Check:
- TryHackMe/HTB forums (spoiler-free hints)
- Recent writeups (past 30 days)
- Similar machines on the platform
- Tool documentation for advanced features

### 7. Privilege Escalation Deep Dive
If you have a foothold but can't escalate:
- Run: `linpeas.sh`, `pspy64`, `linux-exploit-suggester.sh`
- Check: SUID binaries with `find / -perm -4000 2>/dev/null`
- Check: Capabilities with `getcap -r / 2>/dev/null`
- Check: Sudo with `sudo -l`
- Check: Cron jobs with `cat /etc/crontab`
- Search: GTFOBins for any interesting binary

## Output

Provide:
1. New attack vectors to try
2. Research findings from web search
3. Alternative tools/techniques
4. Step-by-step action plan

**Usage**: `/ctf-stuck [optional: describe what you've tried]`
