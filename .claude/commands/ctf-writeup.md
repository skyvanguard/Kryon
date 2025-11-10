---
description: "Generate a comprehensive CTF writeup after solving a challenge"
---

# CTF Writeup Generator

After solving a challenge, generate a detailed writeup for future reference.

## Writeup Structure

### 1. Challenge Overview
```markdown
# [Challenge Name] - Writeup

**Platform**: TryHackMe / HackTheBox / etc.
**Difficulty**: Easy / Medium / Hard / Insane
**Date Solved**: YYYY-MM-DD
**Time Taken**: X hours
**Key Skills**: [List main techniques used]
```

### 2. Reconnaissance
Document all enumeration steps:
```markdown
## Reconnaissance

### Port Scan
[nmap results]

### Service Enumeration
- Port 80: Apache 2.4.49 (vulnerable to CVE-XXXX)
- Port 22: OpenSSH 8.2
- Port 3306: MySQL 5.7

### Web Enumeration
- Directory fuzzing: Found /admin, /backup
- Technology: PHP 7.4, WordPress 5.8
- Interesting files: robots.txt revealed /secret
```

### 3. Vulnerability Discovery
```markdown
## Vulnerability Analysis

### Identified Vulnerabilities
1. **Apache RCE (CVE-2021-41773)**
   - Path traversal leading to RCE
   - Public exploit available

2. **Weak MySQL credentials**
   - Default root password found

3. **SUID binary misconfiguration**
   - /usr/bin/custom allows privilege escalation
```

### 4. Exploitation
```markdown
## Exploitation

### Initial Foothold
Exploited Apache path traversal:
[commands used]
[exploit code]

Got shell as www-data:
[proof screenshot/output]

### Lateral Movement (if applicable)
[steps taken]

### Privilege Escalation
Found SUID binary with GTFOBins technique:
[commands]
[exploit code]

Got root:
[proof]
```

### 5. Flags
```markdown
## Flags

**User Flag**: [flag_hash]
**Root Flag**: [flag_hash]
```

### 6. Lessons Learned
```markdown
## Key Takeaways

### What Worked
- Thorough enumeration revealed hidden directory
- Web research found recent CVE quickly
- GTFOBins was crucial for privesc

### What Didn't Work
- Initial SQL injection attempts failed
- Metasploit module crashed, manual exploit worked better

### New Techniques Learned
- Apache 2.4.49 path traversal exploitation
- Custom SUID binary analysis
- Log poisoning (attempted but not needed)

### Time Savers
- rustscan instead of nmap saved 10 minutes
- Searching "[service] [version] exploit" immediately found CVE
```

### 7. Alternative Methods
```markdown
## Alternative Approaches

Could have also:
1. Exploited WordPress plugin vulnerability
2. Bruteforced SSH with hydra
3. Used XXE in upload feature
```

### 8. References
```markdown
## References

- [CVE-2021-41773 Exploit](https://github.com/...)
- [GTFOBins - custom binary](https://gtfobins.github.io/...)
- [Similar challenge writeup](https://example.com/writeup)
```

### 9. Tools Used
```markdown
## Tools

- nmap / rustscan
- ffuf / gobuster
- metasploit (attempted)
- linpeas.sh
- pspy64
- Custom exploit script
```

## Auto-Generation

The writeup will be automatically populated with:
- Commands from your session history
- Web search results that helped
- RAG knowledge queries made
- Time spent on each phase

## Output Format

Choose format:
- **Markdown** (for GitHub, blogs)
- **HTML** (for web publishing)
- **PDF** (for reports)
- **Internal Notes** (for personal reference)

## Save Location

Writeups saved to:
```
/home/user/Skynet/writeups/[challenge_name]_[date].md
```

## Sharing Guidelines

### Safe to Share:
✅ Your methodology and approach
✅ Tools and techniques used
✅ Lessons learned
✅ Alternative methods explored

### Don't Share (if challenge is active):
❌ Full solution/commands
❌ Exact exploit code
❌ Flags
❌ Specific vulnerabilities

**Usage**: `/ctf-writeup [challenge_name]`
