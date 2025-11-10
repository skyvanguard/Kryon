---
description: "Perform comprehensive CTF reconnaissance with creative enumeration"
---

# CTF Reconnaissance Command

Execute a full reconnaissance phase on the target with advanced enumeration techniques.

## Execution Plan

1. **Initial Scan**
   - Fast port scan: `rustscan -a $TARGET -- -sV -sC`
   - Full port scan: `nmap -p- -T4 $TARGET`
   - UDP scan: `nmap -sU --top-ports 100 $TARGET`

2. **Service Enumeration**
   - For each open port, identify service and version
   - Search exploits: `searchsploit [service] [version]`
   - Web search: "[service] [version] vulnerability"

3. **Web Enumeration (if HTTP/HTTPS found)**
   - Directory fuzzing: `ffuf -w /usr/share/wordlists/dirb/common.txt -u http://$TARGET/FUZZ`
   - Technology detection: `whatweb $TARGET`
   - Check: robots.txt, sitemap.xml, .git, .env, backup files
   - Vulnerability scan: `nuclei -u $TARGET -t cves/`

4. **SMB Enumeration (if port 445 open)**
   - `enum4linux -a $TARGET`
   - `smbclient -L //$TARGET`
   - `crackmapexec smb $TARGET --shares`

5. **DNS Enumeration (if DNS found)**
   - `dig axfr @$TARGET`
   - `dnsenum $TARGET`
   - Subdomain fuzzing: `ffuf -w subdomains.txt -u http://FUZZ.$TARGET`

6. **Creative Checks**
   - Check for default credentials
   - Test for common misconfigurations
   - Look for hidden parameters/endpoints
   - Test for IDOR, path traversal

## Output Format

Provide a structured report:
- Open ports and services
- Potential vulnerabilities found
- Recommended attack vectors (prioritized)
- Next steps

## Auto-Research

If stuck, automatically search:
- "[target_os] [service] exploit github"
- "[challenge_name] writeup"
- Recent CVEs for identified services

**Usage**: `/ctf-recon [target_ip]`
