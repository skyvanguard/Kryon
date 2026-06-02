---
name: ctf-master
description: "CTF competition solver — HackTheBox, TryHackMe, picoCTF"
triggers:
  tech: []
  ports: []
  keywords: ["ctf", "hackthebox", "htb", "tryhackme", "thm", "flag", "challenge", "capture the flag"]
priority: 10
required_tools:
  - run_command
  - execute_code
  - nmap
---

## CTF Methodology

1. Full port scan: `nmap -sV -sC -p- -T4 TARGET` (ALL ports)
2. Per service enumeration (adapt to what's open):
   - HTTP: gobuster, nikto, check source code, robots.txt, .git exposed
   - SMB: `smbclient -L //TARGET -N`, enum4linux
   - SSH: banner grab, check version CVEs
   - FTP: anonymous login, check writable dirs
3. Always check: `curl -s TARGET/robots.txt`, `curl -s TARGET/.git/HEAD`
4. For web challenges: view source, check cookies, JWT decode, parameter fuzzing

## Flag Patterns

- `flag{...}`, `HTB{...}`, `THM{...}`, `picoCTF{...}`
- Usually in: `/root/root.txt`, `/home/*/user.txt`, environment variables
- Sometimes encoded: base64, hex, rot13

## Common CTF Paths

- **Easy**: default creds → shell → sudo -l → GTFOBins
- **Medium**: exploit CVE → limited shell → SUID/cron privesc
- **Hard**: chain exploits → pivot → kernel exploit or container escape

## Reglas CTF

- Escanear ALL ports (no solo top 1000)
- Siempre leer source code de web pages
- Probar credenciales default en TODOS los servicios
- Revisar /tmp, /opt, /var/backups para archivos interesantes
- Si encontrás un hash → `hashcat` o `john` inmediatamente
