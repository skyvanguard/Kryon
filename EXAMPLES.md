# Skynet - Usage Examples

This document provides detailed examples of how to use Skynet for various CTF challenges.

## Table of Contents

1. [Basic Usage](#basic-usage)
2. [Reconnaissance](#reconnaissance)
3. [Web Exploitation](#web-exploitation)
4. [Cryptography](#cryptography)
5. [Forensics](#forensics)
6. [Knowledge Management](#knowledge-management)
7. [Advanced Scenarios](#advanced-scenarios)

## Basic Usage

### Starting Interactive Mode

```bash
$ python skynet.py interactive

╔═══════════════════════════════════════════════════════════════╗
║                     SKYNET v0.1.0                            ║
║            CTF Agent Framework with RAG                      ║
╚═══════════════════════════════════════════════════════════════╝

Available agents: recon, web, crypto, forensics
Commands: /help, /stats, /exit

skynet> /help

Available Commands:
  /help       - Show this help
  /stats      - Show agent statistics
  /exit       - Exit Skynet

  <agent> <task> - Run a task with specified agent

skynet>
```

## Reconnaissance

### Example 1: Basic Port Scan

```bash
skynet> recon Scan 192.168.1.100 for open ports

[ReconAgent] Processing...
================================================================
Result (took 15.3s):
================================================================

# Reconnaissance Report

## Target: 192.168.1.100

## Findings:
DNS Information:
192.168.1.100.in-addr.arpa. has no PTR record

Port Scan:
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1
80/tcp   open  http    Apache httpd 2.4.41
443/tcp  open  https   Apache httpd 2.4.41

Web Enumeration:
HTTP Headers:
Server: Apache/2.4.41
X-Powered-By: PHP/7.4.3

robots.txt:
User-agent: *
Disallow: /admin/
Disallow: /backup/
```

### Example 2: Full Network Enumeration

```bash
$ python skynet.py run recon \
  "Perform comprehensive reconnaissance including DNS, ports, and services" \
  --target example.com \
  --verbose
```

## Web Exploitation

### Example 1: SQL Injection Testing

```bash
skynet> web Test http://vulnerable-site.com/product.php?id=1 for SQL injection

[WebAgent] Processing...
================================================================
Result (took 45.2s):
================================================================

# Web Exploitation Report

## Target: http://vulnerable-site.com/product.php?id=1

## Findings:

Directory Enumeration:
Found paths: admin, backup, config, uploads

SQL Injection Test:
VULNERABLE to SQL injection!
Injection type: Boolean-based blind
Parameter: id
Payload: 1' AND '1'='1
Database: MySQL 5.7.32

Recommended exploitation:
sqlmap -u "http://vulnerable-site.com/product.php?id=1" --dump
```

### Example 2: Directory Bruteforce

```bash
$ python skynet.py run web \
  "Enumerate directories and find interesting files" \
  --url "http://target.com" \
  --verbose
```

### Example 3: Multiple Vulnerability Testing

```bash
skynet> web Test http://target.com for common vulnerabilities including SQLi, XSS, and LFI
```

## Cryptography

### Example 1: Hash Cracking

```bash
skynet> crypto Crack this MD5 hash: 5d41402abc4b2a76b9719d911017c592

[CryptoAgent] Processing...
================================================================
Result (took 2.1s):
================================================================

# Cryptography Analysis Report

## Challenge Data:
5d41402abc4b2a76b9719d911017c592

## Analysis:

Cipher Identification:
Likely: MD5 hash (32 characters, hex)

Hash Cracking:
Hash cracked!
Password: hello

Method: Dictionary attack using rockyou.txt
Time: 0.8 seconds
```

### Example 2: Base64 Decoding

```bash
skynet> crypto Decode this text: SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBDVEYgZmxhZw==

[CryptoAgent] Processing...
================================================================
Result (took 0.3s):
================================================================

Decoding Attempts:
Base64: Hello World! This is a CTF flag
```

### Example 3: Caesar Cipher

```bash
skynet> crypto Decrypt this Caesar cipher: Uryyb Jbeyq
```

### Example 4: Unknown Cipher

```bash
$ python skynet.py run crypto \
  "Identify and decrypt this ciphertext: KBBX TXZZ GBTL MBPE" \
  --verbose
```

## Forensics

### Example 1: Image Steganography

```bash
$ python skynet.py run forensics \
  "Extract hidden data from this image" \
  --file challenge.png \
  --verbose

SKYNET ANALYSIS RESULTS
================================================================================

Agent: ForensicsAgent
Success: True
Iterations: 5
Time: 8.7s

# Forensics Analysis Report

## Target File: challenge.png

## Findings:

File Analysis:
File Type: PNG image data, 1920 x 1080, 8-bit/color RGB
Size: 2.4 MB
MD5: a3c5e8d9f2b1e4c7a9d6f8e2b5c3a1d9
SHA256: 7f8e9d6c5b4a3e2f1d9c8b7a6e5d4c3b2a1f9e8d7c6b5a4e3f2d1c9b8a7e6d5

Metadata:
Creation Date: 2024:01:15 14:23:45
Software: Adobe Photoshop CS6
Comment: CTF{h1dd3n_1n_pl41n_s1ght}

Hidden Data Analysis:
Binwalk Extraction:
Found embedded ZIP archive at offset 0x1F4B80
Extracted: secret.txt

Steghide Extraction:
Successfully extracted file: flag.txt
Content: The flag is CTF{st3g4n0gr4phy_m4st3r}
```

### Example 2: PCAP Analysis

```bash
skynet> forensics Analyze network traffic in capture.pcap
```

### Example 3: Memory Dump

```bash
$ python skynet.py run forensics \
  "Analyze memory dump for credentials and processes" \
  --file memory.dmp \
  --verbose
```

## Knowledge Management

### Building Your Knowledge Base

```bash
# Add techniques from your previous CTF experiences
$ python skynet.py knowledge add \
  --content "For LFI bypass, try ....//....// instead of ../" \
  --category web \
  --source "HTB Machine: Example"

# Import writeups
$ python skynet.py knowledge add \
  --directory ~/ctf_writeups/ \
  --category general \
  --pattern "*.md"

# Add crypto techniques
$ python skynet.py knowledge add \
  --file crypto_techniques.txt \
  --category crypto
```

### Searching Your Knowledge

```bash
$ python skynet.py knowledge search --query "SQL injection WAF bypass"

Found 5 results:

1. [web] Use UNION SELECT with comments to bypass WAF: /*!UNION*/ /*!SELECT*/
   Relevance: 0.234

2. [web] URL encoding can bypass simple WAF rules: %55NION %53ELECT
   Relevance: 0.456

3. [web] Try case manipulation: UnIoN SeLeCt
   Relevance: 0.512
```

### Managing Knowledge

```bash
# Check knowledge count
$ python skynet.py knowledge count
Total knowledge entries: 247

# Export for backup
$ python skynet.py knowledge export --output backup_2024.json
Exported knowledge to backup_2024.json

# Import from backup
$ python skynet.py knowledge import --input backup_2024.json
Imported 247 documents from backup_2024.json
```

## Advanced Scenarios

### Scenario 1: Multi-Stage CTF Challenge

```bash
# Stage 1: Reconnaissance
$ python skynet.py run recon "Enumerate target 10.0.0.1" --target 10.0.0.1 > recon_results.txt

# Stage 2: Web Exploitation (based on recon findings)
$ python skynet.py run web "Exploit web service on port 80" --url "http://10.0.0.1"

# Stage 3: Extract credentials
$ python skynet.py run forensics "Extract data from downloaded file" --file loot.zip
```

### Scenario 2: Using RAG Context

First, add relevant techniques:

```bash
$ python skynet.py knowledge add \
  --content "For HackTheBox machines, check default credentials first" \
  --category general

$ python skynet.py knowledge add \
  --content "Common SQLi payloads: ' OR 1=1--, ' UNION SELECT NULL--" \
  --category web
```

Then run with context:

```bash
$ python skynet.py run web "Test login page for SQLi" --url "http://target/login.php"
# Agent will automatically retrieve relevant techniques from knowledge base
```

### Scenario 3: Custom Configuration

Create `my_config.json`:

```json
{
  "default_model": "claude-sonnet-4",
  "max_iterations": 50,
  "sandbox_mode": false,
  "verbose": true,
  "log_level": "DEBUG"
}
```

Use it:

```bash
$ python skynet.py --config my_config.json run recon "Deep scan target"
```

### Scenario 4: Batch Processing

Process multiple targets:

```bash
#!/bin/bash
# scan_targets.sh

for target in $(cat targets.txt); do
    echo "Scanning $target..."
    python skynet.py run recon "Quick scan" --target "$target" > "results_${target}.txt"
done
```

## Tips and Best Practices

### 1. Build Your Knowledge Base

The more you add to your knowledge base, the smarter Skynet becomes:

```bash
# After solving a challenge, document the technique
$ python skynet.py knowledge add \
  --content "Solution for Challenge XYZ: Use technique ABC" \
  --category ctf_solutions
```

### 2. Use Verbose Mode for Learning

```bash
$ python skynet.py run web "Test for XSS" --url "http://target" --verbose
# Shows full reasoning process
```

### 3. Combine Agents

```bash
# Use recon to find web services
$ python skynet.py run recon "Find web services" --target 10.0.0.1

# Then use web agent on discovered services
$ python skynet.py run web "Exploit found service" --url "http://10.0.0.1:8080"
```

### 4. Safe Testing

Always keep sandbox mode enabled when testing unknown targets:

```python
# In config
"sandbox_mode": true
```

### 5. Regular Backups

```bash
# Backup your knowledge regularly
$ python skynet.py knowledge export --output "backup_$(date +%Y%m%d).json"
```

## Troubleshooting

### Issue: Agent times out

Increase max_iterations in config:

```json
{
  "max_iterations": 50
}
```

### Issue: Tools not found

Install required tools:

```bash
sudo apt-get install nmap gobuster sqlmap john binwalk
```

### Issue: API key errors

Check your `.env` file:

```bash
cat .env
# Should show: ANTHROPIC_API_KEY=sk-...
```

## Next Steps

1. Explore the codebase: `skynet/agents/`
2. Create custom agents for your specific needs
3. Build a comprehensive knowledge base from your CTF experiences
4. Contribute back to the project!

---

For more information, see the main [README.md](README.md).
