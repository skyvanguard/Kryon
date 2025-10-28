# Guía de Skynet para Claude Code

Esta es una guía rápida de cómo usar Skynet desde Claude Code sin necesidad de APIs.

## 🚀 Quick Start

Skynet tiene comandos rápidos que devuelven JSON para fácil parsing:

```bash
# Escaneo rápido
python -m skynet.cli.quick scan 10.0.0.1

# Enumeración web
python -m skynet.cli.quick enum-web http://target.com

# Análisis de archivo
python -m skynet.cli.quick analyze suspicious.bin

# Buscar en knowledge base
python -m skynet.cli.quick search "sql injection bypass"

# Crack hash
python -m skynet.cli.quick crack 5d41402abc4b2a76b9719d911017c592

# Ver flags encontradas
python -m skynet.cli.quick flags list

# Check seguridad de binario
python -m skynet.cli.quick exploit-check ./binary
```

## 📋 Comandos por Categoría

### Reconnaissance

```bash
# Port scan completo
python -m skynet.cli.quick scan 192.168.1.1
# Output: JSON con puertos abiertos, servicios, flags detectadas

# DNS enumeration
from skynet.tools.network import NetworkTools
net = NetworkTools()
dns_info = net.dns_enumerate("example.com")

# Subnet scan
live_hosts = net.subnet_scan("192.168.1.0/24")
```

### Web Exploitation

```bash
# Enumeración web rápida
python -m skynet.cli.quick enum-web http://target.com

# Directory bruteforce
from skynet.tools.web import WebTools
web = WebTools()
dirs = web.directory_bruteforce("http://target.com")

# SQLi testing
sqli_result = web.sqlmap_test("http://target.com/page.php?id=1")

# XSS testing
xss_results = web.xss_test("http://target.com/search?q=FUZZ")

# LFI testing
lfi_results = web.lfi_test("http://target.com/page?file=FUZZ")
```

### Binary Exploitation

```bash
# Check security features
python -m skynet.cli.quick exploit-check ./binary

# Full analysis
from skynet.agents.exploit_agent import ExploitAgent
agent = ExploitAgent()
analysis = agent._tool_analyze_binary("./challenge")

# Find ROP gadgets
gadgets = agent._tool_find_rop_gadgets("./challenge")

# Generate shellcode
shellcode = agent._tool_generate_shellcode("x64:shell")
```

### Forensics & Analysis

```bash
# Análisis completo de archivo
python -m skynet.cli.quick analyze mysterious.png

# Strings interesantes
from skynet.tools.analysis import AnalysisTools
tools = AnalysisTools()
strings = tools.extract_strings(Path("file.bin"), min_length=8)

# Binwalk analysis
binwalk_data = tools.binwalk_analyze(Path("image.jpg"))

# Steganography
tools.steghide_extract(Path("image.jpg"), passphrase="secret")

# PCAP analysis
pcap_data = tools.pcap_analyze(Path("capture.pcap"))
```

### Cryptography

```bash
# Crack hash
python -m skynet.cli.quick crack abc123def456...

# Multiple hashes
from skynet.tools.analysis import AnalysisTools
tools = AnalysisTools()
result = tools.crack_hash("5d41402abc4b2a76b9719d911017c592")

# Análisis de archivo con crypto
from skynet.agents.crypto_agent import CryptoAgent
agent = CryptoAgent()
analysis = agent._tool_identify_cipher("URYYB JBEYQ")
```

### Knowledge Management

```bash
# Buscar técnicas
python -m skynet.cli.quick search "privilege escalation"

# Add knowledge
from skynet.rag.retriever import get_retriever
retriever = get_retriever()
retriever.add_knowledge(
    content="Técnica X funciona en Y situación",
    category="web",
    source="HTB-Machine-Name"
)

# Import directory
retriever.add_knowledge_from_directory(
    Path("~/ctf_writeups"),
    category="general"
)
```

### Flag Detection

```bash
# List all found flags
python -m skynet.cli.quick flags list

# Count flags
python -m skynet.cli.quick flags count

# Auto-detect flags in output
from skynet.core.flag_detector import detect_flags_in_output
flags = detect_flags_in_output(command_output, source="nmap")
# Automatically logged and saved!
```

## 🎯 Workflows Comunes

### Workflow 1: Initial Recon

```python
from skynet.tools.network import NetworkTools
from skynet.core.flag_detector import get_flag_detector

net = NetworkTools()
detector = get_flag_detector()

# 1. Quick scan
result = net.quick_scan("10.10.10.100")
print(f"Open ports: {result.open_ports}")

# 2. Check for flags
flags = detector.detect(result.scan_output, "initial_scan")
if flags:
    print(f"🚩 Found {len(flags)} flags!")

# 3. DNS enum
dns = net.dns_enumerate("target.com")
print(f"DNS records: {dns.records}")
```

### Workflow 2: Web App Testing

```python
from skynet.tools.web import WebTools

web = WebTools()
url = "http://10.10.10.100"

# 1. Headers
headers = web.get_headers(url)
print(f"Server: {headers.get('Server')}")

# 2. Directory enum
dirs = web.directory_bruteforce(url)
print(f"Found paths: {dirs.found_paths}")

# 3. Test SQLi on interesting endpoints
for path in dirs.found_paths:
    if "?" in path or "login" in path:
        result = web.sqlmap_test(f"{url}{path}")
        if result.vulnerable:
            print(f"🎯 SQLi found in {path}!")
```

### Workflow 3: Binary Pwn

```python
from skynet.agents.exploit_agent import ExploitAgent
from pathlib import Path

agent = ExploitAgent()
binary = "./challenge"

# 1. Check security
security = agent._tool_check_security(binary)
print(security)

# 2. Analyze
analysis = agent._tool_analyze_binary(binary)
print(analysis[:500])

# 3. Find gadgets if NX enabled
if "NX: ENABLED" in security:
    gadgets = agent._tool_find_rop_gadgets(binary)
    print("ROP gadgets available!")

# 4. Generate exploit template
template = agent._generate_exploit_template(binary, security, analysis)
Path("exploit.py").write_text(template)
print("Exploit template generated!")
```

### Workflow 4: CTF Challenge

```python
from skynet.rag.retriever import get_retriever
from skynet.core.flag_detector import get_flag_detector

retriever = get_retriever()
detector = get_flag_detector()

# 1. Search for similar challenges
techniques = retriever.retrieve("web sqli bypass waf", top_k=3)
for tech in techniques:
    print(f"- {tech.content[:100]}")

# 2. Run your commands
output = run_your_exploit()

# 3. Auto-detect flags
flags = detector.detect(output, "exploit")
if flags:
    print(f"🎉 FLAG FOUND: {flags[0].value}")

# 4. Save technique for future
retriever.add_knowledge(
    content="Successfully bypassed WAF using technique X",
    category="web",
    source="current_ctf"
)
```

## 🔥 Pro Tips

### 1. Siempre busca flags automáticamente

```python
from skynet.core.flag_detector import detect_flags_in_output

# Después de cada comando importante
output = run_command()
flags = detect_flags_in_output(output)
```

### 2. Usa JSON output para parsing fácil

```bash
# Los comandos quick devuelven JSON
result=$(python -m skynet.cli.quick scan 10.0.0.1)
echo $result | jq '.open_ports'
```

### 3. Construye tu knowledge base

```bash
# Después de cada CTF
python -m skynet.rag.retriever add \
  --directory ~/ctf_writeups/last_ctf \
  --category general
```

### 4. Shortcuts en tu shell

```bash
# Agrega a ~/.bashrc
alias sk-scan="python -m skynet.cli.quick scan"
alias sk-web="python -m skynet.cli.quick enum-web"
alias sk-analyze="python -m skynet.cli.quick analyze"
alias sk-search="python -m skynet.cli.quick search"
alias sk-flags="python -m skynet.cli.quick flags list"
```

## 📊 Output Format

Todos los comandos quick devuelven JSON:

```json
{
  "success": true,
  "target": "10.0.0.1",
  "open_ports": [
    {"port": "22/tcp", "state": "open", "service": "ssh"},
    {"port": "80/tcp", "state": "open", "service": "http"}
  ],
  "flags_found": ["HTB{example_flag}"],
  "raw_output": "..."
}
```

## 🐛 Debugging

```bash
# Verbose mode
export SKYNET_LOG_LEVEL=DEBUG

# Check logs
tail -f ~/.skynet/skynet.log

# Ver todas las flags
python -m skynet.cli.quick flags list | jq
```

## 📚 Common Patterns

### Pattern: Enumerate then Exploit

```python
# 1. Enum
result = scan_or_enum()

# 2. Detect interesting findings
if "smb" in result:
    exploit_smb()
elif "http" in result:
    test_web_vulns()

# 3. Check flags
flags = detector.detect(output)
```

### Pattern: Multi-stage Exploitation

```python
# Stage 1: Foothold
initial_access = get_shell()

# Stage 2: Priv Esc
search_privesc = retriever.retrieve("linux privilege escalation")
root_access = escalate()

# Stage 3: Exfil
flags = detector.detect_in_file(Path("/root/root.txt"))
```

### Pattern: Team Collaboration

```bash
# Miembro 1: Recon
sk-scan 10.0.0.0/24 > targets.json

# Miembro 2: Web
sk-web http://10.0.0.5 > web_enum.json

# Miembro 3: Exploits
sk-exploit-check binary > security.json

# Todos: Share knowledge
python -m skynet.rag.retriever export > team_knowledge.json
```

## 🎓 Learning from CTFs

Después de cada CTF, documenta:

```python
retriever = get_retriever()

# Técnica exitosa
retriever.add_knowledge(
    content="Buffer overflow con offset 64 funcionó en binario X",
    category="exploit",
    source="CTF_2024_Challenge_Y"
)

# Payloads útiles
retriever.add_knowledge(
    content="SQLi payload: ' UNION SELECT NULL,NULL,version()-- -",
    category="web",
    source="HTB_Machine_Z"
)
```

Con el tiempo, tu knowledge base se vuelve tu ventaja competitiva!

---

¿Preguntas? Revisa los ejemplos en `EXAMPLES.md`
