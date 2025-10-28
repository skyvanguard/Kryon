# Skynet - Setup para Notebook/Local

Guía para instalar y usar Skynet en tu notebook o máquina local.

## 📋 Requisitos

- Python 3.8 o superior
- 4GB de RAM mínimo
- 2GB de espacio en disco

## 🚀 Instalación Rápida (3 pasos)

### 1. Clonar el repositorio

```bash
git clone https://github.com/skyvanguard/Skynet.git
cd Skynet
```

### 2. Instalar dependencias

**Opción A: Instalación completa (recomendado)**
```bash
pip install -r requirements.txt
```

**Opción B: Instalación mínima (sin embeddings locales)**
```bash
# Si solo usarás OpenAI para embeddings o no usarás RAG
pip install anthropic openai chromadb numpy pandas python-dotenv
```

**Opción C: Solo herramientas (sin RAG)**
```bash
# Si solo quieres las herramientas de hacking, sin IA
pip install python-dotenv
```

### 3. Verificar instalación

```bash
python scripts/verify_installation.py
```

## 🔧 Configuración (Opcional)

### API Keys

Si vas a usar embeddings de OpenAI (opcional):

```bash
# Crea archivo .env
cp .env.example .env

# Edita .env y agrega tus keys
OPENAI_API_KEY=tu_key_aqui  # Solo si usarás OpenAI embeddings
```

**Nota**: No necesitas API keys para usar las herramientas básicas de Skynet.

### Inicializar Knowledge Base

```bash
# Esto carga 200+ técnicas de CTF en la base de datos
python scripts/init_knowledge.py
```

## ✅ Verificación

Corre estos comandos para verificar que todo funciona:

```bash
# Test 1: Imports básicos
python -c "from skynet.core.config import get_config; print('✅ Core OK')"
python -c "from skynet.tools.network import NetworkTools; print('✅ Tools OK')"
python -c "from skynet.core.flag_detector import get_flag_detector; print('✅ Flag Detector OK')"

# Test 2: Comando rápido
python -m skynet.cli.quick search "test"

# Test 3: Interactive mode
python skynet.py interactive
```

## 📚 Uso Básico en Notebook

### Ejemplo 1: Usar herramientas directamente

```python
from skynet.tools.network import NetworkTools
from skynet.tools.web import WebTools
from skynet.tools.analysis import AnalysisTools

# Network scanning
net = NetworkTools()
result = net.quick_scan("10.10.10.100")
print(f"Open ports: {result.open_ports}")

# Web enumeration
web = WebTools()
headers = web.get_headers("http://target.com")
print(f"Server: {headers.get('Server')}")

# File analysis
analysis = AnalysisTools()
file_info = analysis.analyze_file(Path("suspicious.bin"))
print(f"File type: {file_info.file_type}")
```

### Ejemplo 2: Detección automática de flags

```python
from skynet.core.flag_detector import get_flag_detector

detector = get_flag_detector()

# Auto-detecta flags en cualquier output
output = "The flag is HTB{test_flag_here}"
flags = detector.detect(output, source="test")

if flags:
    print(f"🚩 FLAG: {flags[0].value}")

# Ver todas las flags encontradas
all_flags = detector.get_found_flags()
print(f"Total flags found: {len(all_flags)}")
```

### Ejemplo 3: Buscar en knowledge base

```python
from skynet.rag.retriever import get_retriever

retriever = get_retriever()

# Buscar técnicas
results = retriever.retrieve("sql injection bypass", top_k=3)

for ctx in results:
    print(f"- {ctx.content[:100]}...")
    print(f"  Relevance: {ctx.relevance_score:.3f}\n")
```

### Ejemplo 4: Comandos rápidos desde Python

```python
import subprocess
import json

# Usar comandos quick desde Python
result = subprocess.run(
    ["python", "-m", "skynet.cli.quick", "scan", "10.10.10.100"],
    capture_output=True,
    text=True
)

data = json.loads(result.stdout)
print(f"Success: {data['success']}")
print(f"Open ports: {data['open_ports']}")
print(f"Flags found: {data['flags_found']}")
```

## 🎯 Workflow Típico en Notebook

```python
from skynet.tools.network import NetworkTools
from skynet.tools.web import WebTools
from skynet.rag.retriever import get_retriever
from skynet.core.flag_detector import get_flag_detector

# Setup
net = NetworkTools()
web = WebTools()
retriever = get_retriever()
detector = get_flag_detector()

# Paso 1: Recon
print("🔍 Scanning target...")
scan_result = net.quick_scan("10.10.10.100")
print(f"Found {len(scan_result.open_ports)} open ports")

# Auto-detect flags
flags = detector.detect(scan_result.scan_output, "nmap")
if flags:
    print(f"🚩 FLAG in scan output: {flags[0].value}")

# Paso 2: Web enum (si hay web)
if any("80" in str(p) or "443" in str(p) for p in scan_result.open_ports):
    print("\n🌐 Enumerating web...")
    headers = web.get_headers("http://10.10.10.100")
    print(f"Server: {headers.get('Server', 'Unknown')}")

# Paso 3: Buscar técnicas relevantes
print("\n📚 Searching for techniques...")
techniques = retriever.retrieve("web exploitation", top_k=3)
for t in techniques:
    print(f"- {t.content[:80]}...")

# Paso 4: Ver todas las flags encontradas
print("\n🚩 All flags found this session:")
for flag_data in detector.get_found_flags():
    print(f"  {flag_data['value']} (from: {flag_data['source']})")
```

## 🔥 Comandos Quick para Terminal

Dentro de tu notebook, puedes ejecutar:

```bash
# Port scanning
!python -m skynet.cli.quick scan 10.10.10.100

# Web enumeration
!python -m skynet.cli.quick enum-web http://target.com

# File analysis
!python -m skynet.cli.quick analyze file.bin

# Search knowledge
!python -m skynet.cli.quick search "privilege escalation"

# Hash cracking
!python -m skynet.cli.quick crack 5d41402abc4b2a76b9719d911017c592

# View flags
!python -m skynet.cli.quick flags list

# Binary security check
!python -m skynet.cli.quick exploit-check ./binary
```

## 🐛 Troubleshooting

### "ModuleNotFoundError: No module named 'skynet'"

Asegúrate de estar en el directorio Skynet:
```bash
cd /path/to/Skynet
python -c "import skynet; print('OK')"
```

O instala en modo desarrollo:
```bash
pip install -e .
```

### "ChromaDB not found"

Si no necesitas RAG:
```python
# Usa solo las herramientas sin RAG
from skynet.tools.network import NetworkTools
# Funciona sin ChromaDB
```

Si necesitas RAG:
```bash
pip install chromadb
```

### Herramientas de seguridad no encontradas

Instala las herramientas que necesites:
```bash
# Linux (Kali/Parrot ya las tiene)
sudo apt install nmap gobuster sqlmap john hashcat binwalk

# macOS
brew install nmap gobuster john-jumbo

# Windows (usar WSL o instalar individualmente)
```

## 💡 Tips para Notebook

### 1. Crear shortcuts

```python
# Al inicio de tu notebook
from skynet.tools.network import NetworkTools
from skynet.tools.web import WebTools
from skynet.tools.analysis import AnalysisTools
from skynet.core.flag_detector import get_flag_detector

# Instances globales
net = NetworkTools()
web = WebTools()
analysis = AnalysisTools()
detector = get_flag_detector()

# Ahora puedes usar: net.quick_scan(...) directamente
```

### 2. Pretty printing de resultados

```python
import json

def pp(data):
    """Pretty print JSON"""
    print(json.dumps(data, indent=2, default=str))

# Uso
result = net.quick_scan("target")
pp(result.__dict__)
```

### 3. Logging en notebook

```python
from skynet.core.logging import get_logger

logger = get_logger()
logger.info("Starting CTF challenge...")
```

## 📝 Agregar Conocimiento

Después de cada CTF, documenta lo aprendido:

```python
from skynet.rag.retriever import get_retriever

retriever = get_retriever()

retriever.add_knowledge(
    content="Encontré que X técnica funciona para Y situación",
    category="web",
    source="HTB-Machine-Name"
)
```

## 🎓 Recursos

- **QUICKSTART.md** - Guía de inicio rápido
- **CLAUDE_CODE_GUIDE.md** - Guía completa de uso
- **EXAMPLES.md** - Ejemplos detallados
- **ARCHITECTURE_CLAUDE_CODE.md** - Cómo funciona

## 🚀 Listo para CTF!

Una vez instalado, puedes empezar a resolver challenges inmediatamente.

```python
# Tu primer challenge
from skynet.tools.network import NetworkTools

net = NetworkTools()
result = net.quick_scan("10.10.10.100")
print(f"Found {len(result.open_ports)} services!")
```

¡Buena suerte en tus CTFs! 🏆
