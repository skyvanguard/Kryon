# Arquitectura Skynet + Claude Code (Sin API)

## 🎯 Concepto

Skynet NO hace llamadas a APIs de Claude. En lugar de eso:

**Skynet = Caja de herramientas especializadas para CTF**
**Claude Code = El cerebro que las usa**

## Flujo de Trabajo Real

```
┌─────────────────────────────────────────────────────────────┐
│                    TÚ (en terminal)                         │
│                    "Solve HTB machine"                      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   CLAUDE CODE                               │
│  - Analiza el problema                                      │
│  - Decide qué herramientas usar                            │
│  - Razona sobre resultados                                 │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ usa herramientas
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    SKYNET TOOLS                             │
│  ├─ network.py     → nmap, dig, etc.                       │
│  ├─ web.py         → gobuster, sqlmap                      │
│  ├─ analysis.py    → binwalk, john                         │
│  └─ rag/retriever → buscar técnicas                        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ resultados
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   CLAUDE CODE                               │
│  - Interpreta resultados                                   │
│  - Sugiere siguiente paso                                  │
│  - Genera exploits                                         │
└─────────────────────────────────────────────────────────────┘
```

## ✅ Ventajas de este Enfoque

1. **Sin costos de API** - Usas tu suscripción de Claude Code
2. **Más rápido** - No hay latencia de red
3. **Más contexto** - Claude Code ve todo el historial
4. **Más flexible** - Puedes intervenir cuando quieras
5. **Debugging fácil** - Ves todo en tiempo real

## 🛠️ Cómo Integrar

### Método 1: Scripts de Terminal

Crear scripts que Claude Code puede ejecutar:

```bash
# skynet/bin/scan.sh
#!/bin/bash
python -m skynet.tools.network scan "$1"

# Uso desde Claude Code
$ ./skynet/bin/scan.sh 10.0.0.1
```

### Método 2: Python como Biblioteca

```python
# En tu sesión de Claude Code
from skynet.tools.network import NetworkTools
from skynet.rag.retriever import get_retriever

# Escanear
net = NetworkTools()
results = net.nmap_scan("10.0.0.1")

# Buscar técnicas
retriever = get_retriever()
techniques = retriever.retrieve("sql injection bypass")
```

### Método 3: CLI Shortcuts

```bash
# Crear aliases en ~/.bashrc
alias skynet-scan="python skynet.py scan"
alias skynet-exploit="python skynet.py exploit"
alias skynet-search="python skynet.py search"

# Uso
$ skynet-scan 192.168.1.1
$ skynet-search "privilege escalation linux"
```

## 📋 Comandos Útiles para CTF

Crea comandos específicos que Claude Code puede llamar:

```bash
# Reconnaissance
skynet scan <target>              # Nmap + DNS + services
skynet enum-web <url>             # Gobuster + nikto
skynet enum-smb <target>          # SMB enumeration

# Exploitation
skynet test-sqli <url>            # SQLi testing
skynet test-lfi <url>             # LFI testing
skynet crack-hash <hash>          # Hash cracking

# Analysis
skynet analyze-file <file>        # Full file analysis
skynet extract-hidden <file>      # Steganography
skynet strings-interesting <file> # Smart string extraction

# Knowledge
skynet search <query>             # RAG search
skynet add-knowledge <text>       # Add to knowledge base
```

## 🎯 Workflow Típico en CTF

### Ejemplo: HackTheBox Machine

```bash
# 1. Tú empiezas
user: "Help me pwn HTB machine 'Legacy' at 10.10.10.4"

# 2. Claude Code razona y usa herramientas
claude: "Let me start with reconnaissance"
$ python skynet.py scan 10.10.10.4

# 3. Skynet ejecuta y devuelve resultados
[Skynet Output]
Open ports:
- 139/tcp (smb)
- 445/tcp (smb)
- 3389/tcp (rdp)

# 4. Claude Code analiza y busca conocimiento
$ python skynet.py search "smb exploitation eternal blue"

# 5. Skynet busca en RAG
[Skynet Output]
Found techniques:
- MS17-010 EternalBlue
- SMB version detection
- Null session attacks

# 6. Claude Code genera exploit
claude: "This looks like EternalBlue. Let me craft the exploit..."
[Claude Code genera el script de exploit usando msf o python]

# 7. Ejecución
$ python exploit.py

# 8. Flag encontrada
user: "Got root! Flag: HTB{...}"

# 9. Guardar para futuro
$ python skynet.py add-knowledge "EternalBlue worked on Legacy machine" --category smb
```

## 🔧 Qué Modificar en el Código Actual

### 1. Eliminar referencias a API

```python
# ANTES (en base_agent.py)
# Hacía llamadas a Anthropic API
response = anthropic.chat(...)

# DESPUÉS
# Solo ejecuta herramientas y devuelve resultados estructurados
result = self.executor.execute(command)
return formatted_result
```

### 2. Simplificar Agentes

Los "agentes" son ahora colecciones de herramientas organizadas:

```python
# ReconAgent = herramientas de reconocimiento
# WebAgent = herramientas web
# CryptoAgent = herramientas crypto
# etc.
```

### 3. Mejorar Output para Claude Code

```python
# Output estructurado que Claude Code puede parsear
{
    "success": true,
    "findings": [...],
    "next_steps": [...],
    "relevant_techniques": [...]
}
```

## 📦 Componentes Esenciales (Sin API)

### ✅ Lo que SÍ necesitas:

1. **Herramientas** (tools/)
   - Wrappers de nmap, sqlmap, etc.
   - Ejecutan comandos reales
   - Devuelven resultados parseados

2. **RAG** (rag/)
   - Base de conocimientos
   - Búsqueda de técnicas
   - Embeddings locales (sentence-transformers)

3. **Executor** (core/executor.py)
   - Ejecución segura de comandos
   - Sandbox mode
   - Logging

4. **CLI** (cli/main.py)
   - Comandos útiles
   - Interfaz simple
   - Output estructurado

### ❌ Lo que NO necesitas:

1. ~~Anthropic API client~~
2. ~~Sistema de prompts dinámicos~~
3. ~~Manejo de tokens/rate limiting~~
4. ~~Conversaciones multi-turno complejas~~

## 🚀 Implementación Simplificada

Los agentes se convierten en:

```python
class ReconAgent:
    """Collection of recon tools."""

    def quick_scan(self, target):
        """Fast reconnaissance."""
        results = {
            "ports": self.scan_ports(target),
            "dns": self.dns_lookup(target),
            "services": self.identify_services(target)
        }
        return results

    def full_enum(self, target):
        """Complete enumeration."""
        # Ejecuta múltiples herramientas
        # Devuelve resultados estructurados
        pass
```

Claude Code llama estas funciones y razona sobre los resultados.

## 💡 Ejemplo Real de Uso

```bash
# Terminal con Claude Code
$ claude

claude> Hey, help me with this CTF challenge

user: "I have a web app at http://ctf.example.com, find vulns"

claude: "Let me enumerate directories first"
$ python -c "from skynet.tools.web import WebTools; w=WebTools(); print(w.directory_bruteforce('http://ctf.example.com'))"

[Output: Found /admin, /backup, /api]

claude: "Found interesting paths. Let me check for SQLi on /api"
$ python -c "from skynet.tools.web import WebTools; w=WebTools(); print(w.sqlmap_test('http://ctf.example.com/api?id=1'))"

[Output: Vulnerable to SQLi!]

claude: "Great! Let me craft the exploit..."
[Claude Code genera el exploit basado en los resultados]
```

## 🎯 Ventajas para Competencia

1. **Velocidad** - Herramientas listas para usar
2. **Conocimiento** - RAG con técnicas previas
3. **Organización** - Todo estructurado por categoría
4. **Persistencia** - Logs y sesiones guardadas
5. **Aprendizaje** - Cada CTF mejora la base de conocimientos

## ¿Qué Necesitas Implementar Ahora?

1. ✅ **Herramientas** - Ya están implementadas
2. ✅ **RAG** - Ya funciona
3. 🔨 **Comandos CLI simples** - Mejorar para uso rápido
4. 🔨 **Output estructurado** - JSON parseable
5. 🔨 **Flag detection** - Auto-detectar flags en output
6. 🔨 **ExploitAgent tools** - Pwntools, ROPgadget, etc.

## Siguiente Paso

Crear comandos específicos y scripts que Claude Code puede usar fácilmente.

¿Quieres que implemente:
1. Comandos CLI simplificados
2. Flag detection automático
3. ExploitAgent con pwntools
4. Scripts de ayuda para Claude Code
?
