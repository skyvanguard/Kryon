# KRYON - Configuracion Rapida: Ollama + Kali Container

Guía de inicio rápido para usar KRYON con Ollama (LLM local) y contenedor Kali para herramientas de seguridad.

---

## Arquitectura

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│   Windows/Mac   │         │  Ollama Server   │         │  Kali Container │
│   KRYON CLI    │ ───────▶│  qwen2.5:7b      │         │  Security Tools │
│   Orchestrator  │ ◀───────│  :11434          │         │  nmap, metasploit│
│   Pentest Agent  │         └──────────────────┘         │  sqlmap, etc.   │
│                 │ ────────────────────────────────────▶│  :22 (SSH)      │
└─────────────────┘         Genera decisiones             └─────────────────┘
   Orquestación              autónomas                     Ejecuta comandos
```

---

## Paso 1: Instalar Ollama

### Windows / MacOS

1. Descargar de: https://ollama.com/download
2. Instalar el ejecutable
3. Verificar instalación:
   ```bash
   ollama --version
   ```

### Linux

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

---

## Paso 2: Descargar Modelo Recomendado

El modelo **qwen2.5:7b** está optimizado para operaciones autónomas (razonamiento, decisiones tácticas):

```bash
ollama pull qwen2.5:7b
```

**Alternativas** (menor rendimiento autónomo):
- `llama3:8b` - General purpose, más rápido pero menos razonamiento
- `mistral:7b` - Bueno para tool calling
- `deepseek-coder:6.7b` - Especializado en código

**Requerimientos**:
- qwen2.5:7b: ~5GB RAM, ~4.7GB disco
- Tiempo de descarga: 2-5 min (depende de conexión)

---

## Paso 3: Iniciar Ollama Server

Ollama se ejecuta automáticamente como servicio en Windows/Mac. Verificar:

```bash
ollama list
# Debería mostrar: qwen2.5:7b
```

**Puerto por defecto**: `http://localhost:11434/v1` (compatible OpenAI API)

---

## Paso 4: Configurar Kali Container

### Opción A: Docker Compose (Recomendado)

Crear `docker-compose.yml`:

```yaml
version: '3.8'
services:
  kali:
    image: kalilinux/kali-rolling
    container_name: kryon-kali
    network_mode: bridge
    ports:
      - "2222:22"  # SSH
    volumes:
      - ./results:/root/results  # Compartir resultados
    command: >
      /bin/bash -c "
      apt-get update &&
      apt-get install -y openssh-server nmap metasploit-framework sqlmap nuclei &&
      service ssh start &&
      tail -f /dev/null
      "
    restart: unless-stopped
```

Iniciar:
```bash
docker-compose up -d
```

### Opción B: Docker run directo

```bash
docker run -d \
  --name kryon-kali \
  -p 2222:22 \
  -v $(pwd)/results:/root/results \
  kalilinux/kali-rolling \
  bash -c "apt-get update && apt-get install -y openssh-server nmap && service ssh start && tail -f /dev/null"
```

### Configurar SSH (Opcional - para acceso directo)

```bash
# Dentro del contenedor
docker exec -it kryon-kali bash
passwd root  # Establecer contraseña
```

Desde Windows, conectar:
```bash
ssh root@localhost -p 2222
```

---

## Paso 5: Configurar KRYON

### Variables de Entorno

Crear `.env` en `C:\Users\admin\Documents\kryon\`:

```bash
# Ollama Configuration
OPENAI_BASE_URL=http://localhost:11434/v1
KRYON_MODEL=qwen2.5:7b
OPENAI_API_KEY=ollama  # Dummy key requerido

# Agent Configuration
KRYON_AGENT_TYPE=pentest_agent  # Agente ofensivo con autonomía
KRYON_GUARDRAILS=true              # Seguridad habilitada
KRYON_DEBUG=1                       # Logs informativos

# Autonomous Features
KRYON_LEARNING=true                 # Learning Engine activo
KRYON_ADAPTIVE=true                 # Adaptive Strategy activo

# CTF/Lab Configuration (opcional)
CTF_SUBNET=192.168.3.0/24
CTF_IP=192.168.3.100
CTF_INSIDE=true  # Ejecutar desde dentro del contenedor
```

### Instalar KRYON (si no está instalado)

```bash
cd C:\Users\admin\Documents\kryon
.venv313\Scripts\activate  # O tu virtualenv preferido
pip install -e .
```

---

## Paso 6: Primera Operación Autónoma

### Test de Conectividad

```bash
# Verificar Ollama
ollama list

# Verificar Kali
docker ps | grep kryon-kali

# Verificar KRYON import
python -c "from kryon.agents.pentest_agent import pentest_agent; print('PENTEST AGENT READY')"
```

### Lanzar Pentest Agent

```bash
# Con variables de entorno cargadas
kryon

# O especificar directamente
OPENAI_BASE_URL=http://localhost:11434/v1 KRYON_MODEL=qwen2.5:7b KRYON_AGENT_TYPE=pentest_agent kryon
```

### Ejemplo de Uso - Reconocimiento Autónomo

Una vez en el REPL de KRYON:

```
You: Necesito reconocer el objetivo 192.168.3.100, es una máquina TryHackMe

[Pentest Agent automáticamente]:
1. Ejecuta nmap con parámetros óptimos
2. Analiza resultados (extract_credentials, analyze_context)
3. Busca exploits conocidos (get_learned_recommendations)
4. Si falla, adapta técnica (execute_with_adaptation)
5. Registra aprendizaje (record_operation)
```

---

## Verificación del Sistema

### Script de Diagnóstico

```python
# scripts/verify_ollama_kali.py
import os
import requests
from kryon.agents.pentest_agent import pentest_agent

def verify_ollama():
    """Verificar Ollama está funcionando"""
    try:
        resp = requests.get("http://localhost:11434/api/tags")
        models = [m['name'] for m in resp.json().get('models', [])]
        print(f"✓ Ollama running. Models: {models}")
        return 'qwen2.5:7b' in ' '.join(models)
    except:
        print("✗ Ollama not accessible")
        return False

def verify_pentest_agent():
    """Verificar Pentest Agent carga correctamente"""
    try:
        tools = len(pentest_agent.tools)
        model = pentest_agent.model.model
        print(f"✓ Pentest Agent loaded: {tools} tools, model={model}")
        return tools >= 8
    except Exception as e:
        print(f"✗ Pentest Agent failed: {e}")
        return False

def verify_kali():
    """Verificar Kali container"""
    import subprocess
    result = subprocess.run(['docker', 'ps', '--filter', 'name=kryon-kali'],
                          capture_output=True, text=True)
    running = 'kryon-kali' in result.stdout
    print(f"{'✓' if running else '✗'} Kali container {'running' if running else 'not found'}")
    return running

if __name__ == "__main__":
    print("KRYON System Verification")
    print("=" * 50)

    checks = [
        ("Ollama Server", verify_ollama()),
        ("Pentest Agent", verify_pentest_agent()),
        ("Kali Container", verify_kali()),
    ]

    passed = sum(1 for _, result in checks if result)
    print("=" * 50)
    print(f"Result: {passed}/3 checks passed")

    if passed == 3:
        print("\n✓ System ready for autonomous operations!")
    else:
        print("\n✗ System not ready. Fix issues above.")
```

Ejecutar:
```bash
python scripts/verify_ollama_kali.py
```

---

## Capacidades Autónomas del Pentest Agent

### 1. Learning Engine
- **Qué hace**: Registra cada operación en SQLite local (`.kryon_knowledge/operations.db`)
- **Beneficio**: Aprende qué exploits funcionan contra qué targets
- **Uso automático**: `get_learned_recommendations()` sugiere exploits basados en historial

### 2. Adaptive Strategy
- **Qué hace**: Detecta 10 tipos de fallo (WAF, IPS, rate limit, timeout, etc.)
- **Beneficio**: Auto-adapta exploits con encoding, obfuscación, delays
- **Uso automático**: `execute_with_adaptation()` reintenta hasta 5 veces con ajustes

### 3. Context Analyzer
- **Qué hace**: Extrae credenciales (20+ patrones), hints, vulnerabilidades de cualquier texto
- **Beneficio**: No pierde información valiosa en logs/banners
- **Uso automático**: `analyze_context()` + `extract_credentials()` + `follow_hints()`

---

## Troubleshooting

### Ollama no responde

```bash
# Windows
Get-Process ollama
# Si no aparece:
ollama serve

# Linux/Mac
systemctl status ollama
systemctl start ollama
```

### Modelo qwen2.5:7b no encontrado

```bash
ollama pull qwen2.5:7b
# Esperar descarga (4.7GB)
ollama list  # Verificar
```

### Kali container sin herramientas

```bash
docker exec -it kryon-kali bash
apt-get update
apt-get install -y nmap metasploit-framework sqlmap nuclei gobuster ffuf
```

### Error "No module named 'kryon.agents.pentest_agent'"

```bash
# Reinstalar en modo desarrollo
cd C:\Users\admin\Documents\kryon
pip install -e .
```

### Guardrails bloquean operaciones legítimas

```bash
# Deshabilitar SOLO para entornos de prueba autorizados
export KRYON_GUARDRAILS=false
kryon
```

---

## Rendimiento y Optimización

### Modelos Recomendados por Caso de Uso

| Caso de Uso | Modelo Recomendado | RAM Req | Velocidad | Autonomía |
|-------------|-------------------|---------|-----------|-----------|
| **CTF/TryHackMe** | `qwen2.5:7b` | 5GB | Media | ★★★★★ |
| **Bug Bounty** | `qwen2.5:14b` | 9GB | Lenta | ★★★★★ |
| **Pentesting Rápido** | `llama3:8b` | 6GB | Rápida | ★★★☆☆ |
| **Análisis Código** | `deepseek-coder:6.7b` | 5GB | Media | ★★★★☆ |
| **Recursos Limitados** | `phi3:mini` | 2GB | Muy rápida | ★★☆☆☆ |

### Parámetros de Ollama para mejor autonomía

Crear `~/.ollama/models/qwen2.5-autonomous.json`:

```json
{
  "model": "qwen2.5:7b",
  "temperature": 0.3,
  "top_p": 0.9,
  "top_k": 40,
  "repeat_penalty": 1.1,
  "num_ctx": 8192
}
```

Usar:
```bash
export KRYON_MODEL=qwen2.5-autonomous
```

---

## Próximos Pasos

1. **Explorar Agentes**: `/agent` en REPL para ver todos los agentes disponibles
2. **Configurar CTF Master**: Agente especializado en CTFs con orquestación multi-tool
3. **Configurar Knowledge Base**: Inicializar base de datos de vulnerabilidades
4. **Habilitar Tracing**: Visualizar decisiones autónomas con OpenTelemetry

Ver: `docs/AUTONOMY_GUIDE.md` para detalles completos del sistema autónomo.

---

**KRYON PENTEST AGENT OPERATIONAL**
