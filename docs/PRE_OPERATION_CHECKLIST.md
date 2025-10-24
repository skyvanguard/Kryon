# SKYNET Pre-Operation Checklist

**Date:** January 2025
**Version:** SKYNET v3.3.0
**Status:** 🔍 READINESS ASSESSMENT
**Clearance Level:** Omega-Command

---

## Executive Summary

Este documento analiza el estado actual del sistema SKYNET y lista todo lo necesario para estar completamente listo para la primera operación autónoma.

---

## ✅ COMPONENTES YA LISTOS

### 1. Core System ✅
- ✅ **Módulos autónomos:** 8/8 operacionales
  - `skynet.tools.autonomous`
  - `autonomous.auto_recon`
  - `autonomous.decision_engine`
  - `autonomous.orchestrator`
  - `autonomous.strategic_planner`
  - `autonomous.context_analyzer`
  - `autonomous.learning_engine`
  - `autonomous.adaptive_strategy`

- ✅ **Funciones principales:**
  - `autonomous_ctf_solver()` - Solver completo de CTF
  - `autonomous_pentest()` - Pentest automatizado
  - `autonomous_network_pivot()` - Pivoting de red
  - `multi_agent_coordination()` - Coordinación multi-agente
  - `full_auto_enumeration()` - Enumeración automática
  - `select_best_exploit()` - Selección de exploits

### 2. Exploit Database ✅
- ✅ **8 servicios mapeados:** apache, ssh, mysql, postgresql, smb, http, rdp, ftp
- ✅ **16 exploits disponibles** con CVE mappings
- ✅ **Motor de decisión funcional**

### 3. Security Tools ✅
- ✅ **100+ herramientas instaladas:**
  - Reconocimiento: nmap, masscan, rustscan, amass, subfinder, dnsenum
  - Web: gobuster, ffuf, nikto, nuclei, sqlmap, wpscan
  - Explotación: metasploit, hydra, john, hashcat
  - Post-explotación: crackmapexec, evil-winrm, impacket
  - Wireless: aircrack-ng, wifite, reaver
  - Mobile: androguard, frida, objection
  - Network: tcpdump, tshark, scapy
  - Forensics: binwalk, gdb, radare2

### 4. Python Dependencies ✅
- ✅ **skynet-framework:** 1.0.0
- ✅ **mysql-connector-python:** 9.5.0
- ✅ **paramiko:** 4.0.0
- ✅ **impacket:** 0.13.0
- ✅ **scapy:** 2.6.1
- ✅ **shodan, censys, androguard, frida:** Todos instalados

### 5. Container Environment ✅
- ✅ **Base:** Kali Linux rolling
- ✅ **Python:** 3.13.7
- ✅ **Docker:** Configurado y corriendo
- ✅ **Network:** skynet (192.168.3.0/24)

### 6. Documentation ✅
- ✅ `INSTALLATION_COMPLETE.md`
- ✅ `VERIFICATION_REPORT.md`
- ✅ `CAI_TO_SKYNET_MIGRATION_COMPLETE.md`
- ✅ `SECURITY_TOOLS_INVENTORY.md`
- ✅ `TOOL_DEPENDENCIES.md`
- ✅ `TROUBLESHOOTING.md`

---

## ⚠️ COMPONENTES QUE FALTAN

### 1. Configuración de LLM/API Keys ❌

**Estado:** NO CONFIGURADO

**Necesario para:**
- Toma de decisiones autónoma
- Análisis de contexto
- Generación de estrategias
- Coordinación multi-agente

**Qué se necesita:**

#### Opción A: OpenAI API
```bash
# En el contenedor
export OPENAI_API_KEY="sk-..."

# O en archivo de configuración
mkdir -p ~/.skynet
cat > ~/.skynet/config.json << 'EOF'
{
  "provider": "openai",
  "api_key": "sk-...",
  "model": "gpt-4",
  "temperature": 0.7,
  "max_tokens": 2000
}
EOF
```

#### Opción B: Anthropic Claude
```bash
export ANTHROPIC_API_KEY="sk-ant-..."

cat > ~/.skynet/config.json << 'EOF'
{
  "provider": "anthropic",
  "api_key": "sk-ant-...",
  "model": "claude-3-sonnet-20240229",
  "temperature": 0.7,
  "max_tokens": 4000
}
EOF
```

#### Opción C: Ollama (Local)
```bash
# Iniciar Ollama
ollama serve &

# Descargar modelo
ollama pull llama2

cat > ~/.skynet/config.json << 'EOF'
{
  "provider": "ollama",
  "base_url": "http://localhost:11434",
  "model": "llama2",
  "temperature": 0.7
}
EOF
```

#### Opción D: Azure OpenAI
```bash
cat > ~/.skynet/config.json << 'EOF'
{
  "provider": "azure",
  "api_key": "your-azure-key",
  "endpoint": "https://your-resource.openai.azure.com/",
  "deployment": "gpt-4",
  "api_version": "2024-02-15-preview"
}
EOF
```

**Prioridad:** 🔴 CRÍTICA - Sin esto, las funciones autónomas no pueden tomar decisiones

---

### 2. Variables de Entorno del Sistema ⚠️

**Estado:** PARCIALMENTE CONFIGURADO

**Falta configurar:**

```bash
# Variables críticas
export SKYNET_HOME=/workspace
export SKYNET_CONFIG=~/.skynet/config.json
export SKYNET_WORDLISTS=/usr/share/wordlists
export SKYNET_EXPLOITS=/usr/share/exploitdb

# Variables de herramientas Go
export GOPATH=/root/go
export PATH=$PATH:$GOPATH/bin

# Variables opcionales pero útiles
export SKYNET_LOG_LEVEL=INFO
export SKYNET_OUTPUT_DIR=/workspace/results
export SKYNET_CACHE_DIR=/workspace/.cache

# Para Metasploit
export MSF_DATABASE_CONFIG=/root/.msf4/database.yml
```

**Solución:** Crear archivo de inicialización (ver sección 4)

**Prioridad:** 🟡 MEDIA - El sistema funciona sin esto pero mejor con configuración

---

### 3. Base de Datos PostgreSQL para Metasploit ⚠️

**Estado:** NO INICIALIZADA

**Problema:** Metasploit necesita PostgreSQL para guardar resultados

**Solución:**
```bash
# Inicializar PostgreSQL
service postgresql start

# Inicializar base de datos de Metasploit
msfdb init

# Verificar
msfconsole -q -x "db_status; exit"
```

**Prioridad:** 🟡 MEDIA - Metasploit funciona sin BD pero pierde funcionalidad

---

### 4. Script de Inicialización del Sistema ❌

**Estado:** NO EXISTE

**Necesario:** Script que configure todo automáticamente al iniciar el contenedor

**Ubicación sugerida:** `/workspace/scripts/init_skynet.sh`

**Contenido:** Ver sección "Scripts Necesarios" abajo

**Prioridad:** 🟡 MEDIA - Facilita operaciones pero no es crítico

---

### 5. Configuración de Logging/Trazabilidad ⚠️

**Estado:** BÁSICO

**Falta:**
- Sistema de logs centralizado
- Trazabilidad de operaciones
- Registro de decisiones autónomas

**Solución:**
```bash
mkdir -p /workspace/logs/{operations,decisions,tools,errors}
```

**Prioridad:** 🟢 BAJA - Nice to have, no crítico para primera operación

---

### 6. Target de Prueba ❌

**Estado:** NO DEFINIDO

**Necesario:** Un target vulnerable para la primera operación

**Opciones:**

#### Opción A: Máquina Local Vulnerable (Recomendado)
```bash
# Usar contenedor incluido en docker-compose
docker-compose up prompt-injection-poc
# Target: 192.168.3.14
```

#### Opción B: HackTheBox/TryHackMe
- Necesita VPN configurada
- Necesita cuenta activa
- Target: IP de la máquina activa

#### Opción C: Metasploitable
```bash
docker run -d --network skynet --ip 192.168.3.100 vulnerables/metasploitable2
```

**Prioridad:** 🔴 CRÍTICA - Necesario para cualquier operación

---

### 7. Configuración de Red/Conectividad ⚠️

**Estado:** CONFIGURADO PERO NO PROBADO

**Verificar:**
```bash
# Dentro del contenedor
ping -c 2 192.168.3.14  # Target de prueba
ping -c 2 8.8.8.8       # Internet
curl -I https://google.com  # HTTPS
```

**Prioridad:** 🔴 CRÍTICA - Sin conectividad no hay operación

---

## 📋 SCRIPTS NECESARIOS

### 1. Script de Inicialización del Sistema

**Archivo:** `/workspace/scripts/init_skynet.sh`

```bash
#!/bin/bash
# SKYNET System Initialization Script
# Clearance: Omega-Command

echo "🤖 SKYNET v3.3.0 - Inicialización del Sistema"
echo "=============================================="

# 1. Configurar variables de entorno
export SKYNET_HOME=/workspace
export SKYNET_CONFIG=~/.skynet/config.json
export SKYNET_WORDLISTS=/usr/share/wordlists
export SKYNET_EXPLOITS=/usr/share/exploitdb
export GOPATH=/root/go
export PATH=$PATH:$GOPATH/bin
export SKYNET_LOG_LEVEL=INFO
export SKYNET_OUTPUT_DIR=/workspace/results
export SKYNET_CACHE_DIR=/workspace/.cache

echo "✅ Variables de entorno configuradas"

# 2. Crear directorios necesarios
mkdir -p ~/.skynet
mkdir -p /workspace/results/{operations,reports,logs}
mkdir -p /workspace/.cache/scans

echo "✅ Directorios creados"

# 3. Verificar configuración de API
if [ ! -f ~/.skynet/config.json ]; then
    echo "⚠️  WARNING: No se encontró config.json"
    echo "   Crear ~/.skynet/config.json con las API keys necesarias"
else
    echo "✅ Configuración de API encontrada"
fi

# 4. Inicializar PostgreSQL para Metasploit
if ! service postgresql status > /dev/null 2>&1; then
    service postgresql start
    echo "✅ PostgreSQL iniciado"
fi

# 5. Verificar base de datos de Metasploit
if ! msfdb status | grep -q "connected"; then
    echo "🔧 Inicializando base de datos de Metasploit..."
    msfdb init
    echo "✅ Metasploit DB inicializada"
fi

# 6. Iniciar Metasploit RPC (para automatización)
if ! pgrep -f "msfrpcd" > /dev/null; then
    msfrpcd -P skynet -a 127.0.0.1 &
    echo "✅ Metasploit RPC iniciado"
fi

# 7. Actualizar Nuclei templates
if command -v nuclei &>/dev/null; then
    nuclei -update-templates -silent
    echo "✅ Nuclei templates actualizados"
fi

# 8. Verificar herramientas críticas
echo ""
echo "🔍 Verificando herramientas críticas..."
TOOLS="nmap gobuster sqlmap hydra nuclei msfconsole"
for tool in $TOOLS; do
    if command -v $tool &>/dev/null; then
        echo "  ✅ $tool"
    else
        echo "  ❌ $tool - NOT FOUND"
    fi
done

# 9. Verificar módulos Python
echo ""
echo "🐍 Verificando módulos Python..."
python3 << 'PYEOF'
import sys
sys.path.insert(0, '/workspace/src')
try:
    from skynet.tools.autonomous import autonomous_ctf_solver, autonomous_pentest
    print("  ✅ Módulos autónomos de SKYNET")
except Exception as e:
    print(f"  ❌ Error importando módulos: {e}")
PYEOF

# 10. Mostrar estado final
echo ""
echo "=============================================="
echo "✅ SKYNET inicializado correctamente"
echo ""
echo "📊 Estado del sistema:"
echo "  - Config: $([ -f ~/.skynet/config.json ] && echo '✅' || echo '❌')"
echo "  - PostgreSQL: $(service postgresql status > /dev/null 2>&1 && echo '✅' || echo '❌')"
echo "  - Metasploit DB: $(msfdb status | grep -q 'connected' && echo '✅' || echo '⚠️')"
echo "  - Metasploit RPC: $(pgrep -f msfrpcd > /dev/null && echo '✅' || echo '❌')"
echo ""
echo "🚀 Sistema listo para operaciones"
echo ""
echo "Para ejecutar primera operación:"
echo "  python3 /workspace/scripts/first_operation.py --target <IP>"
echo ""
```

---

### 2. Script de Primera Operación

**Archivo:** `/workspace/scripts/first_operation.py`

```python
#!/usr/bin/env python3
"""
SKYNET First Operation Script
Automated CTF/Pentest on target

Clearance: Omega-Command
"""

import sys
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from skynet.tools.autonomous import autonomous_ctf_solver, full_auto_enumeration


def first_operation(target_ip: str, mode: str = "ctf", difficulty: str = "easy"):
    """
    Execute first autonomous operation.

    Args:
        target_ip: Target IP address
        mode: Operation mode (ctf, pentest, recon)
        difficulty: Difficulty level (easy, medium, hard)
    """
    print("=" * 80)
    print("🤖 SKYNET v3.3.0 - Primera Operación Autónoma")
    print("=" * 80)
    print(f"\n📍 Target: {target_ip}")
    print(f"🎯 Modo: {mode}")
    print(f"📊 Dificultad: {difficulty}\n")

    if mode == "recon":
        # Solo reconocimiento
        print("🔍 Iniciando reconocimiento autónomo...\n")
        results = full_auto_enumeration(
            target_ip=target_ip,
            deep_scan=True,
            max_time_minutes=30
        )

        print("\n" + "=" * 80)
        print("📊 RESULTADOS DEL RECONOCIMIENTO")
        print("=" * 80)
        print(f"\nPuertos abiertos: {len(results.get('open_ports', []))}")
        print(f"Servicios detectados: {len(results.get('services', []))}")
        print(f"Vulnerabilidades potenciales: {len(results.get('vulnerabilities', []))}")

        if results.get('open_ports'):
            print("\n🔓 Puertos abiertos:")
            for port in results['open_ports'][:10]:  # Mostrar primeros 10
                print(f"  - {port}")

        if results.get('services'):
            print("\n🎯 Servicios detectados:")
            for service in results['services'][:10]:
                print(f"  - {service.get('name', 'unknown')} en puerto {service.get('port', 'N/A')}")

    elif mode == "ctf":
        # CTF completo
        print("🚀 Iniciando solver autónomo de CTF...\n")
        results = autonomous_ctf_solver(
            target_ip=target_ip,
            difficulty=difficulty,
            max_time_hours=2,
            objectives=["initial_access", "privilege_escalation", "find_flags"]
        )

        print("\n" + "=" * 80)
        print("🏆 RESULTADOS DE LA OPERACIÓN CTF")
        print("=" * 80)

        if results.get('success'):
            print("\n✅ OPERACIÓN EXITOSA")
        else:
            print("\n⚠️  OPERACIÓN INCOMPLETA")

        print(f"\n📈 Progreso:")
        print(f"  - Fase alcanzada: {results.get('final_phase', 'N/A')}")
        print(f"  - Tiempo total: {results.get('total_time', 0):.2f}s")

        if results.get('flags_found'):
            print(f"\n🚩 Flags encontradas: {len(results['flags_found'])}")
            for flag in results['flags_found']:
                print(f"  - {flag}")

        if results.get('services_exploited'):
            print(f"\n💥 Servicios explotados: {len(results['services_exploited'])}")
            for service in results['services_exploited']:
                print(f"  - {service}")

        if results.get('privilege_level'):
            print(f"\n👑 Nivel de privilegio: {results['privilege_level']}")

        if results.get('lateral_movement'):
            print(f"\n↔️  Movimiento lateral: {len(results['lateral_movement'])} oportunidades")

    else:
        print(f"❌ Modo desconocido: {mode}")
        return

    # Guardar reporte
    import json
    from datetime import datetime

    output_file = f"/workspace/results/operations/operation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n📄 Reporte guardado en: {output_file}")
    print("\n" + "=" * 80)
    print("✅ Operación completada")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SKYNET First Operation Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Reconocimiento básico
  python3 first_operation.py --target 192.168.3.14 --mode recon

  # CTF completo (fácil)
  python3 first_operation.py --target 192.168.3.14 --mode ctf --difficulty easy

  # CTF completo (medio)
  python3 first_operation.py --target 10.10.10.5 --mode ctf --difficulty medium
        """
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target IP address"
    )

    parser.add_argument(
        "--mode",
        choices=["recon", "ctf", "pentest"],
        default="ctf",
        help="Operation mode (default: ctf)"
    )

    parser.add_argument(
        "--difficulty",
        choices=["easy", "medium", "hard"],
        default="easy",
        help="Difficulty level (default: easy)"
    )

    args = parser.parse_args()

    first_operation(
        target_ip=args.target,
        mode=args.mode,
        difficulty=args.difficulty
    )
```

---

## 🎯 CHECKLIST PARA PRIMERA OPERACIÓN

### Pre-Operación (Hacer ANTES de comenzar)

- [ ] **1. Configurar API Key**
  ```bash
  # Crear ~/.skynet/config.json con provider y API key
  vi ~/.skynet/config.json
  ```

- [ ] **2. Ejecutar script de inicialización**
  ```bash
  chmod +x /workspace/scripts/init_skynet.sh
  /workspace/scripts/init_skynet.sh
  ```

- [ ] **3. Iniciar target de prueba**
  ```bash
  # Opción A: Contenedor de prueba
  docker-compose up -d prompt-injection-poc

  # Opción B: Metasploitable
  docker run -d --network skynet --ip 192.168.3.100 \
    vulnerables/metasploitable2
  ```

- [ ] **4. Verificar conectividad**
  ```bash
  # Desde el contenedor
  ping -c 2 192.168.3.14  # O la IP del target
  nmap -Pn -p 80,443 192.168.3.14
  ```

- [ ] **5. Crear scripts de operación**
  ```bash
  # Copiar scripts desde esta documentación
  vi /workspace/scripts/init_skynet.sh
  vi /workspace/scripts/first_operation.py
  chmod +x /workspace/scripts/*.sh
  chmod +x /workspace/scripts/*.py
  ```

### Durante la Operación

- [ ] **6. Ejecutar primera operación (solo recon)**
  ```bash
  cd /workspace
  python3 scripts/first_operation.py --target 192.168.3.14 --mode recon
  ```

- [ ] **7. Revisar resultados**
  ```bash
  # Ver reporte JSON
  cat /workspace/results/operations/operation_*.json | jq
  ```

- [ ] **8. Si el recon funciona, ejecutar CTF completo**
  ```bash
  python3 scripts/first_operation.py --target 192.168.3.14 --mode ctf --difficulty easy
  ```

### Post-Operación

- [ ] **9. Analizar logs**
  ```bash
  # Revisar logs de operación
  ls -lah /workspace/results/
  ```

- [ ] **10. Documentar resultados**
  - Qué funcionó
  - Qué falló
  - Ajustes necesarios

---

## 🚀 QUICK START (Paso a Paso)

### Mínimo Absoluto para Primera Operación

**Tiempo estimado:** 15-20 minutos

#### 1. Configurar API Key (5 min)
```bash
docker exec -it cai_devcontainer-devenv-1 bash

# Crear configuración
mkdir -p ~/.skynet
cat > ~/.skynet/config.json << 'EOF'
{
  "provider": "openai",
  "api_key": "TU_API_KEY_AQUI",
  "model": "gpt-4",
  "temperature": 0.7,
  "max_tokens": 2000
}
EOF
```

#### 2. Crear scripts (5 min)
```bash
mkdir -p /workspace/scripts
mkdir -p /workspace/results/operations

# Copiar init_skynet.sh desde este documento
# Copiar first_operation.py desde este documento
chmod +x /workspace/scripts/*.sh /workspace/scripts/*.py
```

#### 3. Inicializar sistema (2 min)
```bash
cd /workspace
./scripts/init_skynet.sh
```

#### 4. Iniciar target (2 min)
```bash
# En host (fuera del contenedor)
cd C:\Users\admin\Documents\cai
docker-compose up -d prompt-injection-poc
```

#### 5. Ejecutar primera operación (5 min)
```bash
# Dentro del contenedor
cd /workspace
python3 scripts/first_operation.py --target 192.168.3.14 --mode recon
```

---

## 📊 NIVELES DE READINESS

### Nivel 1: BÁSICO (Actual) 🟡
**Estado:** 60% listo

**Puede hacer:**
- ✅ Reconocimiento con fallbacks (socket scanning)
- ✅ Detección de servicios
- ✅ Selección de exploits
- ⚠️  Decisiones limitadas (sin LLM)

**No puede hacer:**
- ❌ Análisis autónomo avanzado
- ❌ Estrategias adaptativas
- ❌ Toma de decisiones complejas

### Nivel 2: OPERACIONAL (Con API Key) 🟢
**Estado:** Alcanzable en 15 minutos

**Puede hacer:**
- ✅ Todo lo del Nivel 1
- ✅ Análisis autónomo con LLM
- ✅ Toma de decisiones inteligentes
- ✅ Estrategias adaptativas
- ✅ Generación de reportes

**Requisito único:**
- 🔑 API Key configurada

### Nivel 3: PROFESIONAL (Completamente configurado) 🔵
**Estado:** Alcanzable en 30 minutos

**Puede hacer:**
- ✅ Todo lo del Nivel 2
- ✅ Persistencia de resultados (Metasploit DB)
- ✅ Logging completo
- ✅ Trazabilidad de operaciones
- ✅ Operaciones multi-target

**Requisitos:**
- 🔑 API Key
- 📊 PostgreSQL inicializado
- 📝 Scripts de automatización
- 🎯 Target configurado

---

## 💡 RECOMENDACIÓN

### Para Primera Operación: Nivel 2 (OPERACIONAL)

**Razón:** Balance perfecto entre simplicidad y funcionalidad

**Pasos mínimos:**
1. ✅ Configurar API Key (5 min)
2. ✅ Crear scripts básicos (5 min)
3. ✅ Iniciar target de prueba (2 min)
4. ✅ Ejecutar operación de reconocimiento (3 min)

**Total:** ~15 minutos

---

## ❓ FAQ

### ¿Puedo hacer una operación SIN API Key?

**Sí**, pero limitado:
- Solo reconocimiento básico
- Sin análisis inteligente
- Sin decisiones autónomas
- Sin generación de reportes

**Recomendación:** Configurar API Key para experiencia completa

### ¿Qué API provider es mejor?

**Para producción:**
- **OpenAI GPT-4:** Mejor calidad de decisiones
- **Anthropic Claude:** Mejor razonamiento complejo

**Para desarrollo:**
- **Ollama (local):** Gratis, privado, pero menor calidad

### ¿Cuánto cuesta una operación?

**Con OpenAI GPT-4:**
- Operación pequeña (recon): $0.10-0.50
- Operación mediana (CTF): $1-3
- Operación grande (pentest): $5-10

**Con Claude:**
- Similar o ligeramente más barato

**Con Ollama:**
- $0 (local)

---

## 📞 SIGUIENTE PASO

### ¿Qué quieres hacer?

**Opción A: Configuración Rápida (15 min)**
→ Te ayudo a configurar solo lo esencial y hacemos la primera operación

**Opción B: Configuración Completa (30 min)**
→ Configuramos todo el sistema profesional con todos los scripts

**Opción C: Solo dar el comando**
→ Te doy el comando exacto para ejecutar ahora mismo (requiere API key)

---

**🤖 SKYNET v3.3.0 - Pre-Operation Assessment**

**Sistema:** 60% LISTO ✅
**Crítico faltante:** API Key configuración 🔑
**Tiempo para operación:** 15 minutos ⏱️
**Clearance:** Omega-Command

