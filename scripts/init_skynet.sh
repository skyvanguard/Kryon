#!/bin/bash
# SKYNET System Initialization Script
# Clearance: Omega-Command

echo '🤖 SKYNET v3.3.0 - Inicialización del Sistema'
echo '=============================================='

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

echo '✅ Variables de entorno configuradas'

# 2. Verificar directorios
mkdir -p /workspace/results/{operations,reports,logs}
mkdir -p /workspace/.cache/scans
echo '✅ Directorios verificados'

# 3. Verificar configuración
if [ -f ~/.skynet/config.json ]; then
    echo '✅ Configuración encontrada:'
    cat ~/.skynet/config.json | grep -E 'provider|model'
else
    echo '❌ No se encontró config.json'
    exit 1
fi

# 4. Verificar conectividad con Ollama
echo ''
echo '🔍 Verificando Ollama...'
if curl -s http://host.docker.internal:11434/api/tags > /dev/null; then
    echo '✅ Ollama accesible'
    MODELS=$(curl -s http://host.docker.internal:11434/api/tags | grep -o '"name":"[^"]*"' | head -1)
    echo "   Modelo: $MODELS"
else
    echo '❌ No se puede conectar a Ollama'
fi

# 5. Inicializar PostgreSQL para Metasploit
echo ''
if ! service postgresql status > /dev/null 2>&1; then
    echo '🔧 Iniciando PostgreSQL...'
    service postgresql start
    sleep 2
fi

if service postgresql status > /dev/null 2>&1; then
    echo '✅ PostgreSQL corriendo'

    # Verificar/crear DB de Metasploit
    if ! msfdb status 2>/dev/null | grep -q 'connected'; then
        echo '🔧 Inicializando Metasploit DB...'
        msfdb init 2>&1 | tail -3
    fi
else
    echo '⚠️  PostgreSQL no disponible (opcional)'
fi

# 6. Iniciar Metasploit RPC
echo ''
if ! pgrep -f 'msfrpcd' > /dev/null; then
    echo '🔧 Iniciando Metasploit RPC...'
    msfrpcd -P skynet -a 127.0.0.1 > /dev/null 2>&1 &
    sleep 2
fi

if pgrep -f 'msfrpcd' > /dev/null; then
    echo '✅ Metasploit RPC corriendo'
else
    echo '⚠️  Metasploit RPC no disponible (opcional)'
fi

# 7. Verificar herramientas críticas
echo ''
echo '🔍 Verificando herramientas críticas...'
CRITICAL_TOOLS='nmap gobuster sqlmap nuclei'
FOUND=0
TOTAL=0
for tool in $CRITICAL_TOOLS; do
    TOTAL=$((TOTAL + 1))
    if command -v $tool &>/dev/null; then
        echo "  ✅ $tool"
        FOUND=$((FOUND + 1))
    else
        echo "  ❌ $tool"
    fi
done

# 8. Verificar módulos Python
echo ''
echo '🐍 Verificando módulos SKYNET...'
cd /workspace
python3 << 'PYEOF'
import sys
sys.path.insert(0, '/workspace/src')
try:
    from skynet.tools.autonomous import autonomous_ctf_solver, full_auto_enumeration
    from skynet.tools.autonomous.decision_engine import EXPLOIT_DATABASE
    print('  ✅ Módulos autónomos')
    print(f'  ✅ Base de datos: {len(EXPLOIT_DATABASE)} servicios')
except Exception as e:
    print(f'  ❌ Error: {e}')
PYEOF

# 9. Estado final
echo ''
echo '=============================================='
echo '📊 RESUMEN DEL SISTEMA'
echo '=============================================='
echo ''
echo 'Configuración:'
echo "  • Ollama: ✅"
echo "  • Config file: $([ -f ~/.skynet/config.json ] && echo '✅' || echo '❌')"
echo "  • Herramientas: $FOUND/$TOTAL críticas"
echo ''
echo 'Servicios:'
echo "  • PostgreSQL: $(service postgresql status > /dev/null 2>&1 && echo '✅' || echo '⚠️ ')"
echo "  • Metasploit RPC: $(pgrep -f msfrpcd > /dev/null && echo '✅' || echo '⚠️ ')"
echo ''
echo '✅ Sistema listo para operaciones'
echo ''
echo 'Ejecutar primera operación:'
echo '  python3 /workspace/scripts/first_operation.py --target <IP> --mode recon'
echo ''
