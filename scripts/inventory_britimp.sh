#!/usr/bin/env bash
# Inventario hardware de pve-britimp (read-only).
# Output sirve para decidir si Kryon puede correr local vs cloud API.
#
# Uso (desde laptop conectada a red Britimp o VPN):
#   bash scripts/inventory_britimp.sh
#
# Asume SSH config con Host alias `pve-britimp` (ver ~/.ssh/config).

set -euo pipefail

SSH_HOST="${1:-pve-britimp}"

echo "=== Conectando a $SSH_HOST ==="
echo ""

ssh -o ConnectTimeout=10 "$SSH_HOST" 'bash -s' <<'REMOTE'
echo "=== OS ==="
hostnamectl 2>/dev/null | head -8 || cat /etc/os-release 2>/dev/null | head -4

echo ""
echo "=== CPU ==="
lscpu | grep -E "Model name|Architecture|Socket|Core\(s\) per socket|Thread\(s\) per core|CPU MHz|CPU max" | head -10

echo ""
echo "=== RAM ==="
free -h

echo ""
echo "=== GPU ==="
if command -v nvidia-smi >/dev/null 2>&1; then
    nvidia-smi -L
    echo ""
    nvidia-smi --query-gpu=name,memory.total,memory.free,memory.used,driver_version,utilization.gpu --format=csv
elif command -v rocm-smi >/dev/null 2>&1; then
    rocm-smi --showid --showmeminfo vram
else
    echo "(no nvidia-smi ni rocm-smi — buscando con lspci:)"
    lspci 2>/dev/null | grep -iE "vga|3d|display|nvidia|amd|radeon" || echo "(sin GPU dedicada detectada)"
fi

echo ""
echo "=== Disco ==="
df -h | grep -vE "tmpfs|udev|loop"

echo ""
echo "=== Proxmox VE ==="
if command -v pveversion >/dev/null 2>&1; then
    pveversion
    echo ""
    echo "VMs:"
    qm list 2>/dev/null | head -10 || echo "  (sin VMs o sin permisos)"
    echo "LXC:"
    pct list 2>/dev/null | head -10 || echo "  (sin LXC o sin permisos)"
else
    echo "(no es Proxmox VE)"
fi

echo ""
echo "=== Kernel + Load ==="
uname -r
uptime

echo ""
echo "=== Networking ==="
ip -br addr show 2>/dev/null | head -5 || ifconfig 2>/dev/null | grep -E "inet " | head -5

echo ""
echo "=== Docker / Containers ==="
if command -v docker >/dev/null 2>&1; then
    docker --version
    docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" 2>/dev/null | head -10
else
    echo "(docker no instalado)"
fi

echo ""
echo "=== Ollama (modelo LLM local) ==="
if command -v ollama >/dev/null 2>&1; then
    ollama --version 2>/dev/null
    ollama list 2>/dev/null | head -10 || echo "(ollama instalado pero sin modelos / sin servicio)"
else
    echo "(ollama no instalado)"
fi
REMOTE

echo ""
echo "=== Inventory done ==="
