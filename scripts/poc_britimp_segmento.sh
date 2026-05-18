#!/usr/bin/env bash
# poc_britimp_segmento.sh
#
# Orquesta el POC interno de Kryon sobre el segmento de servidores Britimp.
# Diseñado para correr DENTRO del pod RunPod (después de provisionar el
# container Kryon + Ollama + el modelo kryon-120B).
#
# Flujo:
#   1. Pre-flight: confirma Ollama up + modelo cargado + nmap + VPN.
#   2. Pre-poblar CVE cache (evita 30 min de descarga durante el scan).
#   3. `kryon discover --subnet $SEGMENT --queue-add` (con throttle F196).
#   4. `kryon queue process --concurrency 1 --framework $FRAMEWORKS
#       --orchestrated --auto-approve` por cada host vivo.
#   5. Consolidar reportes en $OUTDIR/consolidated/.
#   6. Imprimir resumen (succeeded / failed / archivos generados).
#
# Variables de entorno relevantes (banca-safe defaults para horario laboral):
#   SEGMENT             — CIDR del segmento (ej. 10.x.x.0/24). REQUERIDO.
#   FRAMEWORKS          — frameworks de compliance (default: pci_dss).
#   KRYON_MODEL         — modelo Ollama (default: kryon-120B).
#   KRYON_NMAP_TIMING   — F195/F196 (default: T2 banca-safe).
#   KRYON_NMAP_MIN_RATE — F195/F196 (default: 50).
#   KRYON_NMAP_MAX_PARALLELISM — F195/F196 (default: 10).
#   KRYON_NUCLEI_RATE_LIMIT — F195 (default: 50).
#   KRYON_NUCLEI_BULK_SIZE  — F195 (default: 10).
#   KRYON_NUCLEI_CONCURRENCY — F195 (default: 10).
#   OUTDIR              — directorio raíz de reportes (default: ./poc-britimp-<ts>).
#   CLIENT              — nombre del cliente para el reporte (default: britimp-internal).
#   OLLAMA_URL          — URL del Ollama (default: http://localhost:11434).
#
# Uso:
#   SEGMENT=10.x.x.0/24 ./scripts/poc_britimp_segmento.sh
#
# Costo: depende del pod RunPod. Wall-time esperado: 1-2 días hábiles.

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuración
# -----------------------------------------------------------------------------

if [[ -z "${SEGMENT:-}" ]]; then
    echo "ERROR: SEGMENT no definido. Ejemplo: SEGMENT=10.x.x.0/24 $0" >&2
    exit 2
fi

FRAMEWORKS="${FRAMEWORKS:-pci_dss}"
CLIENT="${CLIENT:-britimp-internal}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUTDIR="${OUTDIR:-./poc-britimp-${TIMESTAMP}}"
OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"

# Banca-safe throttle defaults — el operador puede override con su propio .env.
export KRYON_MODEL="${KRYON_MODEL:-kryon-120B}"
export KRYON_NMAP_TIMING="${KRYON_NMAP_TIMING:-T2}"
export KRYON_NMAP_MIN_RATE="${KRYON_NMAP_MIN_RATE:-50}"
export KRYON_NMAP_MAX_PARALLELISM="${KRYON_NMAP_MAX_PARALLELISM:-10}"
export KRYON_NUCLEI_RATE_LIMIT="${KRYON_NUCLEI_RATE_LIMIT:-50}"
export KRYON_NUCLEI_BULK_SIZE="${KRYON_NUCLEI_BULK_SIZE:-10}"
export KRYON_NUCLEI_CONCURRENCY="${KRYON_NUCLEI_CONCURRENCY:-10}"
export KRYON_RED_TEAM="${KRYON_RED_TEAM:-false}"

mkdir -p "$OUTDIR"

echo "==============================================================================="
echo "POC Kryon — Britimp (segmento de servidores)"
echo "==============================================================================="
echo "  Segment       : $SEGMENT"
echo "  Frameworks    : $FRAMEWORKS"
echo "  Client        : $CLIENT"
echo "  Output dir    : $OUTDIR"
echo "  Model         : $KRYON_MODEL"
echo "  Throttle      : -T${KRYON_NMAP_TIMING#T} min-rate=$KRYON_NMAP_MIN_RATE max-par=$KRYON_NMAP_MAX_PARALLELISM"
echo "  Red team mode : $KRYON_RED_TEAM (debe ser 'false' para banca-safe)"
echo "==============================================================================="
echo ""

# -----------------------------------------------------------------------------
# Pre-flight
# -----------------------------------------------------------------------------

echo "==> Pre-flight checks"

# 1. Ollama up
if ! curl -sS --max-time 5 "${OLLAMA_URL}/api/tags" >/dev/null 2>&1; then
    echo "  ERROR: Ollama no responde en ${OLLAMA_URL}"
    exit 1
fi
echo "  [ok] Ollama up en ${OLLAMA_URL}"

# 2. Modelo cargado
if ! curl -sS "${OLLAMA_URL}/api/tags" | grep -q "\"${KRYON_MODEL}"; then
    echo "  ERROR: modelo '${KRYON_MODEL}' no está en Ollama."
    echo "    Provisión esperada: 'ollama create ${KRYON_MODEL} -f /workspace/models/Modelfile.${KRYON_MODEL}'"
    exit 1
fi
echo "  [ok] modelo ${KRYON_MODEL} cargado"

# 3. nmap
if ! command -v nmap >/dev/null 2>&1; then
    echo "  ERROR: nmap no instalado. apt install nmap"
    exit 1
fi
echo "  [ok] nmap $(nmap --version | head -1 | awk '{print $3}')"

# 4. kryon CLI
if ! command -v kryon >/dev/null 2>&1; then
    echo "  ERROR: kryon CLI no en PATH. Activá el venv o uv run kryon."
    exit 1
fi
echo "  [ok] kryon $(kryon --version 2>/dev/null || echo '(versión desconocida)')"

# 5. Conectividad al segmento (un ping a un host arbitrario del CIDR)
# Saltar si KRYON_SKIP_PREFLIGHT_PING=true (útil cuando los hosts filtran ICMP).
if [[ "${KRYON_SKIP_PREFLIGHT_PING:-}" != "true" ]]; then
    first_ip="$(echo "$SEGMENT" | awk -F'[./]' '{print $1"."$2"."$3"."($4==0?"1":$4)}')"
    if ping -c 1 -W 2 "$first_ip" >/dev/null 2>&1; then
        echo "  [ok] $first_ip responde al ping (VPN parece OK)"
    else
        echo "  [warn] $first_ip no responde al ping. Puede ser firewall o VPN caída."
        echo "    Set KRYON_SKIP_PREFLIGHT_PING=true para omitir este check si el segmento filtra ICMP."
    fi
fi

echo ""

# -----------------------------------------------------------------------------
# CVE cache pre-poblado
# -----------------------------------------------------------------------------

if [[ ! -s "$HOME/.kryon/nvd_cache/cves.txt" ]]; then
    echo "==> Pre-poblar CVE cache (5-10 min, una sola vez)"
    kryon update-cve-cache --all || echo "  [warn] update-cve-cache falló — F151 puede dejar pasar IDs no validados"
else
    echo "==> CVE cache ya existe ($(wc -l < "$HOME/.kryon/nvd_cache/cves.txt") IDs)"
fi
echo ""

# -----------------------------------------------------------------------------
# Fase 1 — Discover (barrer segmento)
# -----------------------------------------------------------------------------

echo "==> Fase 1 — Discover ($SEGMENT)"
kryon discover \
    --subnet "$SEGMENT" \
    --queue-add \
    --output "$OUTDIR/discovery.json"

n_pending="$(kryon queue list --status pending 2>/dev/null | grep -c '^[a-f0-9]' || true)"
echo "  hosts encolados: $n_pending"
echo ""

if [[ "$n_pending" == "0" ]]; then
    echo "ERROR: No se encolaron hosts. Revisar el rango y la conectividad."
    exit 1
fi

# -----------------------------------------------------------------------------
# Fase 2 — Process queue (engage por host)
# -----------------------------------------------------------------------------

echo "==> Fase 2 — Process queue (engage por host)"
echo "    framework=$FRAMEWORKS, concurrency=1 (banca-safe), orchestrated"

set +e
kryon queue process \
    --concurrency 1 \
    --framework "$FRAMEWORKS" \
    --orchestrated \
    --auto-approve \
    --client "$CLIENT" \
    --out "$OUTDIR/per-host"
PROCESS_RC=$?
set -e

echo ""

# -----------------------------------------------------------------------------
# Fase 3 — Consolidar reportes
# -----------------------------------------------------------------------------

echo "==> Fase 3 — Consolidar reportes"
mkdir -p "$OUTDIR/consolidated"

# Listado plano de PDFs/HTMLs generados (Magic Doc + multi-framework).
find "$OUTDIR/per-host" -maxdepth 3 \( -name '*.pdf' -o -name '*.html' -o -name '*.json' \) \
    -exec cp {} "$OUTDIR/consolidated/" \; 2>/dev/null || true

echo "  archivos consolidados:"
ls -la "$OUTDIR/consolidated/" 2>/dev/null | tail -n +2 || echo "  (vacío)"
echo ""

# -----------------------------------------------------------------------------
# Resumen final
# -----------------------------------------------------------------------------

echo "==============================================================================="
echo "POC FINALIZADO"
echo "==============================================================================="
echo "  Output dir       : $OUTDIR"
echo "  Process exit code: $PROCESS_RC  $( [[ $PROCESS_RC -eq 0 ]] && echo '(todos OK)' || echo '(uno o más hosts fallaron)' )"
echo "  Reportes         : $OUTDIR/consolidated/"
echo "  Queue state      : $(kryon queue list 2>/dev/null | wc -l) items"
echo "==============================================================================="
echo ""
echo "Próximos pasos:"
echo "  1. Revisar $OUTDIR/consolidated/ y subir a Drive / OneDrive antes del TERMINATE."
echo "  2. Verificar el hash de reproducibilidad en cada reporte."
echo "  3. Si todo OK: TERMINATE el pod desde RunPod console (\\$0 permanente)."

exit "$PROCESS_RC"
