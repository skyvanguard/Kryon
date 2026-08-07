#!/usr/bin/env bash
# =============================================================================
# KRYON Appliance — setup de primera vez (correr en la mini PC del cliente)
# =============================================================================
# Genera las claves, escribe .env.appliance apuntando a tu cerebro central, y
# deja el appliance listo para levantar. Idempotente: si ya existe un
# .env.appliance, pregunta antes de sobreescribir.
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")"

BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
say() { printf '%s\n' "$*"; }

say "${BOLD}${CYAN}=== KRYON Appliance — configuración inicial ===${RESET}"

# --- 0. dependencias --------------------------------------------------------
command -v docker >/dev/null 2>&1 || { say "${YELLOW}Docker no está instalado. Instalalo antes de continuar.${RESET}"; exit 1; }

# --- 1. no pisar una config existente sin avisar ----------------------------
ENV_FILE=".env.appliance"
if [ -f "$ENV_FILE" ]; then
  read -r -p "Ya existe $ENV_FILE. ¿Sobreescribir? (se pierden las claves actuales) [s/N] " ans
  case "${ans:-N}" in
    s|S|y|Y) : ;;
    *) say "Cancelado. La config actual se mantiene."; exit 0 ;;
  esac
fi

# --- 2. generar secretos ----------------------------------------------------
gen_secret() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 32
  elif command -v python3 >/dev/null 2>&1; then python3 -c "import secrets;print(secrets.token_hex(32))"
  else head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}
API_KEY="$(gen_secret)"
JWT_SECRET="$(gen_secret)"

# --- 3. datos del despliegue ------------------------------------------------
read -r -p "IP:puerto de tu cerebro central (LLM) [10.0.0.10:8080]: " BRAIN
BRAIN="${BRAIN:-10.0.0.10:8080}"
read -r -p "Nombre del cliente (para los reportes) [cliente]: " CLIENT
CLIENT="${CLIENT:-cliente}"
read -r -p "Puerto del dashboard en la mini PC [8700]: " PORT
PORT="${PORT:-8700}"

# --- 4. escribir .env.appliance ---------------------------------------------
cat > "$ENV_FILE" <<EOF
# Generado por setup.sh — NO commitear (contiene secretos).
OPENAI_BASE_URL=http://${BRAIN}/v1
OPENAI_API_KEY=llama
KRYON_MODEL=qwen-unc
KRYON_LOCAL_LLM=true

KRYON_UNIFIED=true
KRYON_AGENT_TYPE=kryon

KRYON_API_KEY=${API_KEY}
KRYON_JWT_SECRET=${JWT_SECRET}
KRYON_PORT=${PORT}

KRYON_MODEL_MAX_TOKENS=262144
KRYON_CLIENT_NAME=${CLIENT}

KRYON_STREAM=false
KRYON_MEMORY=false
EOF
chmod 600 "$ENV_FILE"

say ""
say "${GREEN}${BOLD}✓ Config lista.${RESET}"
say "  Cerebro central : http://${BRAIN}/v1"
say "  Cliente         : ${CLIENT}"
say "  Dashboard        : http://<IP-de-esta-mini-PC>:${PORT}/"
say ""
say "${BOLD}${YELLOW}⚠ GUARDÁ esta API key (es la que el cliente ingresa en el dashboard):${RESET}"
say "  ${BOLD}${API_KEY}${RESET}"
say ""

# --- 5. levantar (opcional) -------------------------------------------------
read -r -p "¿Levantar el appliance ahora? [S/n] " up
case "${up:-S}" in
  n|N) say "Ok. Levantalo con: docker compose -f docker-compose.appliance.yml up -d --build" ;;
  *)
    say "${CYAN}Construyendo e iniciando…${RESET}"
    docker compose -f docker-compose.appliance.yml up -d --build
    say "${GREEN}✓ Appliance arriba en el puerto ${PORT}.${RESET}"
    ;;
esac
