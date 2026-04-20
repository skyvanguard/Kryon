#!/usr/bin/env bash
# F27+F28 — one-liner compliance audit from host, with SSH remote support.
#
# Usage:
#   ./scripts/kryon-audit.sh [-u USER] [-k KEY] [-p PORT] [-c CLIENT] HOST FRAMEWORK
#
# Flags (all optional except HOST + FRAMEWORK):
#   -u USER    SSH user for remote audit            (or env KRYON_SSH_USER)
#   -k KEY     SSH private key path                 (or env KRYON_SSH_KEY)
#   -p PORT    SSH port (default 22)                (or env KRYON_SSH_PORT)
#   -c CLIENT  Banking client name on cover         (or env KRYON_CLIENT_NAME)
#   -h         show this help
#
# Positional:
#   HOST       target hostname or "localhost" for self-audit
#   FRAMEWORK  all | pci-dss | proxmox | ad
#
# Examples:
#   # Local self-audit (no SSH):
#   ./scripts/kryon-audit.sh localhost all
#
#   # Remote Proxmox (key-based SSH), with bank branding on cover:
#   ./scripts/kryon-audit.sh -u auditor -k ~/.ssh/bank_audit \
#       -c "Banco Continental S.A.E.C.A." \
#       pve01.bank.com.py proxmox
#
#   # Remote AD (requires KRYON_AD_* env vars for the bind creds):
#   KRYON_AD_DOMAIN=BANK.LOCAL KRYON_AD_USER=auditor@BANK.LOCAL \
#   KRYON_AD_PASS='***' KRYON_AD_DC=dc01.bank.local \
#       ./scripts/kryon-audit.sh -u admin -k ~/.ssh/dc_audit \
#       dc01.bank.local ad
#
# Pre-reqs (one-time):
#   docker compose -f docker/docker-compose.kali.yml \
#                  -f docker/docker-compose.override.yml up -d
#   # ^ the override bind-mounts ~/.ssh and ../reports
set -euo pipefail

# Defaults (env-var fallbacks)
SSH_USER="${KRYON_SSH_USER:-}"
SSH_KEY="${KRYON_SSH_KEY:-}"
SSH_PORT="${KRYON_SSH_PORT:-22}"
CLIENT_NAME="${KRYON_CLIENT_NAME:-}"

usage() {
    sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while getopts ":u:k:p:c:h" opt; do
    case $opt in
        u) SSH_USER="$OPTARG" ;;
        k) SSH_KEY="$OPTARG" ;;
        p) SSH_PORT="$OPTARG" ;;
        c) CLIENT_NAME="$OPTARG" ;;
        h) usage 0 ;;
        \?) echo "unknown flag -$OPTARG" >&2; usage 1 ;;
    esac
done
shift $((OPTIND - 1))

HOST="${1:-}"
FRAMEWORK="${2:-all}"
if [[ -z "$HOST" ]]; then
    echo "!! missing HOST" >&2
    usage 1
fi

CONTAINER="${KRYON_CONTAINER:-kryon}"
REPORTS_DIR="$(cd "$(dirname "$0")/.." && pwd)/reports"
mkdir -p "$REPORTS_DIR"

# Translate host-side SSH key path to container-side path (bind mount lives
# at /home/kryon/.ssh inside the container — see docker-compose.override.yml).
container_ssh_key() {
    local host_path="$1"
    if [[ -z "$host_path" ]]; then echo ""; return; fi
    # Expand ~ on the host
    host_path="${host_path/#\~/$HOME}"
    case "$host_path" in
        "$HOME/.ssh/"*) echo "/home/kryon/.ssh/${host_path#"$HOME/.ssh/"}" ;;
        *) echo "$host_path" ;;  # fallback: let container try the literal path
    esac
}
SSH_KEY_CONTAINER="$(container_ssh_key "$SSH_KEY")"

echo "=============================================="
echo "  Kryon Compliance Audit"
echo "  host:      $HOST  (framework=$FRAMEWORK)"
if [[ -n "$SSH_USER" ]]; then
    echo "  ssh:       $SSH_USER@$HOST:$SSH_PORT  key=${SSH_KEY_CONTAINER:-<default>}"
fi
if [[ -n "$CLIENT_NAME" ]]; then
    echo "  client:    $CLIENT_NAME"
fi
echo "  reports:   $REPORTS_DIR/"
echo "=============================================="

# Pass-through env (AD creds + client name + SSH port numeric)
ENV_ARGS=()
for v in KRYON_AD_DOMAIN KRYON_AD_USER KRYON_AD_PASS KRYON_AD_DC; do
    if [[ -n "${!v:-}" ]]; then ENV_ARGS+=("-e" "$v=${!v}"); fi
done

docker exec "${ENV_ARGS[@]}" "$CONTAINER" python -c "
from kryon.tools.appsec.compliance_audit import _run_compliance_pdf
print(_run_compliance_pdf(
    host='$HOST',
    framework='$FRAMEWORK',
    ssh_user='$SSH_USER',
    ssh_key_path='$SSH_KEY_CONTAINER',
    ssh_port=$SSH_PORT,
    client_name='''$CLIENT_NAME''',
))
"

echo ""
echo "=============================================="
echo "  Recent outputs in: $REPORTS_DIR/"
ls -lht "$REPORTS_DIR/" 2>/dev/null | grep -v '^total\|\.gitignore$' | head -5 || echo "  (empty)"
echo "=============================================="
