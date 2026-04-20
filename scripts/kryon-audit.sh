#!/usr/bin/env bash
# F27 — one-liner compliance audit from host.
#
# Usage:
#   ./scripts/kryon-audit.sh [host] [framework]
#     host       default: localhost
#     framework  all | pci-dss | proxmox | ad        default: all
#
# Examples for ASOBAN demo:
#   ./scripts/kryon-audit.sh pve.bank.local proxmox
#   KRYON_AD_DOMAIN=BANK.LOCAL KRYON_AD_USER=auditor@BANK.LOCAL \
#   KRYON_AD_PASS='...' KRYON_AD_DC=dc01.bank.local \
#       ./scripts/kryon-audit.sh dc01.bank.local ad
#   ./scripts/kryon-audit.sh localhost all
#
# Pre-reqs:
#   docker compose up must have already started the kryon container with
#   ./reports bind-mounted (F27 docker-compose.override.yml).
#
# Output: ./reports/kryon_<framework>_<host>_<timestamp>.{pdf,html}
set -euo pipefail

HOST="${1:-localhost}"
FRAMEWORK="${2:-all}"
CONTAINER="${KRYON_CONTAINER:-kryon}"
REPORTS_DIR="$(cd "$(dirname "$0")/.." && pwd)/reports"
mkdir -p "$REPORTS_DIR"

echo "=============================================="
echo "  Kryon Compliance Audit"
echo "  host:      $HOST"
echo "  framework: $FRAMEWORK"
echo "  reports:   $REPORTS_DIR/"
echo "=============================================="

# Pass-through AD creds + client name (branding on cover) if present
AD_ENV=()
for v in KRYON_AD_DOMAIN KRYON_AD_USER KRYON_AD_PASS KRYON_AD_DC KRYON_CLIENT_NAME; do
    if [[ -n "${!v:-}" ]]; then
        AD_ENV+=("-e" "$v=${!v}")
    fi
done

# Call the plain Python function (no decorator acrobatics needed)
docker exec "${AD_ENV[@]}" "$CONTAINER" python -c "
from kryon.tools.appsec.compliance_audit import _run_compliance_pdf
print(_run_compliance_pdf(host='$HOST', framework='$FRAMEWORK'))
"

echo ""
echo "=============================================="
echo "  Recent outputs in: $REPORTS_DIR/"
ls -lht "$REPORTS_DIR/" 2>/dev/null | head -5 || echo "  (empty)"
echo "=============================================="
