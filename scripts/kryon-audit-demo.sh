#!/usr/bin/env bash
# F26.1 — one-liner to audit the fake Proxmox target spun up by demo/setup.sh
#
# Usage:
#   ./scripts/kryon-audit-demo.sh
#
# Pre-reqs:
#   demo/setup.sh already ran (lab is up, kryon has the demo key at
#   /home/kryon/kryon_keys/demo_key, kryon is on ctfnet).
set -euo pipefail

CONTAINER="${KRYON_CONTAINER:-kryon}"
CLIENT="${KRYON_CLIENT_NAME:-Banco Demo Paraguay S.A.}"
FRAMEWORK="${1:-proxmox}"
TARGET="${2:-pve_fake}"

echo "=============================================="
echo "  Kryon F26.1 demo audit"
echo "  target:    $TARGET"
echo "  framework: $FRAMEWORK"
echo "  client:    $CLIENT"
echo "=============================================="

MSYS_NO_PATHCONV=1 docker exec \
    -e KRYON_SSH_USER=auditor \
    -e KRYON_SSH_KEY=/home/kryon/kryon_keys/demo_key \
    -e KRYON_CLIENT_NAME="$CLIENT" \
    "$CONTAINER" python -c "
from kryon.tools.appsec.compliance_audit import _run_compliance_pdf
print(_run_compliance_pdf(
    host='$TARGET',
    framework='$FRAMEWORK',
    ssh_user='auditor',
    ssh_key_path='/home/kryon/kryon_keys/demo_key',
    client_name='''$CLIENT''',
))
"

echo ""
echo "  Latest outputs:"
REPORTS_DIR="$(cd "$(dirname "$0")/.." && pwd)/reports"
ls -lht "$REPORTS_DIR/" 2>/dev/null | grep -v '\.gitignore$\|^total' | head -3
echo "=============================================="
