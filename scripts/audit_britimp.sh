#!/usr/bin/env bash
# audit_britimp.sh
#
# Run a Kryon engagement against a Britimp Proxmox host using kryon-14b
# local (Ollama container) for inference and the host's VPN for network
# access to the target.
#
# Prerequisites:
#   1. Docker Desktop is running, kryon-ollama container is up with the
#      kryon-14b model loaded (verify with `docker exec kryon-ollama ollama list`).
#   2. nmap is installed on the Windows host (run scripts/install_nmap_host.ps1).
#   3. The Britimp VPN is connected (check `Get-NetIPAddress` for 10.212.134.x).
#   4. uv is installed and the project venv is synced (`uv sync`).
#
# Usage:
#   bash scripts/audit_britimp.sh                        # default target proxmox2
#   bash scripts/audit_britimp.sh 172.18.201.116         # custom target IP
#   bash scripts/audit_britimp.sh 172.18.201.115 user@host  # custom ssh target
#
# Cost: \$0 (Ollama local). Wall time: ~10-20 min per host with kryon-14b.

set -euo pipefail

TARGET="${1:-172.18.201.115}"
SSH_TARGET="${2:-root@${TARGET}}"
CLIENT="${KRYON_CLIENT:-britimp-internal}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTDIR="${KRYON_OUTDIR:-reports/audit-${CLIENT}-${TIMESTAMP}}"

echo "==> Pre-flight checks"

# 1. Ollama container up?
if ! docker ps --format '{{.Names}}' | grep -q '^kryon-ollama$'; then
    echo "  ERROR: kryon-ollama container is not running."
    echo "  Start it with: docker compose -f docker/docker-compose.kali.yml \\"
    echo "                                -f docker/docker-compose.override.yml up -d ollama"
    exit 1
fi
echo "  [ok] kryon-ollama container running"

# 2. kryon-14b model present?
if ! docker exec kryon-ollama ollama list 2>/dev/null | grep -q '^kryon-14b'; then
    echo "  ERROR: kryon-14b model not found in Ollama."
    echo "  Pull it with: bash scripts/install_kryon_r1.sh   (or the equivalent for kryon-14b)"
    exit 1
fi
echo "  [ok] kryon-14b model loaded"

# 3. Ollama container reachable from host?
if ! curl -sS --max-time 3 http://localhost:11435/api/tags >/dev/null 2>&1; then
    echo "  ERROR: Ollama API not reachable on localhost:11435."
    echo "  Check port mapping: docker port kryon-ollama"
    exit 1
fi
echo "  [ok] Ollama API reachable at localhost:11435"

# 4. nmap on host PATH?
if ! command -v nmap >/dev/null 2>&1; then
    echo "  ERROR: nmap not in PATH on host."
    echo "  Install: run scripts/install_nmap_host.ps1 as Administrator,"
    echo "  then open a new shell and re-run this script."
    exit 1
fi
echo "  [ok] nmap available: $(nmap --version | head -1)"

# 5. uv on host PATH?
if ! command -v uv >/dev/null 2>&1; then
    if [ -x "/c/Users/skyva/.local/bin/uv" ]; then
        export PATH="/c/Users/skyva/.local/bin:$PATH"
        echo "  [ok] uv added to PATH from ~/.local/bin"
    else
        echo "  ERROR: uv not found. Install: curl -LsSf https://astral.sh/uv/install.sh | sh"
        exit 1
    fi
else
    echo "  [ok] uv available: $(uv --version)"
fi

# 6. Target reachable from host (VPN active)?
if ! ssh -o ConnectTimeout=5 -o BatchMode=yes "${SSH_TARGET}" 'hostname && uname -r' >/dev/null 2>&1; then
    echo "  ERROR: SSH to ${SSH_TARGET} failed. Is the Britimp VPN connected?"
    echo "  Check: Get-NetIPAddress -InterfaceAlias 'Ethernet 3' (PowerShell)"
    exit 1
fi
echo "  [ok] SSH reachable to ${SSH_TARGET}"

echo ""
echo "==> Configuration"
echo "  Target:        ${TARGET}"
echo "  SSH:           ${SSH_TARGET}"
echo "  Client:        ${CLIENT}"
echo "  Output dir:    ${OUTDIR}"
echo "  Model:         kryon-14b (Ollama local, \$0 cost)"
echo "  Embeddings:    nomic-embed-text (Ollama local)"
echo ""

# Kryon environment — point at Ollama in the kryon-ollama container.
# Port 11435 because compose maps container's 11434 -> host 11435 to avoid
# clashing with a native Ollama install that might be using 11434.
export OPENAI_API_KEY=ollama
export OPENAI_BASE_URL=http://localhost:11435/v1
export OLLAMA=true
export KRYON_MODEL=kryon-14b
export KRYON_TRIAGE_MODEL=kryon-14b
export KRYON_RAG_MODEL=kryon-14b
export KRYON_GUARDRAIL_MODEL=kryon-14b
export KRYON_COMPLIANCE_NARRATOR_MODEL=kryon-14b
export KRYON_EMBEDDING_MODEL=nomic-embed-text
export KRYON_EMBEDDING_BASE_URL=http://localhost:11435
export KRYON_FORCE_TOOL_TURNS=8
export KRYON_PRICE_LIMIT=inf
export KRYON_MAX_TURNS=80
export KRYON_STREAM=false
export KRYON_GUARDRAILS=true
export KRYON_TELEMETRY=false

mkdir -p "${OUTDIR}"

echo "==> Launching kryon engage..."
echo ""

uv run kryon engage "${TARGET}" \
    --ssh "${SSH_TARGET}" \
    --ssh-key ~/.ssh/id_ed25519 \
    --dry-run-only \
    --auto-approve \
    --client "${CLIENT}" \
    --auditor "Kryon-${USER:-skyva}" \
    --out "${OUTDIR}" \
    --skip-reaudit \
    --nmap-timeout 300

echo ""
echo "==> Engagement done. Reports in: ${OUTDIR}"
ls -la "${OUTDIR}" 2>/dev/null | head -10
echo ""
echo "Compare findings against ground truth:"
echo "  diff <(jq -r '.findings[] | .finding' ${OUTDIR}/*.findings.json | sort) \\"
echo "       docs/benchmarks/ground_truth/proxmox2.md"
