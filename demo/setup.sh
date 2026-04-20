#!/usr/bin/env bash
# F26 — bring up the reproducible vulnerable lab + seed demo SSH key.
#
# Run this once to build + start. Subsequent starts just `docker compose up -d`.
set -euo pipefail

cd "$(dirname "$0")"

echo "=============================================="
echo "  Kryon F26 — vulnerable lab bootstrap"
echo "=============================================="

# 1. Ensure ctfnet network exists (reused by kryon + ollama + these targets)
if ! docker network inspect ctfnet >/dev/null 2>&1; then
    echo "  creating network: ctfnet"
    docker network create ctfnet >/dev/null
fi

# 2. Generate demo SSH key (idempotent)
mkdir -p .ssh
if [ ! -f .ssh/demo_key ]; then
    echo "  generating demo SSH key at demo/.ssh/demo_key"
    ssh-keygen -q -N "" -t ed25519 -f .ssh/demo_key -C "kryon-demo"
else
    echo "  demo SSH key already exists, skipping"
fi

# 3. Build + start containers
echo "  building pve_fake image..."
docker compose -f docker-compose.demo.yml build --quiet pve_fake
echo "  starting lab..."
docker compose -f docker-compose.demo.yml up -d
sleep 4

# 4. Smoke test SSH into pve_fake from inside kryon container
echo "  smoke test: kryon → pve_fake over SSH"
if docker exec -e DEMO_KEY_PATH=/run/auditor_pubkey kryon \
     ssh -o StrictHostKeyChecking=no -o BatchMode=yes \
         -i /demo_key auditor@pve_fake 'echo ok' 2>&1 | tail -1; then
    echo "  NOTE: kryon container doesn't have demo key yet; see run command below"
fi

echo ""
echo "=============================================="
echo "  Lab ready."
echo ""
echo "  Targets (from kryon container on ctfnet):"
echo "    ssh auditor@pve_fake                   # fake Proxmox (port 22 inside net)"
echo "    curl http://juice.local:3000/          # OWASP Juice Shop"
echo ""
echo "  Targets (from host, exposed ports):"
echo "    ssh auditor@127.0.0.1 -p 2222 -i demo/.ssh/demo_key"
echo "    curl -k https://127.0.0.1:8006/api2/json/version"
echo "    curl http://127.0.0.1:3003/"
echo ""
echo "  Run audit (host → kryon → pve_fake):"
echo "    ./scripts/kryon-audit.sh \\"
echo "        -u auditor -k demo/.ssh/demo_key \\"
echo "        -c \"Banco Demo Paraguay S.A.\" \\"
echo "        pve_fake proxmox"
echo ""
echo "  Tear down:"
echo "    cd demo && docker compose -f docker-compose.demo.yml down -v"
echo "=============================================="
