#!/usr/bin/env bash
# F17 — one-shot setup: copies src/kryon/webexploit into the running kryon
# container and smoke-tests the engine against an ephemeral test server.
# Use before invoking webexploit_bench.py.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo ">> Checking kryon container is running..."
if ! docker ps --format '{{.Names}}' | grep -qx 'kryon'; then
  echo "!! kryon container not running. Start it first:"
  echo "   docker compose -f docker/docker-compose.kali.yml -f docker/docker-compose.override.yml up -d"
  exit 1
fi

echo ">> Copying src/kryon/webexploit → kryon:/usr/local/lib/python3.*/site-packages/kryon/webexploit"
# Python site-packages path inside the image can vary; find it dynamically.
SITE_PKG="$(docker exec kryon python -c "import kryon, os; print(os.path.dirname(kryon.__file__))")"
echo "   target: $SITE_PKG/webexploit"

docker exec kryon rm -rf "$SITE_PKG/webexploit"
docker cp "$REPO_ROOT/src/kryon/webexploit" "kryon:$SITE_PKG/webexploit"

echo ">> Smoke test: import"
docker exec kryon python -c "
from kryon.webexploit import run_engine
from kryon.webexploit.probes import PROBES
print('probes loaded:', [p.probe_id for p in PROBES])
print('total probes:', len(PROBES))
"

echo ">> Smoke test: CLI --help"
docker exec kryon python -m kryon.webexploit --help | head -5

echo ""
echo ">> Setup OK. Run the benchmark with:"
echo "   python scripts/f17/webexploit_bench.py"
echo ""
echo "   (or a single challenge:)"
echo "   python scripts/f17/webexploit_bench.py --only 'I Got Id'"
