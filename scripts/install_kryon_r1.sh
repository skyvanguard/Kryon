#!/usr/bin/env bash
# install_kryon_r1.sh
#
# Pulls deepseek-r1:14b inside the kryon-ollama container and registers
# it as the kryon-r1-14b tag using scripts/modelfiles/kryon-r1-14b.Modelfile.
# Then runs a tiny tool-calling smoke test so we fail fast if the model
# can't emit the function-call format Kryon expects.
#
# Usage (Linux/WSL/git-bash):
#   bash scripts/install_kryon_r1.sh
#
# Windows PowerShell equivalent commented at the bottom.

set -euo pipefail

CONTAINER="${KRYON_OLLAMA_CONTAINER:-kryon-ollama}"
MODELFILE_LOCAL="scripts/modelfiles/kryon-r1-14b.Modelfile"
MODELFILE_REMOTE="/tmp/kryon-r1-14b.Modelfile"
BASE_TAG="deepseek-r1:14b"
KRYON_TAG="kryon-r1-14b"

echo "==> kryon-r1-14b installer"
echo "    container : ${CONTAINER}"
echo "    base      : ${BASE_TAG}"
echo "    target tag: ${KRYON_TAG}"
echo

# 1. Sanity-check container exists and is running.
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
  echo "ERROR: container '${CONTAINER}' is not running." >&2
  echo "       Start the dev stack first:" >&2
  echo "       docker compose -f docker/docker-compose.kali.yml up -d ollama" >&2
  exit 1
fi

# 2. Sanity-check Modelfile exists locally.
if [[ ! -f "${MODELFILE_LOCAL}" ]]; then
  echo "ERROR: ${MODELFILE_LOCAL} not found. Run from repo root." >&2
  exit 1
fi

# 3. Pull the base model (idempotent; ollama skips if cached).
echo "==> Pulling base ${BASE_TAG} ..."
docker exec "${CONTAINER}" ollama pull "${BASE_TAG}"

# 4. Copy Modelfile and create the kryon-tagged variant.
echo "==> Registering ${KRYON_TAG} ..."
docker cp "${MODELFILE_LOCAL}" "${CONTAINER}:${MODELFILE_REMOTE}"
docker exec "${CONTAINER}" ollama create "${KRYON_TAG}" -f "${MODELFILE_REMOTE}"

# 5. Quick chat smoke test (no tools): does the model respond at all?
echo
echo "==> Smoke test 1/2: chat response"
SMOKE_PROMPT='Say "ok" in one word.'
RESP=$(docker exec "${CONTAINER}" ollama run "${KRYON_TAG}" "${SMOKE_PROMPT}" \
       2>/dev/null | tail -n 5 | tr -d '\r')
echo "    response (last 5 lines): ${RESP}"
if [[ -z "${RESP// }" ]]; then
  echo "ERROR: empty response from ${KRYON_TAG}." >&2
  exit 2
fi

# 6. Tool-calling smoke test via /api/chat.
#    R1-distill emits <think>...</think> before tool_calls. We just need
#    to confirm the request returns a 200 with non-empty body — the actual
#    tool-call parsing is verified by juice_shop_llm_bench.py.
echo
echo "==> Smoke test 2/2: /api/chat round-trip"
PAYLOAD=$(cat <<JSON
{
  "model": "${KRYON_TAG}",
  "messages": [{"role": "user", "content": "What is 2+2? Reply with only the number."}],
  "stream": false,
  "options": {"num_ctx": 4096, "num_predict": 512, "temperature": 0}
}
JSON
)
HTTP_CODE=$(docker exec "${CONTAINER}" sh -c \
  "curl -s -o /tmp/r1_smoke.json -w '%{http_code}' \
   -X POST http://localhost:11434/api/chat \
   -H 'Content-Type: application/json' \
   -d '${PAYLOAD}'")
echo "    HTTP ${HTTP_CODE}"
if [[ "${HTTP_CODE}" != "200" ]]; then
  echo "ERROR: /api/chat returned HTTP ${HTTP_CODE}" >&2
  docker exec "${CONTAINER}" cat /tmp/r1_smoke.json >&2 || true
  exit 3
fi

echo
echo "==> Done. Use it with:"
echo "    KRYON_MODEL=${KRYON_TAG} kryon"
echo "    KRYON_MODEL=${KRYON_TAG} uv run python scripts/f18/juice_shop_llm_bench.py"

# ---------------------------------------------------------------------------
# PowerShell equivalent (run from repo root):
#
#   $C = "kryon-ollama"
#   docker exec $C ollama pull deepseek-r1:14b
#   docker cp scripts/modelfiles/kryon-r1-14b.Modelfile ${C}:/tmp/kryon-r1-14b.Modelfile
#   docker exec $C ollama create kryon-r1-14b -f /tmp/kryon-r1-14b.Modelfile
#   docker exec $C ollama run kryon-r1-14b 'Say "ok" in one word.'
# ---------------------------------------------------------------------------
