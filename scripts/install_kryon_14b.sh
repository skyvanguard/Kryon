#!/usr/bin/env bash
# install_kryon_14b.sh
#
# F85.1 — Builds the kryon-14b tag from Unsloth's Qwen3-14B UD-Q4_K_XL
# GGUF and runs a tool-calling smoke test. Replaces the unpinned
# `qwen3:14b` baseline with a Modelfile-managed, reproducible build.
#
# The base GGUF lives on HuggingFace and ollama pulls it directly via
# the hf.co/<repo>:<quant> reference in the Modelfile. The actual
# download lands in ollama's blob store inside the container, so the
# host filesystem is not touched.
#
# Usage (Linux/WSL/git-bash):
#   bash scripts/install_kryon_14b.sh
#
# Windows PowerShell equivalent commented at the bottom.

set -euo pipefail

CONTAINER="${KRYON_OLLAMA_CONTAINER:-kryon-ollama}"
MODELFILE_LOCAL="scripts/modelfiles/kryon-14b.Modelfile"
MODELFILE_REMOTE="/tmp/kryon-14b.Modelfile"
KRYON_TAG="kryon-14b"

echo "==> kryon-14b installer (Unsloth UD-Q4_K_XL)"
echo "    container : ${CONTAINER}"
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

# 3. Register the kryon-tagged variant. ollama pulls the HF GGUF
#    automatically the first time, then caches it in its blob store.
echo "==> Registering ${KRYON_TAG} (this may take ~10 minutes on first run while the 9-10 GB GGUF downloads) ..."
docker cp "${MODELFILE_LOCAL}" "${CONTAINER}:${MODELFILE_REMOTE}"
docker exec "${CONTAINER}" ollama create "${KRYON_TAG}" -f "${MODELFILE_REMOTE}"

# 4. Quick chat smoke test (no tools): does the model respond at all?
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

# 5. Tool-calling smoke test via /api/chat. Same payload pattern as
#    install_kryon_r1.sh so the two installers are directly comparable.
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
  "curl -s -o /tmp/k14b_smoke.json -w '%{http_code}' \
   -X POST http://localhost:11434/api/chat \
   -H 'Content-Type: application/json' \
   -d '${PAYLOAD}'")
echo "    HTTP ${HTTP_CODE}"
if [[ "${HTTP_CODE}" != "200" ]]; then
  echo "ERROR: /api/chat returned HTTP ${HTTP_CODE}" >&2
  docker exec "${CONTAINER}" cat /tmp/k14b_smoke.json >&2 || true
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
#   docker cp scripts/modelfiles/kryon-14b.Modelfile ${C}:/tmp/kryon-14b.Modelfile
#   docker exec $C ollama create kryon-14b -f /tmp/kryon-14b.Modelfile
#   docker exec $C ollama run kryon-14b 'Say "ok" in one word.'
# ---------------------------------------------------------------------------
