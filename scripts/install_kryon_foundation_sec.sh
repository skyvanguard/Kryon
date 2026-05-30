#!/usr/bin/env bash
# install_kryon_foundation_sec.sh
#
# Pulls Foundation-Sec-8B-Reasoning (Cisco Foundation AI, security
# reasoning model, Llama-3.1-8B base) inside the kryon-ollama container
# and registers it as the kryon-foundation-sec tag using
# models/Modelfile.kryon-foundation-sec. Then runs a tiny smoke test so we
# fail fast if the model can't respond / the tag is misbuilt.
#
# Usage (Linux/WSL/git-bash):
#   bash scripts/install_kryon_foundation_sec.sh
#
# Windows PowerShell equivalent commented at the bottom.

set -euo pipefail

CONTAINER="${KRYON_OLLAMA_CONTAINER:-kryon-ollama}"
MODELFILE_LOCAL="models/Modelfile.kryon-foundation-sec"
MODELFILE_REMOTE="/tmp/Modelfile.kryon-foundation-sec"
BASE_TAG="hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF"
# Slash-free local alias — the Modelfile's FROM references THIS, not the
# hf.co tag. ollama treats a FROM containing "/" as a filesystem path and
# fails create with "no Modelfile or safetensors files found".
ALIAS_TAG="foundation-sec-reasoning-base:latest"
KRYON_TAG="kryon-foundation-sec"

echo "==> kryon-foundation-sec installer"
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

# 3. Pull the base GGUF (idempotent; ollama skips if cached). ~8.5 GB.
echo "==> Pulling base ${BASE_TAG} ..."
docker exec "${CONTAINER}" ollama pull "${BASE_TAG}"

# 3b. Re-tag to a slash-free local alias the Modelfile's FROM can reference.
echo "==> Aliasing ${BASE_TAG}:latest -> ${ALIAS_TAG} ..."
docker exec "${CONTAINER}" ollama cp "${BASE_TAG}:latest" "${ALIAS_TAG}"

# 4. Stream the Modelfile into the container via stdin and create the tag.
#    NB: we deliberately do NOT use `docker cp` here. On Windows hosts,
#    docker-cp'ing the Modelfile yields a file that `ollama create` rejects
#    with "no Modelfile or safetensors files found" even though its bytes are
#    identical to a working copy (some docker-cp filesystem-attribute quirk).
#    Piping through `cat` inside the container sidesteps it entirely.
echo "==> Registering ${KRYON_TAG} ..."
docker exec -i "${CONTAINER}" sh -c \
  "cat > ${MODELFILE_REMOTE} && ollama create ${KRYON_TAG} -f ${MODELFILE_REMOTE}" \
  < "${MODELFILE_LOCAL}"

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

# 6. Domain smoke test — confirm the security corpus actually answers. The
#    reasoning variant emits a <think> block before its answer; we just check
#    the reply mentions CWE-89 for SQL injection. (No curl: the ollama
#    container ships no curl binary, so we go through the CLI.)
echo
echo "==> Smoke test 2/2: security-domain answer (expect CWE-89)"
DOMAIN_RESP=$(docker exec "${CONTAINER}" sh -c \
  "echo 'What CWE number is SQL injection? Reply with only the CWE id.' | ollama run ${KRYON_TAG}" \
  2>/dev/null | tr -d '\r')
echo "    answer tail: $(printf '%s' "${DOMAIN_RESP}" | tail -n 1)"
if ! printf '%s' "${DOMAIN_RESP}" | grep -qi "CWE-89"; then
  echo "WARNING: expected CWE-89 in the answer; model may need a warm-up run." >&2
fi

echo
echo "==> Done. Use it with:"
echo "    KRYON_MODEL=${KRYON_TAG} kryon"
echo "    KRYON_MODEL=${KRYON_TAG} kryon investigate ./path/to/source/  # vuln-research line"

# ---------------------------------------------------------------------------
# PowerShell equivalent (run from repo root):
#
#   $C = "kryon-ollama"
#   docker exec $C ollama pull hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF
#   docker exec $C ollama cp hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest foundation-sec-reasoning-base:latest
#   docker cp models/Modelfile.kryon-foundation-sec ${C}:/tmp/Modelfile.kryon-foundation-sec
#   docker exec $C ollama create kryon-foundation-sec -f /tmp/Modelfile.kryon-foundation-sec
#   docker exec $C ollama run kryon-foundation-sec 'Say "ok" in one word.'
# ---------------------------------------------------------------------------
