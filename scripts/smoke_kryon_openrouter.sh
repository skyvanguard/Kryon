#!/usr/bin/env bash
# Smoke test Kryon contra OpenRouter (openai/gpt-oss-120b:free).
#
# Uso:
#   export OPENROUTER_API_KEY=sk-or-v1-...
#   bash scripts/smoke_kryon_openrouter.sh
#
# Costo: $0 (free tier). Consume ~5 RPD del cap diario de 50 RPD compartido.
# Si OpenRouter da 429, esperá unos minutos o cargá $10 para 1000 RPD.

set -euo pipefail

if [ -z "${OPENROUTER_API_KEY:-}" ]; then
    echo "ERROR: exporta OPENROUTER_API_KEY antes de correr este script:"
    echo "    export OPENROUTER_API_KEY=sk-or-v1-..."
    exit 1
fi

# === Provider config ===
export OPENAI_API_KEY="$OPENROUTER_API_KEY"
export OPENAI_BASE_URL="https://openrouter.ai/api/v1"
export OLLAMA=false

# === Kryon model config ===
# gpt-oss-120b: 120B MoE, reasoning + tools, 131K ctx, free
export KRYON_MODEL="openai/gpt-oss-120b:free"
# Llama 3.3 70B free para servicios secundarios (no reasoning, mas rapido)
export KRYON_TRIAGE_MODEL="meta-llama/llama-3.3-70b-instruct:free"
export KRYON_RAG_MODEL="meta-llama/llama-3.3-70b-instruct:free"
export KRYON_GUARDRAIL_MODEL="meta-llama/llama-3.3-70b-instruct:free"
export KRYON_COMPLIANCE_NARRATOR_MODEL="meta-llama/llama-3.3-70b-instruct:free"

# === Kryon runtime config ===
export KRYON_FORCE_TOOL_TURNS=0      # API hace tool calling correcto
export KRYON_STREAM=false             # non-stream estable
export KRYON_GUARDRAILS=true
export KRYON_MAX_TURNS=5              # paranoia para no comerse RPD
export KRYON_PRICE_LIMIT=0.10         # paranoia (free tier deberia ser $0)
export KRYON_CHECKPOINT_EVERY=20

# === Embeddings local (no toca OpenRouter) ===
export KRYON_EMBEDDING_MODEL="${KRYON_EMBEDDING_MODEL:-nomic-embed-text}"
export KRYON_EMBEDDING_BASE_URL="${KRYON_EMBEDDING_BASE_URL:-http://localhost:11434}"

echo "=== Config aplicada ==="
echo "  Provider:           OpenRouter"
echo "  Model principal:    $KRYON_MODEL"
echo "  Model secundarios:  $KRYON_TRIAGE_MODEL"
echo "  Max turns:          $KRYON_MAX_TURNS"
echo "  Price limit:        \$$KRYON_PRICE_LIMIT"
echo "  Embeddings:         $KRYON_EMBEDDING_MODEL @ $KRYON_EMBEDDING_BASE_URL"
echo ""

# === Smoke test secuencial ===

echo "=== [1/3] Validar API + endpoint ==="
HTTP=$(curl -sS -o /dev/null -w "%{http_code}" \
    https://openrouter.ai/api/v1/models \
    -H "Authorization: Bearer $OPENAI_API_KEY")
if [ "$HTTP" = "200" ]; then
    echo "  OK: OpenRouter responde HTTP 200"
else
    echo "  FAIL: HTTP $HTTP"
    exit 1
fi
echo ""

echo "=== [2/3] /skill list (sin LLM call, valida boot) ==="
echo "  ejecutando: kryon -- '/skill list'"
uv run kryon -- "/skill list" 2>&1 | tail -30 || echo "  WARN: comando fallo, revisa output"
echo ""

echo "=== [3/3] Tool call real con gpt-oss-120b (5 turns max) ==="
echo "  ejecutando: kryon -- 'scan localhost on port 22'"
uv run kryon -- "scan localhost on port 22" 2>&1 | tail -50 || echo "  WARN: smoke test crash"
echo ""

echo "=== Smoke test completo ==="
echo ""
echo "Si los 3 pasos pasaron, OpenRouter + Kryon esta funcionando con gpt-oss-120b."
echo ""
echo "Para audit de web real, escala a:"
echo "  kryon -- '/skill list | grep -i web'"
echo "  kryon -- '/skill show appsec'"
echo "  kryon -- 'audit https://target.example.com using appsec skill'"
echo ""
echo "Recordatorio: 50 RPD compartido en free tier sin saldo en cuenta."
echo "Cargar \$10 USD en OpenRouter para subir a 1000 RPD."
