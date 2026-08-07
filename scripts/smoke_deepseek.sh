#!/usr/bin/env bash
# Smoke test DeepSeek API — corre vos esto en tu shell, pegás el output al asistente.
# Asume que `export DEEPSEEK_API_KEY=sk-...` ya esta seteado.
set -euo pipefail

if [ -z "${DEEPSEEK_API_KEY:-}" ]; then
    echo "ERROR: DEEPSEEK_API_KEY no esta seteado. Hace antes:"
    echo "    export DEEPSEEK_API_KEY=sk-tu-clave"
    exit 1
fi

echo "=== Test 1: auth + lista de modelos (gratis) ==="
HTTP_CODE=$(curl -sS -o /tmp/ds_models.json -w "%{http_code}" \
    https://api.deepseek.com/v1/models \
    -H "Authorization: Bearer $DEEPSEEK_API_KEY")
echo "HTTP: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "OK. Modelos disponibles:"
    python -c "import json; d=json.load(open('/tmp/ds_models.json')); [print('  -', m['id']) for m in d.get('data',[])][:10]" \
        2>/dev/null || cat /tmp/ds_models.json | head -30
else
    echo "FAIL. Body (sin tu key):"
    cat /tmp/ds_models.json
    rm -f /tmp/ds_models.json
    exit 1
fi
rm -f /tmp/ds_models.json
echo ""

echo "=== Test 2: inferencia minima (~\$0.0001) ==="
HTTP_CODE=$(curl -sS -o /tmp/ds_chat.json -w "%{http_code}" \
    https://api.deepseek.com/v1/chat/completions \
    -H "Authorization: Bearer $DEEPSEEK_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"model":"deepseek-chat","messages":[{"role":"user","content":"reply with just OK"}],"max_tokens":5}')
echo "HTTP: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "OK. Response:"
    python -c "
import json
d = json.load(open('/tmp/ds_chat.json'))
msg = d['choices'][0]['message']
usage = d.get('usage', {})
print(f\"  content: {msg.get('content','')!r}\")
print(f\"  finish_reason: {d['choices'][0].get('finish_reason')}\")
print(f\"  usage: prompt={usage.get('prompt_tokens',0)}, completion={usage.get('completion_tokens',0)}, total={usage.get('total_tokens',0)}\")
print(f\"  cache_hit_tokens: {usage.get('prompt_cache_hit_tokens', 'n/a')}\")
print(f\"  cache_miss_tokens: {usage.get('prompt_cache_miss_tokens', 'n/a')}\")
" 2>/dev/null || cat /tmp/ds_chat.json
else
    echo "FAIL. Body:"
    cat /tmp/ds_chat.json
    rm -f /tmp/ds_chat.json
    exit 1
fi
rm -f /tmp/ds_chat.json
echo ""
echo "=== Tests 1+2 PASS — avanzamos al smoke de Kryon ==="
