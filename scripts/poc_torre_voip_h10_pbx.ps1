# POC en vivo: kryon engage contra 172.18.202.10 (PBX Asterisk Britimp)
# Valida F198 voip-asterisk-audit en produccion por primera vez.
# Banca-safe throttle activo, dry-run-only.

$env:OPENAI_API_KEY = 'ollama'
$env:OPENAI_BASE_URL = 'http://localhost:11435/v1'
$env:OLLAMA = 'true'
$env:KRYON_MODEL = 'kryon-gpt-oss'
$env:KRYON_TRIAGE_MODEL = 'kryon-gpt-oss'
$env:KRYON_RAG_MODEL = 'kryon-gpt-oss'
$env:KRYON_GUARDRAIL_MODEL = 'kryon-gpt-oss'
$env:KRYON_COMPLIANCE_NARRATOR_MODEL = 'kryon-gpt-oss'
$env:KRYON_EMBEDDING_MODEL = 'nomic-embed-text'
$env:KRYON_EMBEDDING_BASE_URL = 'http://localhost:11435'

$env:KRYON_NMAP_TIMING = 'T2'
$env:KRYON_NMAP_MIN_RATE = '50'
$env:KRYON_NMAP_MAX_PARALLELISM = '10'
$env:KRYON_NUCLEI_RATE_LIMIT = '50'
$env:KRYON_NUCLEI_BULK_SIZE = '10'
$env:KRYON_NUCLEI_CONCURRENCY = '10'

$env:KRYON_RED_TEAM = 'false'
$env:KRYON_STREAM = 'false'
$env:KRYON_FORCE_TOOL_TURNS = '8'
$env:KRYON_TELEMETRY = 'false'

$out = 'C:\Users\skyva\Documents\Kryon\.kryon\poc-britimp-torre-voip\h10'
New-Item -ItemType Directory -Force -Path $out | Out-Null

Write-Output "=== kryon engage 172.18.202.10 (Asterisk PBX TORRE_VOIP, banca-safe) ==="
Write-Output ""

uv run kryon engage 172.18.202.10 --dry-run-only --skip-reaudit --client britimp-internal --out $out --engagement-id britimp-torre-voip-h10-poc --framework asterisk --nmap-timeout 1110 --max-turns 10 --max-cost 0.5
