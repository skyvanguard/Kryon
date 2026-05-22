# Engage Kryon contra los 3 targets del vulnerable-lab Docker local.
# Validation end-to-end de los 32 features F202.* + ground-truth comparison.

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

$env:KRYON_NMAP_TIMING = 'T4'  # lab local, no banca-safe needed
$env:KRYON_RED_TEAM = 'false'
$env:KRYON_STREAM = 'false'
$env:KRYON_FORCE_TOOL_TURNS = '8'
$env:KRYON_TELEMETRY = 'false'

$out = 'C:\Users\skyva\Documents\Kryon\.kryon\bench-vulnerable-lab'
New-Item -ItemType Directory -Force -Path $out | Out-Null

$targets = @(
    @{ IP = '127.0.0.1'; Port = 8080;  Tag = 'web'; Frame = '';       NeedsDb = $false },
    @{ IP = '127.0.0.1'; Port = 2222;  Tag = 'ssh'; Frame = 'linux';  NeedsDb = $false },
    @{ IP = '127.0.0.1'; Port = 33060; Tag = 'db';  Frame = '';       NeedsDb = $true  }
)

foreach ($t in $targets) {
    Write-Output ""
    Write-Output "===================================================="
    Write-Output "=== ENGAGE $($t.Tag) @ $($t.IP):$($t.Port) ==="
    Write-Output "===================================================="

    $outDir = "$out\$($t.Tag)"
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    $args = @(
        $t.IP,
        '--dry-run-only',
        '--skip-reaudit',
        '--client', 'vulnerable-lab',
        '--out', $outDir,
        '--engagement-id', "bench-vulnerable-lab-$($t.Tag)",
        '--nmap-timeout', '300',
        '--max-turns', '10',
        '--max-cost', '0.5',
        '--ports', '22,2222,80,8080,3306,33060'
    )
    if ($t.Frame) {
        $args += @('--framework', $t.Frame)
    }
    # F202.W — pasar creds DB via env (no argv) para target-db.
    if ($t.NeedsDb) {
        $env:KRYON_DB_USER = 'app'
        $env:KRYON_DB_PASSWORD = 'changeme'
    }

    uv run kryon engage @args

    if ($t.NeedsDb) {
        Remove-Item Env:KRYON_DB_USER -ErrorAction SilentlyContinue
        Remove-Item Env:KRYON_DB_PASSWORD -ErrorAction SilentlyContinue
    }
}
