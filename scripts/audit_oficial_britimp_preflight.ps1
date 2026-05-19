# Audit Oficial Britimp - Pre-Flight Check
#
# Verifica TODOS los prerequisites antes de correr el audit Kryon completo.
# Output: PASS / FAIL / PENDING por cada item.
#
# Uso:
#   powershell -ExecutionPolicy Bypass -File C:/Users/skyva/Documents/Kryon/scripts/audit_oficial_britimp_preflight.ps1
#
# Para fix de items FAIL, ver el README adjunto:
#   scripts/audit_oficial_britimp_README.md

$ErrorActionPreference = 'SilentlyContinue'
$total = 0
$pass = 0
$fail = 0
$pending = 0

function Report-Item {
    param([string]$Category, [string]$Name, [string]$Status, [string]$Detail = "")
    $script:total++
    $color = switch ($Status) {
        "PASS"    { $script:pass++; "Green" }
        "FAIL"    { $script:fail++; "Red" }
        "PENDING" { $script:pending++; "Yellow" }
        default   { "White" }
    }
    $statusPad = $Status.PadRight(8)
    Write-Host "  [$statusPad] $Category :: $Name" -ForegroundColor $color
    if ($Detail) { Write-Host "             $Detail" -ForegroundColor DarkGray }
}

function Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "=== $Title ===" -ForegroundColor Cyan
}

# ============================================================
# 1. KRYON TOOLING AVAILABILITY
# ============================================================
Section "1. Tooling Kryon"

# uv binary
$uv = (Get-Command uv -ErrorAction SilentlyContinue)
if ($uv) {
    Report-Item -Category "uv" -Name "Python package manager" -Status "PASS"
} else {
    Report-Item -Category "uv" -Name "Python package manager" -Status "FAIL" -Detail "Install: https://docs.astral.sh/uv/"
}

# kryon CLI
$kryon = (Get-Command kryon -ErrorAction SilentlyContinue)
if ($kryon) {
    Report-Item -Category "kryon" -Name "CLI entry point" -Status "PASS"
} else {
    Report-Item -Category "kryon" -Name "CLI entry point" -Status "FAIL" -Detail "Run: uv sync --all-extras"
}

# nmap
$nmap = (Get-Command nmap -ErrorAction SilentlyContinue)
if ($nmap) {
    $ver = (& nmap --version 2>&1 | Select-Object -First 1)
    Report-Item -Category "nmap" -Name "Service discovery" -Status "PASS" -Detail $ver
} else {
    Report-Item -Category "nmap" -Name "Service discovery" -Status "FAIL" -Detail "Install: choco install nmap"
}

# Ollama (local model)
try {
    $ol = Invoke-WebRequest -Uri "http://localhost:11435/api/tags" -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
    Report-Item -Category "ollama" -Name "Local model API" -Status "PASS"
} catch {
    Report-Item -Category "ollama" -Name "Local model API" -Status "FAIL" -Detail "docker compose up kryon-ollama; kryon-gpt-oss model required"
}

# dig (necesario para F202.D)
$dig = (Get-Command dig -ErrorAction SilentlyContinue)
if ($dig) {
    Report-Item -Category "dig" -Name "DNS resolver (F202.D cache snoop)" -Status "PASS"
} else {
    Report-Item -Category "dig" -Name "DNS resolver (F202.D cache snoop)" -Status "PENDING" -Detail "Optional: docker exec si no esta en host"
}

# smbclient (necesario para F202.Q)
$smb = (Get-Command smbclient -ErrorAction SilentlyContinue)
if ($smb) {
    Report-Item -Category "smbclient" -Name "SMB anonymous enum (F202.Q)" -Status "PASS"
} else {
    Report-Item -Category "smbclient" -Name "SMB anonymous enum (F202.Q)" -Status "PENDING" -Detail "Optional: docker exec si no esta en host"
}

# ============================================================
# 2. NETWORK CONNECTIVITY - Segments Britimp
# ============================================================
Section "2. Conectividad a segmentos Britimp"

$segments = @{
    "TORRE_SVR (.201)"        = "172.18.201.1"
    "TORRE_VOIP (.202)"       = "172.18.202.1"
    "TORRE_USR/CCTV (.203)"   = "172.18.203.1"
    "TORRE_EXTRA (.204)"      = "172.18.204.1"
    "BASE seg .203 (CCTV)"    = "172.19.203.1"
    "BASE seg .202"           = "172.19.202.1"
    "Mgmt VLAN 200 (.200)"    = "172.18.200.1"
}

foreach ($name in $segments.Keys) {
    $ip = $segments[$name]
    $ping = (New-Object System.Net.NetworkInformation.Ping).Send($ip, 1500)
    if ($ping.Status -eq 'Success') {
        Report-Item -Category "Network" -Name "$name gateway" -Status "PASS" -Detail "$ip $($ping.RoundtripTime)ms"
    } else {
        Report-Item -Category "Network" -Name "$name gateway" -Status "FAIL" -Detail "$ip $($ping.Status) - solicitar routeo VPN o jump host"
    }
}

# ============================================================
# 3. SSH KEY ACCESS - Hosts con la key del jumphost
# ============================================================
Section "3. SSH key (id_ed25519) access verification"

$keyPath = "$HOME/.ssh/id_ed25519"
if (-not (Test-Path $keyPath)) {
    Report-Item -Category "SSH key" -Name "id_ed25519 present" -Status "FAIL" -Detail "Falta key SSH del jumphost"
} else {
    Report-Item -Category "SSH key" -Name "id_ed25519 present" -Status "PASS"

    $sshHosts = @{
        "jump (.115 Proxmox primary)"       = "root@172.18.201.115"
        ".222 Proxmox pve-torre-prod"       = "root@172.18.201.222"
        ".200 Proxmox pve-britimp (8.4)"    = "root@172.18.201.200"
        ".18 Odoo Enterprise"               = "root@172.18.201.18"
        ".121 Odoo Community"               = "root@172.18.201.121"
        ".110 Reporting-itau"               = "ubuntu@172.18.201.110"
        ".119 dashboards-hub"               = "ubuntu@172.18.201.119"
    }

    foreach ($name in $sshHosts.Keys) {
        $target = $sshHosts[$name]
        $r = (ssh -o ConnectTimeout=6 -o BatchMode=yes -o StrictHostKeyChecking=no -i $keyPath $target "echo OK" 2>&1)
        if ($r -match "OK") {
            Report-Item -Category "SSH (key)" -Name $name -Status "PASS"
        } else {
            Report-Item -Category "SSH (key)" -Name $name -Status "FAIL" -Detail $target
        }
    }
}

# ============================================================
# 4. HOSTS PENDIENTES (key segmentada o sin creds)
# ============================================================
Section "4. Hosts con creds segmentadas (pendiente obtener)"

$pendingSsh = @{
    ".99 britimp-llavero (vault)"            = "root@172.18.201.99"
    ".117 CentOS 7 legacy"                   = "root@172.18.201.117"
    ".150 PostgreSQL 9.6 EOL"                = "root@172.18.201.150"
    ".123 DB"                                = "root@172.18.201.123"
}

foreach ($name in $pendingSsh.Keys) {
    $target = $pendingSsh[$name]
    $r = (ssh -o ConnectTimeout=6 -o BatchMode=yes -o StrictHostKeyChecking=no -o ProxyCommand=none -i $keyPath $target "echo OK" 2>&1)
    if ($r -match "OK") {
        Report-Item -Category "SSH (segm)" -Name $name -Status "PASS" -Detail "ya tiene key"
    } elseif ($r -match "Permission denied") {
        Report-Item -Category "SSH (segm)" -Name $name -Status "PENDING" -Detail "Solicitar credenciales del host (key separada o password+MFA)"
    } else {
        Report-Item -Category "SSH (segm)" -Name $name -Status "FAIL" -Detail "Host no alcanzable o SSH down"
    }
}

# ============================================================
# 5. WINDOWS HOSTS - WinRM necesario
# ============================================================
Section "5. Windows hosts (WinRM creds requeridas)"

$winHosts = @(
    @{ Name = ".5 DC secundario britimp.com.py"; IP = "172.18.201.5" },
    @{ Name = ".205 DC primario britimp.com.py"; IP = "172.18.201.205" },
    @{ Name = ".13 Windows + DBs";                IP = "172.18.201.13" },
    @{ Name = ".15 Windows + SQL Server 2019";    IP = "172.18.201.15" },
    @{ Name = ".19 Windows member + IIS";         IP = "172.18.201.19" },
    @{ Name = ".100 Windows member + RDP";        IP = "172.18.201.100" },
    @{ Name = ".101 Windows + IIS:8080";          IP = "172.18.201.101" },
    @{ Name = ".103 Windows + SQL Server";        IP = "172.18.201.103" }
)

foreach ($h in $winHosts) {
    # Check WinRM port (5985 HTTP) only - actual auth requires creds
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $ok = $tcp.ConnectAsync($h.IP, 5985).Wait(2500)
        if ($ok -and $tcp.Connected) {
            Report-Item -Category "WinRM" -Name $h.Name -Status "PENDING" -Detail "Puerto 5985 OK - falta creds dominio britimp.com.py"
        } else {
            Report-Item -Category "WinRM" -Name $h.Name -Status "FAIL" -Detail "WinRM no habilitado en el host - Enable-PSRemoting first"
        }
    } catch {
        Report-Item -Category "WinRM" -Name $h.Name -Status "FAIL" -Detail "Host no alcanzable"
    } finally {
        $tcp.Close()
    }
}

# ============================================================
# 6. NDAs / autorización scope (manual check)
# ============================================================
Section "6. NDAs / autorización (verification manual)"

Report-Item -Category "NDA" -Name "Britimp authorization scope" -Status "PENDING" -Detail "Confirmar con Osvaldo: scope formal del audit"
Report-Item -Category "NDA" -Name "Cliente Itaú (host .110)" -Status "PENDING" -Detail "Si reportes Itau estan en scope, requiere autorizacion Itau"
Report-Item -Category "NDA" -Name "Cliente Giva (.111 dashboards + .130 bases)" -Status "PENDING" -Detail "DBs Giva en scope?"
Report-Item -Category "NDA" -Name "Cliente TEISA (.200.26 RPA share)" -Status "PENDING" -Detail "RPA-TEISA share en scope?"

# ============================================================
# 7. KRYON CONFIG / PROFILE recommendation
# ============================================================
Section "7. Configuracion Kryon para audit oficial"

$kryonConfig = @(
    @{ Name = "KRYON_NMAP_TIMING"; Value = "T2"; Detail = "banca-safe en horario laboral" },
    @{ Name = "KRYON_NMAP_MIN_RATE"; Value = "50"; Detail = "limit packet rate" },
    @{ Name = "KRYON_NMAP_MAX_PARALLELISM"; Value = "10"; Detail = "" },
    @{ Name = "KRYON_RED_TEAM"; Value = "false"; Detail = "dry-run-only obligatorio" },
    @{ Name = "KRYON_MODEL"; Value = "kryon-gpt-oss"; Detail = "local model F162-F189" }
)

foreach ($cfg in $kryonConfig) {
    $env_val = (Get-Item "Env:$($cfg.Name)" -ErrorAction SilentlyContinue).Value
    if ($env_val -eq $cfg.Value) {
        Report-Item -Category "Config" -Name "$($cfg.Name) = $($cfg.Value)" -Status "PASS" -Detail $cfg.Detail
    } else {
        Report-Item -Category "Config" -Name "$($cfg.Name) = $($cfg.Value)" -Status "PENDING" -Detail "Set in profile or wrapper script (current: $env_val)"
    }
}

# ============================================================
# Summary
# ============================================================
Write-Host ""
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "RESUMEN PRE-FLIGHT - Audit Oficial Britimp" -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Total checks:     $total" -ForegroundColor White
Write-Host "  PASS:             $pass" -ForegroundColor Green
Write-Host "  FAIL:             $fail" -ForegroundColor Red
Write-Host "  PENDING:          $pending" -ForegroundColor Yellow
Write-Host ""
if ($fail -gt 0) {
    Write-Host "  STATUS: NO ESTA LISTO. Arreglar los FAIL antes del audit." -ForegroundColor Red
} elseif ($pending -gt 0) {
    Write-Host "  STATUS: BLOQUEADO POR PENDIENTES. Obtener creds + NDAs antes del audit." -ForegroundColor Yellow
} else {
    Write-Host "  STATUS: READY. El audit oficial puede correr." -ForegroundColor Green
}
Write-Host ""
Write-Host "Detalle de remediacion: scripts/audit_oficial_britimp_README.md" -ForegroundColor DarkGray
