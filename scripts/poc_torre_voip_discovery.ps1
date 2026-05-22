# Discovery ligero TORRE_VOIP 172.18.202.0/24
# Ping sweep + nmap top-20 contra los hosts UP.
# Banca-safe: T2, top-20 only.

# 1. Ping sweep al rango .1-.254
$ips_up = @()
$candidates = 1..254 | ForEach-Object { "172.18.202.$_" }

Write-Output "=== Ping sweep TORRE_VOIP 172.18.202.0/24 ==="
foreach ($ip in $candidates) {
    $p = New-Object System.Net.NetworkInformation.Ping
    try {
        $r = $p.Send($ip, 400)
        if ($r.Status -eq 'Success') {
            Write-Output "$ip UP ($($r.RoundtripTime)ms)"
            $ips_up += $ip
        }
    } catch { }
}

Write-Output ""
Write-Output "=== Hosts UP encontrados: $($ips_up.Count) ==="
Write-Output ($ips_up -join ', ')

if ($ips_up.Count -eq 0) {
    Write-Output "Sin hosts UP. Verificar ruteo VPN."
    exit
}

if ($ips_up.Count -gt 20) {
    Write-Output ""
    Write-Output "(Mas de 20 hosts; corre nmap separado manual o limita el sample.)"
}

Write-Output ""
Write-Output "=== nmap top-20 ports (banca-safe T2) contra hosts UP ==="
$target = $ips_up -join ' '
nmap -T2 --min-rate 50 --max-parallelism 10 --top-ports 20 -sV --version-intensity 2 -Pn $ips_up
