# Discovery TORRE_USR 172.18.203.0/24 — ping sweep + nmap top-20 sobre hosts UP.
# Banca-safe: T2, top-20 only.
$ips_up = @()
$candidates = 1..254 | ForEach-Object { "172.18.203.$_" }

Write-Output "=== Ping sweep TORRE_USR 172.18.203.0/24 ==="
foreach ($ip in $candidates) {
    $p = New-Object System.Net.NetworkInformation.Ping
    try {
        $r = $p.Send($ip, 300)
        if ($r.Status -eq 'Success') {
            $ips_up += $ip
        }
    } catch { }
}

Write-Output ""
Write-Output "=== Hosts UP: $($ips_up.Count) ==="
Write-Output ($ips_up -join ', ')

if ($ips_up.Count -eq 0) {
    Write-Output "Sin hosts UP. Verificar ruteo VPN."
    exit
}

if ($ips_up.Count -gt 30) {
    Write-Output ""
    Write-Output "(Mas de 30 hosts; nmap top-20 corre sobre los primeros 30 para velocidad.)"
    $ips_scan = $ips_up[0..29]
} else {
    $ips_scan = $ips_up
}

Write-Output ""
Write-Output "=== nmap top-20 (banca-safe T2) sobre $($ips_scan.Count) hosts ==="
nmap -T2 --min-rate 50 --max-parallelism 10 --top-ports 20 -sV --version-intensity 2 -Pn $ips_scan
