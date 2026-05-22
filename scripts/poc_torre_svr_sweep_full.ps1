# Ping sweep TORRE_SVR 172.18.201.0/24 — encontrar hosts no auditados aun.
$ips_up = @()
$candidates = 1..254 | ForEach-Object { "172.18.201.$_" }

Write-Output "=== Ping sweep TORRE_SVR /24 ==="
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

# Hosts ya auditados
$audited = @(
    '172.18.201.1', '172.18.201.5', '172.18.201.8', '172.18.201.11',
    '172.18.201.12', '172.18.201.13', '172.18.201.15', '172.18.201.16',
    '172.18.201.18', '172.18.201.19', '172.18.201.50', '172.18.201.99',
    '172.18.201.101', '172.18.201.103', '172.18.201.115', '172.18.201.117',
    '172.18.201.119', '172.18.201.121', '172.18.201.123', '172.18.201.150',
    '172.18.201.200', '172.18.201.205', '172.18.201.222', '172.18.201.223'
)

$pending = $ips_up | Where-Object { $audited -notcontains $_ }
Write-Output ""
Write-Output "=== Hosts UP NO auditados: $($pending.Count) ==="
Write-Output ($pending -join ', ')
