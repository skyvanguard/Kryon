# Ping sweep de hosts TORRE_SVR aun no auditados.
$ips = @(
    '172.18.201.12','172.18.201.15','172.18.201.16','172.18.201.19',
    '172.18.201.101','172.18.201.103','172.18.201.119','172.18.201.121',
    '172.18.201.205'
)
foreach ($ip in $ips) {
    $p = New-Object System.Net.NetworkInformation.Ping
    try {
        $r = $p.Send($ip, 800)
        if ($r.Status -eq 'Success') {
            Write-Output "$ip UP $($r.RoundtripTime)ms"
        } else {
            Write-Output "$ip down ($($r.Status))"
        }
    } catch {
        Write-Output "$ip error"
    }
}
