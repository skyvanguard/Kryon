# Ping sweep a los gateways de los segmentos Britimp candidatos.
# Si .1 del segmento responde, el segmento es alcanzable via VPN actual.
$segments = @(
    '172.18.201.1',   # TORRE_SVR (ya auditado)
    '172.18.202.1',   # TORRE_VOIP probable
    '172.18.203.1',   # TORRE_USR probable
    '172.18.204.1',   # TORRE extra
    '172.18.205.1',   # TORRE extra
    '172.19.201.1',   # BASE_SVR
    '172.19.202.1',   # BASE_VOIP probable
    '172.19.203.1',   # BASE_USR probable
    '172.19.204.1',   # BASE extra
    '172.19.205.1'    # BASE extra
)
foreach ($ip in $segments) {
    $p = New-Object System.Net.NetworkInformation.Ping
    try {
        $r = $p.Send($ip, 800)
        if ($r.Status -eq 'Success') {
            Write-Output "$ip UP ($($r.RoundtripTime)ms)"
        } else {
            Write-Output "$ip down ($($r.Status))"
        }
    } catch {
        Write-Output "$ip error"
    }
}
