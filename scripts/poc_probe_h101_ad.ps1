# Confirmar si .101 tiene LDAP/Kerberos (es DC real?)
$ports = @(88, 389, 636, 3268)
foreach ($port in $ports) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $task = $tcp.ConnectAsync('172.18.201.101', $port)
        $ok = $task.Wait(2000)
        if ($ok -and $tcp.Connected) {
            Write-Output "$port`: OPEN"
        } else {
            Write-Output "$port`: closed/filtered"
        }
    } catch {
        Write-Output "$port`: error"
    } finally {
        $tcp.Close()
    }
}
