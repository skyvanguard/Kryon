# Probe :10000 + :80 en .106 — banner grab + verificar que sigan UP
foreach ($port in @(80, 10000)) {
    Write-Output "=== port $port ==="
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $task = $tcp.ConnectAsync('172.18.201.106', $port)
        $ok = $task.Wait(3000)
        if ($ok -and $tcp.Connected) {
            Write-Output "  TCP: CONNECTED"
            $stream = $tcp.GetStream()
            $stream.WriteTimeout = 2000
            $stream.ReadTimeout = 3000
            $req = "GET / HTTP/1.1`r`nHost: 172.18.201.106`r`nUser-Agent: kryon-probe`r`nConnection: close`r`n`r`n"
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($req)
            try {
                $stream.Write($bytes, 0, $bytes.Length)
                $buf = New-Object byte[] 2048
                $read = $stream.Read($buf, 0, $buf.Length)
                if ($read -gt 0) {
                    $resp = [System.Text.Encoding]::ASCII.GetString($buf, 0, [Math]::Min($read, 600))
                    Write-Output "  Response (first 600 chars):"
                    Write-Output $resp
                } else {
                    Write-Output "  Empty response"
                }
            } catch {
                Write-Output "  Send/read error"
            }
        } else {
            Write-Output "  TCP: not connected (filtered/timeout)"
        }
    } catch {
        Write-Output "  Error"
    } finally {
        try { $tcp.Close() } catch {}
    }
    Write-Output ""
}
