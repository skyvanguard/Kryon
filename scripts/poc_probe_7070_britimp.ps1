# Probe :7070 cross-host para identificar qué corre
$hosts = @('172.18.201.5','172.18.201.12','172.18.201.15','172.18.201.19','172.18.201.101')
foreach ($h in $hosts) {
    Write-Output "=== $h :7070 ==="
    Write-Output "--- HTTP probe ---"
    try {
        $r = Invoke-WebRequest -Uri "http://${h}:7070/" -TimeoutSec 4 -UseBasicParsing -ErrorAction Stop
        Write-Output "Status: $($r.StatusCode)"
        Write-Output "Server header: $($r.Headers['Server'])"
        Write-Output "Content-Type: $($r.Headers['Content-Type'])"
        Write-Output "Body (first 400 chars):"
        Write-Output ($r.Content.Substring(0, [Math]::Min(400, $r.Content.Length)))
    } catch {
        Write-Output "HTTP failed: $($_.Exception.Message.Substring(0, [Math]::Min(120, $_.Exception.Message.Length)))"
    }
    Write-Output "--- HTTPS probe ---"
    try {
        $r2 = Invoke-WebRequest -Uri "https://${h}:7070/" -TimeoutSec 4 -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
        Write-Output "Status: $($r2.StatusCode)"
        Write-Output "Server header: $($r2.Headers['Server'])"
        Write-Output "Body (first 400 chars):"
        Write-Output ($r2.Content.Substring(0, [Math]::Min(400, $r2.Content.Length)))
    } catch {
        Write-Output "HTTPS failed: $($_.Exception.Message.Substring(0, [Math]::Min(120, $_.Exception.Message.Length)))"
    }
    Write-Output ""
}
