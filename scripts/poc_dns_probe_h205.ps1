# Probe DNS .205 — verificar si Simple DNS Plus es legitimo o fingerprint
$ErrorActionPreference = 'SilentlyContinue'
Write-Output "=== A record query ==="
nslookup -type=A britimp.com.py 172.18.201.205 2>&1 | Out-String
Write-Output ""
Write-Output "=== version.bind CHAOS TXT ==="
nslookup -type=TXT -class=CHAOS version.bind. 172.18.201.205 2>&1 | Out-String
Write-Output ""
Write-Output "=== Microsoft DNS recursion test ==="
nslookup google.com 172.18.201.205 2>&1 | Out-String
