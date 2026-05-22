# Validar manualmente DNSSEC validation en .5 vs .205
Write-Output "=== .5 dnssec-failed.org ==="
nslookup dnssec-failed.org 172.18.201.5 2>&1 | Out-String
Write-Output ""
Write-Output "=== .205 dnssec-failed.org (control) ==="
nslookup dnssec-failed.org 172.18.201.205 2>&1 | Out-String
