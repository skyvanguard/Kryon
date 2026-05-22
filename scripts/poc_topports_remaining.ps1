# Top-20 port scan a los 9 hosts TORRE_SVR no auditados.
# Banca-safe: T2, --min-rate 50, top-20 only.
$ips = @(
    '172.18.201.12','172.18.201.15','172.18.201.16','172.18.201.19',
    '172.18.201.101','172.18.201.103','172.18.201.119','172.18.201.121',
    '172.18.201.205'
)
$targets = $ips -join ' '
Write-Output "=== nmap top-20 puertos (banca-safe T2) ==="
nmap -T2 --min-rate 50 --max-parallelism 10 --top-ports 20 -sV --version-intensity 2 -Pn $ips
