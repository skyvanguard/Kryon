# Top-20 scan de los 6 hosts TORRE_SVR no auditados
$hosts = @('172.18.201.100','172.18.201.104','172.18.201.105','172.18.201.106','172.18.201.110','172.18.201.120')
Write-Output "=== nmap top-20 (banca-safe T2) ==="
nmap -T2 --min-rate 50 --max-parallelism 10 --top-ports 20 -sV --version-intensity 2 -Pn $hosts
