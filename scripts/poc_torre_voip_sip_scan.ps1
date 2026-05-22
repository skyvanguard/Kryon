# Scan puertos SIP/VoIP-specific cross 4 hosts UP del segmento TORRE_VOIP
# Puertos: 5060 SIP, 5061 SIPS, 5038 Asterisk Manager Interface (AMI),
# 8088 ARI, 8089 ARI-TLS, 4569 IAX2, 8000 PBX web admin alternativo
$hosts = @('172.18.202.10','172.18.202.11','172.18.202.22')
$ports = '5060,5061,5038,8088,8089,4569,8000,8443,9999'

Write-Output "=== nmap SIP/VoIP ports scan ==="
nmap -T2 --min-rate 50 --max-parallelism 10 -p $ports -sV --version-intensity 4 -Pn $hosts
