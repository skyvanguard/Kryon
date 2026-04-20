# F26 — Reproducible vulnerable lab for Kryon

Tres containers que simulan una infraestructura bancaria mínima con
misconfiguraciones intencionales para validar end-to-end el pipeline
de auditoría Kryon:

| Container | Rol | Findings esperados |
|---|---|---|
| `pve_fake` | Fake Proxmox VE 7.2 node | 6 FAIL + 1 PASS (los 7 checks F23 / PVE-x.x) |
| `juice_shop` | OWASP Juice Shop | webexploit probes (F17/F18) + demo OWASP Top 10 |

## Requisitos previos

- Docker Desktop funcionando
- Red `ctfnet` existe (se crea automáticamente por `setup.sh`)
- Kryon + ollama ya levantados:
  ```
  docker compose -f docker/docker-compose.kali.yml \
                 -f docker/docker-compose.override.yml up -d
  ```

## Bootstrap (una sola vez)

```bash
cd demo && bash setup.sh
```

Hace:
1. Crea red `ctfnet` si no existe.
2. Genera `demo/.ssh/demo_key` (ed25519).
3. Build del `pve_fake` Dockerfile.
4. Levanta los 2 containers.
5. Imprime comandos listos para correr.

## Validación manual (opcional)

Desde el host:

```bash
# SSH al fake Proxmox
ssh -i demo/.ssh/demo_key auditor@127.0.0.1 -p 2222 hostname

# Web UI 8006 (self-signed)
curl -sk https://127.0.0.1:8006/api2/json/version

# Juice Shop
curl -s http://127.0.0.1:3003/ -o /dev/null -w '%{http_code}\n'
```

## Correr audit Kryon end-to-end

El kryon container debe estar en la red `ctfnet` para resolver
`pve_fake` como hostname. Primera vez:

```bash
docker network connect ctfnet kryon
```

Key-file con perms correctas dentro de kryon (bind mount `~/.ssh` en
Docker Desktop Windows queda con 777, SSH lo rechaza):

```bash
docker exec -u 0 kryon bash -c '
    install -d -m 700 -o kryon /home/kryon/kryon_keys
    cp /home/kryon/.ssh/demo_key /home/kryon/kryon_keys/demo_key
    chmod 600 /home/kryon/kryon_keys/demo_key
    chown kryon:kryon /home/kryon/kryon_keys/demo_key
'
```

Y ya se puede correr el audit:

```bash
MSYS_NO_PATHCONV=1 docker exec \
    -e KRYON_SSH_USER=auditor \
    -e KRYON_SSH_KEY=/home/kryon/kryon_keys/demo_key \
    -e KRYON_CLIENT_NAME="Banco Demo S.A." \
    kryon python -c '
from kryon.tools.appsec.compliance_audit import _run_compliance_pdf
print(_run_compliance_pdf(host="pve_fake", framework="proxmox",
                          ssh_user="auditor",
                          ssh_key_path="/home/kryon/kryon_keys/demo_key",
                          client_name="Banco Demo S.A."))
'
```

Output esperado: **6 FAIL + 1 PASS** en 7 checks. PDF en `../reports/`.

## Findings esperados por check

| Check | Verdict | Razón |
|---|:---:|---|
| PVE-1.1 | FAIL | Cert self-signed en /etc/pve/local/pve-ssl.pem |
| PVE-1.2 | PASS | nginx retorna 401 en /api2/json/nodes etc |
| PVE-2.1 | FAIL | PermitRootLogin yes + PasswordAuthentication yes |
| PVE-3.1 | FAIL | /etc/pve/domains.cfg sin default-tfa; 3 users sin TFA |
| PVE-3.2 | FAIL | token.cfg 644; 2 tokens sin expiry bound a root |
| PVE-4.1 | FAIL | pve-firewall reports disabled; cluster.fw enable=0 |
| PVE-5.1 | FAIL | pveversion 7.2 (EOL); 42 pending apt upgrades |

## Tear down

```bash
cd demo && docker compose -f docker-compose.demo.yml down -v
```
