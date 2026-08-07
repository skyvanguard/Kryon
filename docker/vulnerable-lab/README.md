# Vulnerable lab for Kryon demo

Three containers with planted, well-known misconfigurations. Used to
validate the example demo flow end-to-end without any real
infrastructure.

## Planted vulnerabilities

| Target | Port (host) | CWE(s) | Expected scanner hits |
|---|---|---|---|
| `target-ssh` | 127.0.0.1:2222 | CWE-521, CWE-287, CWE-250, CWE-307 | PermitRootLogin yes, PasswordAuth yes, X11Forwarding yes, MaxAuthTries 10 |
| `target-web` | 127.0.0.1:8080 | CWE-319, CWE-1004, CWE-306, CWE-200 | HTTP-only, missing HttpOnly cookie, /admin without auth, server tokens exposed |
| `target-db` | 127.0.0.1:33060 | CWE-319, CWE-521 | MySQL without require_secure_transport, bind 0.0.0.0, weak password |

## Bring up

```bash
docker compose -f docker/vulnerable-lab/docker-compose.yml up -d --build
docker compose -f docker/vulnerable-lab/docker-compose.yml ps
```

## Access (from host)

```bash
# SSH (password: demo-only-password, user: admin)
ssh -p 2222 admin@127.0.0.1

# Web
curl http://127.0.0.1:8080/
curl http://127.0.0.1:8080/admin    # intentionally open

# MySQL (user: app, password: changeme)
mysql -h 127.0.0.1 -P 33060 -u app -pchangeme vuln_staging
```

## Access from a Kryon container on the host

Add `--network kryon-lab` to the Kryon container, then targets are
reachable by hostname: `target-ssh`, `target-web`, `target-db`.

## Safety disclaimer

These images embed **plaintext credentials** and intentionally vulnerable
configurations in their layers. The Dockerfiles are labelled
`kryon.demo=true` and the network is a dedicated bridge. Do not deploy
anywhere other than a local dev host and an isolated network.

## Tear down

```bash
docker compose -f docker/vulnerable-lab/docker-compose.yml down
```
