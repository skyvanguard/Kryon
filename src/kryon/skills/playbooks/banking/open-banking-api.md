---
name: open-banking-api
description: "Auditoría APIs Open Banking — OAuth 2.0, mTLS, FAPI, PSD2, JWS/JWE"
triggers:
  tech: []
  keywords: ["open banking", "psd2", "fapi", "mtls", "oauth banking", "openid connect bank", "api banking regulado"]
priority: 17
required_tools:
  - run_command
  - nuclei_scan
---

## Open Banking / PSD2 API Security

Auditoría de APIs Open Banking. Stack típico: **OAuth 2.0 + OpenID Connect + FAPI + mTLS**.

### Estándares relevantes

- **FAPI 1.0 Baseline** (Financial-grade API Security Profile)
- **FAPI 1.0 Advanced** (con JARM, PAR, mTLS OB)
- **FAPI 2.0 Security Profile**
- **PSD2 RTS on SCA and CSC** (EU)
- **Open Banking UK v3.1.x**
- **STET (France) / Berlin Group (NextGen PSD2)**
- **BCP (PY) Open Finance** (cuando se regule)

### Fase 1: Discovery de endpoints

```bash
# Well-known endpoint OpenID Connect
curl -s https://bank.com.py/.well-known/openid-configuration | jq

# Debe retornar:
# - authorization_endpoint
# - token_endpoint
# - userinfo_endpoint
# - registration_endpoint (dynamic client registration)
# - jwks_uri
# - introspection_endpoint
# - revocation_endpoint

# FAPI-specific endpoints
curl -s https://bank.com.py/.well-known/oauth-authorization-server | jq
# Debe tener pushed_authorization_request_endpoint (PAR)
```

### Fase 2: mTLS client authentication (FAPI requirement)

```bash
# Generar cert de cliente para testing
openssl req -x509 -newkey rsa:2048 -keyout client.key -out client.crt -days 365 -nodes

# Token endpoint debe requerir mTLS
curl -X POST https://bank/oauth/token \
  --cert client.crt --key client.key \
  -d "grant_type=authorization_code&code=XXX&client_id=YYY"
# Sin mTLS debe fallar
```

### Fase 3: JWT assertions y signing

FAPI requiere `private_key_jwt` o `tls_client_auth`.

```bash
# Client authentication via JWT assertion
# El cliente firma un JWT con su clave privada

# Test:
# 1. JWT expirado (exp < now)
# 2. JWT con algoritmo débil (HS256, none)
# 3. JWT con alg=none
# 4. JWT firmado con clave ajena
# Todos deben ser rechazados

# FAPI Advanced requires PS256 or ES256 (no RS256)
```

### Fase 4: PKCE + PAR (Pushed Authorization Requests)

```bash
# PAR — el cliente empuja la autorización antes de redirigir al user
curl -X POST https://bank/oauth/par \
  --cert client.crt --key client.key \
  -d "response_type=code&client_id=YYY&redirect_uri=https://client/cb&state=XXX&code_challenge=ZZZ&code_challenge_method=S256&scope=accounts"

# Returns: request_uri (use in authorization)

# Test bypass:
# Enviar authorization directamente sin PAR (si se permite → viola FAPI)
```

### Fase 5: Consent management

```bash
# Open Banking: el user debe dar consent explícito
# Accounts consent: qué cuentas, qué datos, por cuánto tiempo

# Tests:
# 1. Crear consent
curl -X POST https://bank/consents -d '{"accounts": ["ACC_1", "ACC_2"], "expiration": "2027-01-01"}'
# Returns: consent_id

# 2. Token con consent_id → debe permitir solo ACC_1, ACC_2
# 3. Intentar acceder a ACC_3 → debe ser 403

# 4. Consent expirado → debe rechazar
# 5. User revoca consent → token debe ser invalidado
```

### Fase 6: Specific attacks

**1. JWT algorithm confusion**
```bash
# RS256 → HS256 attack
# Algunos servidores aceptan un JWT firmado con HS256 usando la public key como secret
python3 -c "
import jwt
with open('server_public_key.pem') as f:
    pub = f.read()
tok = jwt.encode({'sub': 'victim'}, pub, algorithm='HS256')
print(tok)
"
```

**2. JWK spoofing**
```bash
# Incluir un JWK en el header del JWT y firmar con esa clave
# Si el server trusts el JWK header sin verificar contra JWKS → bypass
```

**3. PKCE downgrade**
```bash
# Empezar con PKCE, intercambiar code sin code_verifier
# Si server acepta → PKCE no está enforced
```

**4. Redirect URI manipulation**
```bash
# Intentar con redirect_uri distinto al registrado
curl "https://bank/oauth/authorize?client_id=X&redirect_uri=https://attacker.com&response_type=code"
# Debe ser rechazado
```

**5. Authorization code reuse**
```bash
# Usar el mismo code 2 veces
curl -X POST https://bank/token -d "grant_type=authorization_code&code=ABC"
# Segunda vez
curl -X POST https://bank/token -d "grant_type=authorization_code&code=ABC"
# Segunda debe rechazarse + invalidar cualquier token emitido con ese code
```

**6. Scope elevation**
```bash
# Token con scope "accounts:read"
# Intentar endpoint que requiere "accounts:write"
curl -X POST https://bank/api/v1/transfer -H "Authorization: Bearer LIMITED_TOKEN"
# Debe ser 403
```

### Fase 7: Signed responses (JARM)

FAPI Advanced requires signed authorization responses.

```bash
# Authorization response debe ser un JWT firmado
# En lugar de: ?code=ABC&state=XYZ
# Debe ser: ?response=eyJhbGc...

# Test: ¿el server soporta JARM? ¿Firma correctamente?
```

### Findings críticos

- Token endpoint sin mTLS → CRÍTICO
- JWT `alg=none` aceptado → CRÍTICO
- PKCE no enforced → CRÍTICO
- Code reuse no bloqueado → CRÍTICO
- Redirect URI no validado estrictamente → CRÍTICO
- Consent sin expiración → ALTO
- Scopes no enforcement granular → ALTO
- Sin rate limiting en token endpoint → ALTO

### Compliance mapping

- **FAPI 1.0 Advanced §5.2.2** — mTLS o private_key_jwt
- **FAPI 1.0 Advanced §5.2.3** — RS256 prohibido, usar PS256/ES256
- **PSD2 RTS Art. 4** — Dynamic linking (transaction binding)
- **OAuth 2.1 (draft)** — PKCE obligatorio para todos los flows
- **OWASP API Security Top 10** — API2 (Broken Auth), API8 (Security Misconfig)
