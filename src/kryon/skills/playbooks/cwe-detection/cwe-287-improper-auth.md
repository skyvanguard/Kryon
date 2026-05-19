---
name: cwe-287-improper-auth
description: "Detección y clasificación de CWE-287 Improper Authentication (bypass, weak credentials, broken session). Discrimina vs CWE-306 (missing auth), CWE-521 (weak password), CWE-307 (excessive auth attempts), CWE-862 (missing authorization)."
triggers:
  tech: []
  ports: []
  file_extensions: [".java", ".py", ".cs", ".rb", ".php", ".go", ".js", ".ts", ".kt", ".scala"]
  keywords:
    - "improper authentication"
    - "authentication bypass"
    - "auth bypass"
    - "broken auth"
    - "broken authentication"
    - "session fixation"
    - "jwt"
    - "jwt verify"
    - "verify_signature"
    - "alg none"
    - "hardcoded credential"
    - "default credential"
    - "weak password"
    - "credential stuffing"
priority: 18
required_tools:
  - run_command
---

# CWE-287 — Improper Authentication (clasificación SAST)

Se activa cuando el agente audita lógica de autenticación,
verificación de tokens/sesiones, o gestión de credenciales. **NO
confundir CWE-287 con CWE-306 (missing auth — completamente ausente),
CWE-862 (missing authorization — IDOR-style), CWE-521 (weak password
policy)**.

## Discriminación CWE-287 vs hermanas

| CWE | Significado | Cuándo usar |
|---|---|---|
| **CWE-287** | **Improper Authentication** | Auth existe pero se valida mal (JWT alg=none, password comparison time-based, session fixation) |
| CWE-306 | Missing Authentication | NO hay auth en endpoint sensitive — completamente ausente |
| CWE-521 | Weak Password Requirements | Política de contraseñas débil (no enforcement) |
| CWE-307 | Improper Restriction of Excessive Auth Attempts | Sin rate-limit en login (credential stuffing) |
| CWE-862 | Missing Authorization | Auth OK pero no authorization (IDOR/BOLA) |
| CWE-798 | Use of Hardcoded Credentials | Password/key hardcoded en código |
| CWE-384 | Session Fixation | Session ID no regenerado tras login |

**Regla práctica**: si el bug es en **cómo** se valida la credencial/token/sesión → **CWE-287**. Si es **ausencia total** de auth → CWE-306. Si es ausencia de authz post-auth → CWE-862.

## Sink patterns CWE-287 por categoría

### JWT misuse
```python
# CWE-287: alg=none accepted
import jwt
payload = jwt.decode(token, key=None, options={"verify_signature": False})

# CWE-287: weak secret
jwt.decode(token, "secret123", algorithms=["HS256"])

# CWE-287: algorithm confusion (RS256 → HS256 with pubkey)
jwt.decode(token, public_key_pem, algorithms=["HS256", "RS256"])

# Safe:
jwt.decode(token, key=expected_key, algorithms=["RS256"])
```

### Password comparison (timing attacks)
```python
# CWE-287 (timing leak)
if user.password == request.password:  # variable-time comparison
    grant_session()

# Safe (constant-time):
import secrets
if secrets.compare_digest(user.password, request.password):
    grant_session()
```

### Session management
```python
# CWE-384 (subset of CWE-287): session ID not regenerated
def login(request):
    if authenticate(...):
        # session ID stays same — fixation vector

# Safe: regenerate ID after auth
def login(request):
    if authenticate(...):
        request.session.cycle_key()
```

### Weak credential storage
```python
# CWE-287 (combined with CWE-916 weak hash)
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()  # weak

# Safe:
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

### OAuth / OpenID Connect
```python
# CWE-287: id_token without signature check
token_data = parse_id_token(id_token)  # no verify

# CWE-287: state parameter not validated (CSRF on OAuth)
def callback(request):
    code = request.GET['code']
    # no state check
```

### Bypass via header injection
```java
// CWE-287 if app trusts X-Forwarded-User
String user = request.getHeader("X-Forwarded-User");  // attacker can set
```

## Familias de bugs CWE-287 (sin spoilers)

- **JWT alg=none / weak secret / alg confusion**: classic JWT bugs.
- **Hardcoded credentials**: `password = "admin123"` en config/source.
- **Default credentials**: app ships with `admin:admin` y no fuerza change.
- **Session fixation**: ID no se regenera post-login.
- **Variable-time password compare**: `==` en vez de `compare_digest`.
- **Weak crypto**: MD5/SHA1 para password hashing (también CWE-916).
- **Trust HTTP headers**: `X-Forwarded-User` accepted sin proxy validation.
- **Bearer token in URL**: `?token=...` GET-style (loggeable).

## Metodología de detección

```bash
# JWT misuse
run_command grep -rn "verify_signature.*False\|alg.*none\|jwt\.decode" {source_path}
run_command grep -rn "algorithms=\\[" {source_path}

# Hardcoded credentials
run_command grep -rEn "password\\s*=\\s*['\"][a-zA-Z0-9!@#$%^&*]{4,}['\"]" {source_path}
run_command grep -rEn "secret\\s*=\\s*['\"]" {source_path}
run_command grep -rn "api_key.*=.*['\"]" {source_path}

# Weak hash
run_command grep -rn "hashlib\\.md5\\|hashlib\\.sha1\\|MD5\\.new\\|MessageDigest\\.getInstance.*MD5" {source_path}

# Timing-unsafe password compare
run_command grep -rn "password\\s*==\\s*\\|getPassword\\(\\).*equals\\(" {source_path}

# Header trust
run_command grep -rn "X-Forwarded-User\\|X-User-Id\\|X-Remote-User" {source_path}
```

Para cada match, verificá:
1. JWT: ¿hay `verify_signature=True`? ¿algorithms whitelist explícito?
2. Password: ¿se usa bcrypt/argon2/scrypt para hashing?
3. Password compare: ¿constant-time function (`compare_digest`, `Arrays.equals`, `MessageDigest.isEqual`)?
4. Session: ¿regenera ID en login? ¿invalida en logout?
5. Headers: ¿valida que el upstream proxy realmente seteó el header (TLS auth)?

## Formato de finding obligatorio

```
CWE-287 en <archivo>:<linea>
```

**NUNCA CWE-306 ni CWE-862** cuando hay lógica de auth presente pero
errónea. CWE-306 = ausencia total. CWE-862 = authorization post-auth.

## Banca-safe

100% read-only. NO intenta auth bypass real (credential stuffing,
JWT alg=none brute), NO usa credenciales hardcoded encontradas.

**Critical en banking**: missing auth o JWT bypass en endpoints de
cuenta = compromiso total. Siempre HIGH/CRITICAL severity.
