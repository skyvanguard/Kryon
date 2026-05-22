---
name: cwe-639-idor
description: "Detección y clasificación de CWE-639 IDOR / BOLA (Insecure Direct Object Reference). Discrimina vs CWE-285 (auth bypass), CWE-862 (missing auth), CWE-863 (incorrect auth)."
triggers:
  tech: []
  ports: [80, 443, 8080, 8443, 3000, 5000, 8000]
  file_extensions: [".java", ".py", ".cs", ".rb", ".php", ".go", ".js", ".ts"]
  keywords:
    - "cwe-639"
    - "idor"
    - "insecure direct object reference"
    - "bola"
    - "broken object level authorization"
    - "object level authorization"
    - "horizontal privilege"
    - "horizontal privilege escalation"
    - "/users/"
    - "/api/v1/users"
    - "/orders/"
    - "/transactions/"
    - "user_id"
    - "account_id"
priority: 5
required_tools:
  - run_command
  - detect_bola
pre_hooks:
  # F203.U — IDOR sequential probe via Python urllib (avoids the
  # SSTI guard that rejects curl `-w '%{http_code}'` format strings).
  # Banca-safe: GET-only, rate-limited (0.2s/req), no modification.
  # Probes ~96 combos (12 paths × 8 IDs) in ~30s.
  - python: ./idor_probe_hook.py:run
    args:
      target: "{ctx.target}"
    inject_as: idor_sequential_probe
    required: false
    timeout_s: 120
---

# CWE-639 — IDOR / BOLA (Insecure Direct Object Reference)

Se activa cuando el agente audita endpoints que toman IDs en el path o
query string (`/users/123`, `/orders/456`, `?user_id=...`). **NO confundir
CWE-639 con CWE-285/862/863 (auth genéricos), CWE-352 (CSRF), ni CWE-918 (SSRF)**.

## Discriminación CWE-639 vs hermanas

| CWE | Significado | Cuándo usar |
|---|---|---|
| **CWE-639** | **IDOR/BOLA** | El user está autenticado, pero accede a objetos que NO le pertenecen cambiando IDs (`/orders/456` → `/orders/457`) |
| CWE-285 | Improper Authorization | Generic missing/incorrect authz |
| CWE-862 | Missing Authorization | Endpoint sin ningún check authz |
| CWE-863 | Incorrect Authorization | Check authz presente pero defectuoso |
| CWE-602 | Client-side enforcement of server-side security | Authz solo en frontend |
| CWE-918 | SSRF | Server fetches attacker-controlled URL |

**Regla práctica**: si el bug es "user A puede leer/modificar recurso de
user B cambiando el ID en la URL", es **CWE-639**. Si es "no hay auth
en absoluto", es CWE-862. Si la check existe pero está mal hecha (e.g.
compara roles antes de validar ownership), es CWE-863.

## Sink patterns CWE-639

### REST endpoint sin ownership check
```python
# CWE-639 — el endpoint solo valida que user esté autenticado,
# pero NO valida que el order_id pertenezca al user.
@app.get("/api/orders/{order_id}")
@require_auth
def get_order(order_id: int, user=Depends(current_user)):
    return Order.query.get(order_id)  # <-- NO chequea user.id == order.user_id
```

### GraphQL resolver sin authorization
```javascript
// CWE-639 — el resolver retorna cualquier order que matchea ID
const resolvers = {
  Query: {
    order: (parent, { id }, ctx) => {
      return db.orders.findOne({ id });  // <-- missing ownership check
    }
  }
};
```

### Direct DB query con ID controlado por user
```java
// CWE-639 — el repository solo busca por ID
@GetMapping("/account/{id}")
public Account getAccount(@PathVariable Long id) {
    return accountRepo.findById(id).orElseThrow();
    // Should be: accountRepo.findByIdAndUserId(id, currentUser.getId())
}
```

## Familias de bugs CWE-639

- **Sequential IDs**: incrementar `?id=1` → `?id=2` → `?id=3` permite
  enumerar todos los recursos.
- **UUIDs predecibles (v1)**: timestamp-based UUIDs pueden enumerarse
  con suficiente tracking.
- **Hash IDs débiles**: MD5(user_id) o base64(id) son reversibles.
- **Document download by filename**: `/download?file=report-123.pdf` sin
  validar ownership.
- **Profile picture URL leak**: `/avatars/user_456.jpg` accesible sin auth.

## Metodología de detección DAST

```bash
# 1. Crear 2 usuarios (A y B) en el target. Tomar sus session cookies.
# 2. Enumerar recursos de user A (login como A, listar /orders).
# 3. Intentar acceder a esos recursos con cookie de B:
curl -s -H "Cookie: SESSION=B" {target}/orders/A_OBJECT_ID

# 4. Si la respuesta es 200 con datos de A → CWE-639 confirmado.
#    Si es 403/404 → endpoint protegido correctamente.
```

## Formato de finding obligatorio

```
CWE-639 en <endpoint> via <param>
```

**NUNCA CWE-285 ni CWE-862** cuando el bug es específicamente "ownership
check missing en endpoint autenticado". CWE-639 es el hijo específico.

## Banca-safe

100% read-only via GET. NO modifica recursos ajenos (no POST/PUT/DELETE
contra IDs no propios). El pre_hook solo prueba secuencias 1-5 + 100 + 999
+ admin sobre paths comunes; el agent extiende con IDs específicos del
target (post-recon).
