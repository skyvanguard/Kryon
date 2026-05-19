---
name: cwe-352-csrf
description: "Detección y clasificación de CWE-352 Cross-Site Request Forgery (state-changing endpoints sin token). Discrimina vs CWE-345 (insufficient verification) y CWE-1275 (SameSite missing)."
triggers:
  tech: []
  ports: []
  file_extensions: [".java", ".py", ".cs", ".rb", ".php", ".go", ".js", ".ts", ".kt", ".scala"]
  keywords:
    - "cwe-352"
    - "csrf"
    - "cross-site request forgery"
    - "xsrf"
    - "anti-csrf"
    - "csrf token"
    - "csrf protection"
    - "samesite"
    - "state-changing"
    - "post handler"
    - "delete handler"
    - "csrfprotect"
    - "csrf_exempt"
    - "synchronizer token"
priority: 5
required_tools:
  - run_command
---

# CWE-352 — Cross-Site Request Forgery (clasificación SAST)

Se activa cuando el agente audita controladores HTTP que cambian
estado (POST/PUT/DELETE/PATCH). **NO confundir CWE-352 con CWE-1275
(missing SameSite — defense in depth, no fix), CWE-345 (insufficient
verification of origin/referer), ni CWE-863 (incorrect authorization)**.

## Discriminación CWE-352 vs hermanas

| CWE | Significado | Cuándo usar |
|---|---|---|
| **CWE-352** | **CSRF — request side effects sin token** | Endpoint state-changing acepta requests sin synchronizer token / sin Origin check |
| CWE-1275 | Missing SameSite | Solo Set-Cookie sin SameSite — defense-in-depth, no causa raíz por sí solo |
| CWE-345 | Insufficient Verification (Origin/Referer) | Cuando hay check de Origin/Referer pero es bypasseable |
| CWE-862 | Missing Authorization | No hay check de auth (más amplio que CSRF) |

**Regla práctica**: si el endpoint procesa POST/PUT/DELETE con efectos
secundarios y NO verifica token CSRF, Origin header allowlist, o
custom header anti-CSRF → **CWE-352**.

## Sink patterns CWE-352 por framework

### Django
```python
# CWE-352 sinks
@csrf_exempt
def transfer_money(request):  # explicit decorator skip
    ...

# En settings.py
MIDDLEWARE = [
    # 'django.middleware.csrf.CsrfViewMiddleware',  # comentado!
]
```

### Flask
```python
# CWE-352: sin Flask-WTF / Flask-SeaSurf
@app.route('/transfer', methods=['POST'])
def transfer():
    # no CSRF check
    amount = request.form['amount']
```

### Spring
```java
// CWE-352: csrf disabled
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http.csrf().disable();  // <-- CWE-352 sink
    }
}
```

### Rails
```ruby
# CWE-352: protect_from_forgery skipped
class TransfersController < ApplicationController
  skip_before_action :verify_authenticity_token  # <-- CWE-352
  # or:
  protect_from_forgery with: :null_session       # weak, accepts cross-site
end
```

### Express.js
```js
// CWE-352 sink: no csurf middleware
const app = express();
app.use(express.json());
// app.use(csurf());  // missing

app.post('/transfer', (req, res) => {
    // no CSRF token check
});
```

### Cookies SameSite (CWE-1275 related, not CWE-352 by itself)
```javascript
res.cookie('session', token, {httpOnly: true});  // CWE-1275 (no SameSite)
res.cookie('session', token, {sameSite: 'none', secure: true});  // weak SameSite
```

## Familias de bugs CWE-352 (sin spoilers)

- **Money transfer endpoints**: `POST /transfer` sin token (catastrófico en banking).
- **Password change**: `POST /change-password` sin re-auth + sin token.
- **Account deletion**: `DELETE /account` sin token.
- **Admin actions**: `POST /admin/users/$id/promote` sin token.
- **API JSON endpoints**: `POST /api/v1/...` que aceptan `Content-Type: application/x-www-form-urlencoded` (CSRF-able) en lugar de exigir `application/json`.

## Metodología de detección

```bash
# Buscar disable explícito
run_command grep -rn "csrf.disable\|csrf().disable\|csrf_exempt\|skip_before_action.*authenticity" {source_path}

# Buscar handlers POST/PUT/DELETE sin token check evidente
run_command grep -rnB2 "@PostMapping\|@PutMapping\|@DeleteMapping\|methods=\\[.*POST\\|app\\.post(\|app\\.put(\|app\\.delete(" {source_path} | head -50

# Buscar config Spring/Rails con CSRF off
run_command grep -rn "csrf().disable\|skip_authenticity\|allow_csrf_token_only" {source_path}

# Buscar Set-Cookie sin SameSite (CWE-1275, defense-in-depth)
run_command grep -rn "Set-Cookie\|res\\.cookie\\(\|cookie:.*=" {source_path} | grep -v "SameSite\|samesite"
```

Para cada match, verificá:
1. ¿El handler valida un token CSRF (synchronizer pattern)?
2. ¿Hay validación de `Origin` o `Referer` header con allowlist?
3. ¿Requiere custom header `X-CSRF-Token` que cross-site no puede setear?
4. Para JSON APIs: ¿valida `Content-Type: application/json` (preflight CORS-protected)?

## Formato de finding obligatorio

```
CWE-352 en <archivo>:<linea>
```

**NUNCA CWE-1275 ni CWE-345** para missing CSRF protection. CWE-1275
es defense-in-depth (cookie SameSite), CWE-345 es para checks
implementados-pero-bypasseables. CWE-352 es la **ausencia** de protección.

## Banca-safe

100% read-only. NO ejecuta CSRF PoCs contra el target. Validación
real con burp/zap en lab separado.

**Critical en banking**: missing CSRF en endpoints de transferencia,
cambio de password, o configuración de cuentas = riesgo CATASTRÓFICO.
Siempre reportar como HIGH/CRITICAL severity.
