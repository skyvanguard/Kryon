---
name: http-fetch
description: "HTTP fetch nativo (Python requests) — cuando curl es bloqueado por WAF o necesitás manejo fino de cookies/sesión dentro de un turno."
triggers:
  tech: []
  ports: [80, 443, 8080, 8443]
  keywords:
    - "http fetch"
    - "http request"
    - "requests library"
    - "python requests"
    - "waf bloqueo"
    - "waf bypass ua"
    - "user-agent fingerprint"
    - "session keep-alive"
    - "cookies nativas"
    - "fetch api"
priority: 22
required_tools:
  - http_fetch
  - shell
---

## Rol dentro del stack

Kryon tiene 3 maneras de generar tráfico HTTP al target:

| Tool | UA default | Cookies | JS | Uso primario |
|---|---|---|---|---|
| `shell("curl …")` | `curl/8.x` | manual via `-b`/`-c` | no | Recon rápido, PoC concisos |
| **`http_fetch` (este skill)** | Chrome realista | automáticas en session | no | Cuando curl es bloqueado por WAF o serializás una sesión de varios pasos |
| `browser_*` (Playwright) | Chrome real | full DOM | sí | DOM-XSS, SPA routes, JS-only flags |

## Cuándo usar `http_fetch` específicamente

1. **WAF/Cloudflare filtra por UA**. Muchos bounties (Plata, Juice Shop
   en prod) devuelven 403 a `curl/*` pero aceptan UA de navegador.
   `http_fetch` ya manda `User-Agent: Mozilla/5.0 … Chrome/120`.

2. **Sesión multi-request en UN turno**. Con curl, cada request se
   encadena con `-b cookies.txt`. Con `http_fetch`, se puede hacer:
   ```
   # 1) login (guarda JSESSIONID en memoria)
   http_fetch(url="...", method="POST", body='{"u":"a","p":"b"}')
   # 2) request autenticado reusando la cookie
   http_fetch(url="...", headers_json='{"Authorization":"Bearer ..."}')
   ```
   Más legible + menos shell quoting.

3. **Headers + body complejos**. `http_fetch` acepta `headers_json`
   como string JSON (un solo parámetro), evitando shell-quote de
   múltiples `-H`.

4. **Respuesta truncada y parseada**. `http_fetch` devuelve
   status + URL final + headers filtrados + body (hasta `max_body`
   bytes). Menos ruido que `curl -v` en el contexto del LLM.

## Anti-patrones

- NO usar `http_fetch` para binarios grandes (> 1 MB) — usar
  `shell("curl -O …")` y luego leer con `shell("head -c …")`.
- NO ignorar redirects si el challenge depende de la URL final —
  `follow_redirects=False` evita esto.
- NO asumir que el target valida pinning TLS — `http_fetch` valida
  certs por defecto (`verify=True`). Si necesitás probar un cert
  inválido, usar curl con `-k`.

## Ejemplos — reemplazos directos

### Antes (curl)
```bash
curl -s -X POST -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"email":"admin@juice-sh.op","password":"x"}' \
  https://target/rest/user/login
```

### Ahora (http_fetch)
```python
http_fetch(
    url="https://target/rest/user/login",
    method="POST",
    headers_json='{"Content-Type":"application/json","Authorization":"Bearer <token>"}',
    body='{"email":"admin@juice-sh.op","password":"x"}'
)
```

## Routing decisión

```
¿Target responde 403 o 503 a curl?
  └─ Sí  → probar http_fetch (UA Chrome por default)
  └─ No  → curl está bien (más portable)

¿El flujo requiere 3+ requests con la misma sesión?
  └─ Sí  → http_fetch con cookies_json compartido
  └─ No  → curl con -b cookies.txt o pares sueltos

¿El challenge requiere JS execution?
  └─ Sí  → browser-exploit skill (Playwright)
  └─ No  → http_fetch o curl
```

## Integración con Burp

Cuando `BURP_API_URL` está configurado, preferir `burp_send_to_repeater`
en lugar de `http_fetch` porque:
- Burp graba cada request → evidencia replayable
- El flow queda listo para modificar en el Repeater de Burp
- El tester puede seguir experimentando manualmente desde ahí

`http_fetch` es la herramienta de "trabajo rápido"; Burp es la de
"construyo evidencia para el reporte".
