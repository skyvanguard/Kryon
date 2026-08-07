---
name: burp-integration
description: "Integración con Burp Suite Professional vía REST API (repeater, active scan, proxy history). Fallback a mitmproxy embebido (F50) cuando Burp no está disponible."
triggers:
  tech: []
  ports: [80, 443, 1337, 8080, 8443]
  keywords:
    - "burp"
    - "burp suite"
    - "burp repeater"
    - "burp intruder"
    - "burp active scan"
    - "burp proxy"
    - "proxy history"
    - "intercept"
    - "replay request"
    - "mitmproxy"
priority: 26
required_tools:
  - burp_send_to_repeater
  - burp_active_scan
  - burp_proxy_history
  - http_fetch
---

## Rol

Burp Suite es la herramienta profesional de referencia para web
pentesting — su fuerza está en el **registro + replay + modificación
iterativa** de requests. Kryon puede integrarse con Burp Pro via
REST API, o caer a mitmproxy embebido (F50) cuando Burp no está
disponible.

## Configuración (Burp Professional)

1. Abrir Burp Suite Professional.
2. Settings → Suite → REST API → **Enable**.
3. Generar API key: **Generate new key** → copiar.
4. Configurar en la shell antes de lanzar Kryon:
   ```bash
   export BURP_API_URL="http://localhost:1337"
   export BURP_API_KEY="<clave-generada>"
   export BURP_API_TIMEOUT="15"
   ```
5. Opcional: confirmar que está arriba:
   ```bash
   curl http://localhost:1337/$BURP_API_KEY/v0.1/
   # → debería responder 200 con JSON de info.
   ```

Sin `BURP_API_KEY`, los tools **caen automáticamente a mitmproxy**
(F50) — no hay error duro, solo se loguea `[mitm-fallback]` en la
salida para que el auditor sepa qué engine corrió.

## Herramientas disponibles

### `burp_send_to_repeater(url, method, headers_json, body, modifications_note)`

Replay de request con modificaciones iterativas. Cada llamada queda
registrada en el Repeater de Burp (Pro) o en el historial de la
sesión mitmproxy (fallback).

Ideal para:
- Probar múltiples payloads contra el mismo endpoint
- Modificar un request capturado de /proxy/history
- Construir PoCs replayables para el reporte final

### `burp_active_scan(url, scan_profile)`

Dispara un scan activo de Burp sobre la URL objetivo. Perfiles
built-in: `audit`, `crawl`, `crawl-and-audit`, `passive-only`.
**Requiere Pro** — el fallback mitmproxy no escanea, sólo avisa.

### `burp_proxy_history(filter_contains, limit)`

Lista las últimas `limit` requests interceptadas. Útil para:
- Reconstruir la secuencia de un bug reproducible
- Filtrar por endpoint específico (`filter_contains="/api/Users"`)
- Exportar evidencia cronológica del engagement

## Flujo recomendado (Burp Pro)

```
1. Iniciar Burp + habilitar proxy :8080
2. Configurar navegador (o Playwright vía env) a usar 127.0.0.1:8080
3. Navegar el target + disparar flows iniciales
4. En Kryon:
   → burp_proxy_history(filter_contains="/api/Users", limit=30)
     para enumerar endpoints interesantes
   → burp_send_to_repeater(...) con payload modificado
   → burp_active_scan(url=...) en endpoints críticos
5. Al cerrar, exportar el proyecto Burp (.burp) como evidencia
```

## Flujo fallback (sin Burp Pro)

```
1. F50 ya instancia un HttpSession in-memory
2. Cada llamada a burp_send_to_repeater o burp_proxy_history
   usa ese session transparentemente
3. La historia vive en RAM durante la sesión Kryon
4. Al cerrar el REPL, se pierde — exportar JSON antes si
   necesitás evidencia (tool `export_session` de F50)
```

## Anti-patrones

- **No** activar `active_scan` en producción sin autorización escrita.
  Un scan activo de Burp dispara miles de payloads y puede alertar
  SIEM o causar carga.
- **No** commitear `BURP_API_KEY` al repo. Usar `~/.kryon/secrets.env`
  (ya en gitignore).
- **No** confiar en Burp como única evidencia — el hash de
  reproducibilidad que Kryon genera es el artefacto defendible ante
  auditor externo.
- **No** usar Burp + mitmproxy al mismo tiempo — ambos ocupan el
  proxy del navegador y cancelan los flows.

## Integración con otros skills

- **`http-fetch`** + `burp_send_to_repeater` = primer request rápido
  con Python requests, luego replay modificado en Burp para el
  reporte.
- **`browser-exploit`** + Burp = Playwright manda requests, Burp los
  captura (configurar Playwright para usar el proxy de Burp).
- **`hackerone`** + Burp = todo request dentro de un programa H1
  queda en Burp con su X-HackerOne-Research header.

## Ejemplo en español

```
Usuario: "Revisá los últimos 20 requests del proxy y mostrame los
          que van a /api/Users"

Kryon (este skill):
  → burp_proxy_history(filter_contains="/api/Users", limit=20)
    [burp-pro] proxy history:
      GET   https://target/api/Users      -> 200  2.1kB
      PUT   https://target/api/Users/3    -> 200  512B
      POST  https://target/api/Users      -> 201  128B
      ...
  
Usuario: "Tomá el PUT /api/Users/3 y cambiale el body a role=admin"

Kryon:
  → burp_send_to_repeater(
      url="https://target/api/Users/3",
      method="PUT",
      headers_json='{"Authorization":"Bearer <captured>"}',
      body='{"role":"admin"}',
      modifications_note="priv-esc attempt via role=admin"
    )
    [burp-pro] status=200 bytes=147
    ...
```

## Seguridad operacional

- Burp API key rotación: **cada engagement**. Tratar la key como
  credencial productiva.
- Logs de Burp: Burp escribe `~/.BurpSuite/burp.log` — incluye URLs
  interceptadas. Asegurarse de que el disco está cifrado (FileVault
  / BitLocker / LUKS) durante engagements bancarios.
- Sanitize: antes de compartir el `.burp` con el cliente, usar
  `File → Tools → Clear state` + export filtrado para eliminar
  tokens/cookies de otras sesiones.
