---
name: cwe-918-ssrf
description: "Detección y clasificación de CWE-918 Server-Side Request Forgery (HTTP fetch hacia URL controlada por input). Discrimina vs CWE-22 (filesystem), CWE-601 (open redirect cliente)."
triggers:
  tech: []
  ports: []
  file_extensions: [".java", ".py", ".cs", ".rb", ".php", ".go", ".js", ".ts", ".kt", ".scala"]
  keywords:
    - "cwe-918"
    - "ssrf"
    - "server-side request forgery"
    - "url fetch"
    - "http fetch"
    - "urlopen"
    - "requests.get"
    - "httpclient"
    - "fetch("
    - "axios.get"
    - "url parameter"
    - "url validation"
    - "169.254.169.254"
    - "metadata service"
    - "imdsv1"
    - "imdsv2"
    - "internal network"
priority: 5
required_tools:
  - run_command
---

# CWE-918 — Server-Side Request Forgery (clasificación SAST)

Se activa cuando el agente audita código que el server-side hace
HTTP/network fetch usando una URL/host parametrizada. **NO confundir
CWE-918 con CWE-22 (filesystem traversal), CWE-601 (open redirect —
cliente, no server), CWE-94 (code injection)**.

## Discriminación CWE-918 vs hermanas

| CWE | Significado | Cuándo usar |
|---|---|---|
| **CWE-918** | **SSRF — server fetches URL del input** | App fetcha `http(s)://`, `gopher://`, `file://`, `dict://` con destino controlado |
| CWE-22 | Path Traversal | Filesystem read local, NO HTTP fetch |
| CWE-601 | Open Redirect | Cliente browser sigue redirect, NO server fetch |
| CWE-940 | Improper Verification of Source of Communication | Más amplio (incluye message queues) |
| CWE-294 | Authentication Bypass by Capture-replay | Network replay, no SSRF |

**Regla práctica**: si el sink es `urlopen/requests.get/HttpClient.send/fetch/curl` con URL parametrizada por input no validado → **CWE-918**.

## Sink patterns CWE-918 por lenguaje

### Python
```python
# CWE-918 sinks
import requests
requests.get(user_url)             # CWE-918
requests.post(user_url, data=...)
urllib.request.urlopen(user_url)

# Scheme bypass tricks
requests.get("http://" + user_input)  # also CWE-918 if user_input controls host
```

### Java
```java
// CWE-918 sinks
URL url = new URL(userInput);
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
conn.getInputStream();

// HttpClient
HttpClient client = HttpClient.newHttpClient();
client.send(HttpRequest.newBuilder().uri(URI.create(userInput)).build(), ...);

// Apache HttpClient
new HttpGet(userInput);

// XXE adjacent (CWE-611, not CWE-918, but related):
DocumentBuilder.parse(InputSource(userInput));  // XXE
```

### Node.js
```js
// CWE-918 sinks
const axios = require('axios');
await axios.get(req.body.url);
fetch(req.query.url);

const http = require('http');
http.get(userUrl, (res) => { ... });

// Webhook handlers que callback al URL del payload
app.post('/webhook', async (req, res) => {
    await fetch(req.body.callback_url);  // CWE-918
});
```

### PHP
```php
// CWE-918 sinks
file_get_contents($_GET['url']);  // CWE-918 (PHP fopen wrappers!)
$ch = curl_init($_POST['target']);
curl_exec($ch);

// File include via PHP wrappers — peligro extra (CWE-73)
include $_GET['file'];  // si file=php://input o data:// es RCE
```

### Go
```go
// CWE-918 sinks
resp, err := http.Get(userURL)
resp, err := http.Client{}.Get(userURL)
req, _ := http.NewRequest("GET", userURL, nil)
```

### Ruby
```ruby
# CWE-918 sinks
Net::HTTP.get(URI(params[:url]))
open(params[:url])  # OpenURI gem — bonus: respect file:// too
```

## Familias de bugs CWE-918 (sin spoilers)

- **Webhook URL parameter**: app fetcha la URL del webhook config.
- **Image proxy**: `/proxy?url=` para evitar mixed-content.
- **PDF generator**: `wkhtmltopdf <user_url>` server-side.
- **OAuth callback / SSO metadata fetch**: discovery endpoint URL.
- **RSS/feed aggregator**: server fetches feed URL del input.
- **URL preview / link unfurling**: Slack-style preview generation.
- **AWS/GCP IMDS abuse**: SSRF a `http://169.254.169.254/latest/meta-data/` para robar credentials.

## Sinks especiales — Cloud Metadata (CRITICAL)

```python
# IMDSv1 (sin token) - target classico de SSRF en cloud
"http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# IMDSv2 (con token) - mitiga SSRF pero no elimina
"http://169.254.169.254/latest/api/token"  + PUT con header

# GCP
"http://metadata.google.internal/computeMetadata/v1/"

# Azure
"http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# OpenStack
"http://169.254.169.254/openstack/"
```

## Metodología de detección

```bash
# Python
run_command grep -rn "requests\\.get\\|requests\\.post\\|urllib\\.request\\.urlopen" {source_path}
run_command grep -rn "httpx\\.get\\|aiohttp\\.ClientSession" {source_path}

# Java
run_command grep -rn "new URL(\\|openConnection\\|HttpClient\\|HttpGet\\(" {source_path}

# Node.js
run_command grep -rn "axios\\.get\\|axios\\.post\\|fetch(\\|http\\.get(\\|got\\.get\\|node-fetch" {source_path}

# PHP
run_command grep -rn "file_get_contents.*\\\$_GET\\|file_get_contents.*\\\$_POST\\|curl_init" {source_path}

# Go
run_command grep -rn "http\\.Get\\|http\\.Post\\|http\\.Client.*Get" {source_path}

# Ruby
run_command grep -rn "Net::HTTP\\|open-uri\\|HTTParty" {source_path}

# Buscar el smoking gun: validación de URL ausente
run_command grep -rn "url.*=.*params\\|url.*=.*request\\." {source_path}
```

Para cada match, verificá:
1. ¿Hay allowlist de schemes (solo `https://`, no `file://`, `gopher://`, `dict://`)?
2. ¿Hay allowlist de hosts (no `169.254.169.254`, no `localhost`, no `10.0.0.0/8`)?
3. ¿Se resuelve DNS antes y se valida la IP resuelta (no privada)?
4. ¿Hay redirect follow limit + revalidación post-redirect?

## Formato de finding obligatorio

```
CWE-918 en <archivo>:<linea>
```

**NUNCA CWE-22, CWE-200, CWE-601** para SSRF server-side. CWE-22 es
filesystem, CWE-601 es client-side redirect, CWE-200 es info leak
genérico (consecuencia).

## Banca-safe

100% read-only. NO ejecuta SSRF PoCs reales, NO toca metadata
endpoints en cloud. Validación real con burp collaborator en lab.

**Critical en banking cloud-hosted**: SSRF a IMDSv1 = robar IAM
credentials = compromiso total de AWS account. Siempre CRITICAL
severity para banking infra.
