---
name: cwe-79-xss
description: "Detección y clasificación de CWE-79 Cross-Site Scripting (Reflected/Stored/DOM-based). Discrimina vs CWE-80 (basic XSS) y CWE-116 (improper encoding)."
triggers:
  tech: []
  ports: []
  file_extensions: [".java", ".py", ".cs", ".rb", ".php", ".go", ".js", ".ts", ".jsx", ".tsx", ".html", ".jsp", ".erb", ".vue"]
  keywords:
    - "cwe-79"
    - "xss"
    - "cross-site scripting"
    - "cross site scripting"
    - "innerhtml"
    - "outerhtml"
    - "document.write"
    - "eval"
    - "dangerouslysetinnerhtml"
    - "v-html"
    - "ng-bind-html"
    - "reflected xss"
    - "stored xss"
    - "dom xss"
    - "dom-based xss"
    - "html injection"
    - "javascript injection"
priority: 5
required_tools:
  - run_command
---

# CWE-79 — Cross-Site Scripting (clasificación SAST)

Se activa cuando el agente audita código que renderiza HTML, manipula
DOM, o devuelve respuestas con contenido derivado de input. **NO
confundir CWE-79 con CWE-80 (basic HTML attribute XSS — más específico),
CWE-116 (improper encoding/escaping), ni CWE-94 (code injection
genérico)**.

## Discriminación CWE-79 vs hermanas

| CWE | Significado | Cuándo usar |
|---|---|---|
| **CWE-79** | **XSS genérico (reflected/stored/DOM)** | input no escapado llega a HTML/JS context del cliente |
| CWE-80 | Basic XSS (HTML attributes) | XSS específicamente vía atributos HTML mal sanitizados |
| CWE-116 | Improper Encoding/Escaping | Encoding incorrecto del output (más general) |
| CWE-94 | Code Injection | Server-side code injection, no client-side |
| CWE-1336 | Improper Neutralization of Special Elements in Template Engine | Template injection (SSTI), no XSS |

**Regla práctica**: si el sink es DOM/HTML del cliente (`innerHTML`, `document.write`, `<script>`, framework template), es CWE-79. Si es el server interpretando código (SSTI/eval), es CWE-94 o CWE-1336.

## Sink patterns CWE-79 por lenguaje

### JavaScript / TypeScript (DOM XSS)
```js
element.innerHTML = userInput;       // CWE-79 sink
element.outerHTML = userInput;
document.write(userInput);
element.setAttribute('onclick', userInput);
eval(userInput);                      // CWE-94 + CWE-79 mixed
new Function(userInput);
location.href = userInput;            // open-redirect + XSS si javascript:
```

### React / Vue / Angular
```jsx
<div dangerouslySetInnerHTML={{__html: userInput}} />   // React CWE-79
<div v-html="userInput" />                              // Vue CWE-79
<div [innerHTML]="userInput" />                         // Angular CWE-79
ng-bind-html-unsafe="userInput"                         // Angular legacy
```

### Java / JSP
```jsp
<%= request.getParameter("name") %>                     // CWE-79 sink (no escape)
${param.name}                                            // CWE-79 si no <c:out>
out.println(request.getParameter("name"));               // CWE-79
```

### Python (Django/Flask/Jinja2)
```python
return HttpResponse(user_input)                          # CWE-79 (Django)
return f"<div>{user_input}</div>"                        # CWE-79
{{ user_input | safe }}                                  # Jinja2 |safe filter CWE-79
{% autoescape off %}{{ user_input }}{% endautoescape %}  # CWE-79
mark_safe(user_input)                                    # CWE-79
```

### PHP
```php
echo $_GET['name'];                                      // CWE-79
echo $_REQUEST['x'];                                     // CWE-79
print($_POST['comment']);                                // CWE-79
```

## Familias de bugs CWE-79 (sin spoilers)

- **Search reflection**: `?q=<script>` reflejado en página de resultados.
- **Error message reflection**: input inválido se devuelve sin escape en mensaje de error.
- **Stored profile fields**: bio/username/comment guardado en DB y renderizado en otras vistas.
- **DOM via location/hash**: `window.location.hash` → `innerHTML`.
- **postMessage handlers**: `event.data` insertado en DOM sin validar origin.
- **Template injection client-side**: Vue/Angular bindings con `eval`-equivalent.

## Metodología de detección

```bash
# JavaScript/TypeScript sinks
run_command grep -rn "innerHTML\|outerHTML\|document\.write\|dangerouslySetInnerHTML" {source_path}
run_command grep -rn "v-html\|ng-bind-html\|\\[innerHTML\\]" {source_path}

# Java JSP / Java servlet
run_command grep -rn "request\.getParameter\|getRequestParameter" {source_path} | grep -v "encodeForHTML\|StringEscapeUtils"

# Python Django/Flask/Jinja
run_command grep -rn "mark_safe\|| safe\|autoescape off\|HttpResponse" {source_path}

# PHP
run_command grep -rn "echo \\\$_GET\|echo \\\$_POST\|print \\\$_REQUEST" {source_path}
```

Para cada match, verificá:
1. ¿El input llega sin pasar por escape contextual (HTML/JS/URL/CSS)?
2. ¿El framework tiene auto-escape habilitado (Jinja2 default sí, raw template no)?
3. ¿Hay CSP que mitige el riesgo? (mitigation, no fix)

## Formato de finding obligatorio

```
CWE-79 en <archivo>:<linea>
```

**NUNCA CWE-200, CWE-94 ni CWE-116** para casos de HTML/JS injection
en client-side. CWE-200 es info exposure (consecuencia downstream), 
CWE-94 es code injection server-side, CWE-79 es la causa raíz client-side.

## Banca-safe

100% read-only — grep/find/cat sobre código pre-clonado. NO ejecuta
payloads XSS contra el target, NO inyecta en DOM real, NO conecta
a red.
