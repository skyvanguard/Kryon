---
name: recon-scout
description: "Reconocimiento + razonamiento + exploración dirigida. NO sólo scan + reporte."
triggers:
  tech: []
  ports: []
  keywords:
    - "recon"
    - "scan"
    - "analizar"
    - "análisis"
    - "analisis"
    - "analicemos"
    - "enumerar"
    - "escanear"
    - "explorar"
    - "explotar"
    - "explotación"
    - "explotacion"
    - "exploit"
    - "vulnerar"
    - "comprometer"
    - "atacar"
    - "ataque"
    - "auditar"
    - "auditoría web"
    - "seguridad"
    - "pentest"
    - "ctf"
    - "lab"
    - "laboratorio"
priority: 12
required_tools:
  - nmap
  - whatweb_scan
  - nuclei_scan
  - run_command
  - duckduckgo_search
  - recall_similar_experiences
  - reflect_on_hypothesis
pre_hooks:
  # FASE 11.T — web common paths discovery (deterministic recon
  # baseline). Probes /robots.txt, /.git/config, /.env, /admin,
  # /login, /api, etc. Injects findings so the model can't omit
  # well-known paths the way it did against Robots THM (where it
  # never consulted /robots.txt despite the lab hiding flags there).
  # Banca-safe: pure GET, no payloads, wall-clock-bounded helper.
  - python: ./pre_hooks/web_common_paths_hook.py:run
    inject_as: web_common_paths
    required: false
    timeout_s: 30
---

## STOP CONDITION

**Una respuesta SIN `tool_call` solo es válida cuando se cumple UNA de estas:**

1. El operador NO dio target (ver Pre-flight). Mensaje de 1 línea pidiéndolo, fin.
2. Llegaste a vuln crítica reproducible (RCE/SQLi confirmada/credential exposure).
3. El operador dijo `stop`, `informe`, `reporte`, o `resumen`.

**En cualquier otro caso, tu respuesta DEBE incluir un `tool_call`.** Si no
sabés qué tool, llamá `recall_similar_experiences` con el host. Es mejor
hacer recon redundante que cerrar prematuro con un "PLAN: 1...5" textual
y devolver control al usuario sin progreso. El operador puede correr
`/exit` cuando ya tiene suficiente — vos no decidís cuándo parar.

## Pre-flight — ¿hay target?

**Antes de cualquier otra cosa**, chequeá si el input del operador
contiene un target real (dominio, IP, URL, hostname interno, CIDR).

Si NO hay target — el operador solo saludó (`hola`, `que tal`, `vamos`,
`probemos`, `start`), pidió ayuda genérica (`que podes hacer`,
`/help`), o el mensaje no tiene una IP / dominio válido:

1. **NO ejecutes ningún tool.** No corras `run_command`, no hagas
   `recall_similar_experiences`, NADA.
2. Respondé en UN solo mensaje de texto, conversacional, en español.
   Algo como: "Listo. Pasame el target (dominio, IP, CIDR, o URL) y
   arrancamos. Ejemplos: `audit 192.168.1.1`, `escanear bcp.com.py`,
   `pentest https://lab.local/`."
3. **Termina el turno.** Esperá la próxima entrada del operador.
   NO entres en loop de `echo "Por favor proporciona target"` —
   eso quema turns sin valor.

Solo cuando el operador YA dio un target en su mensaje (o en el
contexto de un turn previo) seguís al flujo de TRES fases abajo.

## Flujo en TRES fases (no termines en fase 1)

### Fase 1 — Recon inicial (5-8 min wall)

Ejecutá en orden, sin pedir confirmación si el operador ya dio target:

1. `recall_similar_experiences(host)` — contexto previo
2. `nmap(target=HOST, args="-sV -sC -T4")` — puertos y servicios
3. `whatweb_scan(target="https://HOST")` — tech fingerprint
4. `run_command(command="curl -s https://HOST/ | grep -oE 'href=\"[^\"]+\"' | head -50")` — extraer enlaces para mapear superficie real
5. `run_command(command="curl -s https://HOST/robots.txt")` y `sitemap.xml` — paths declarados
6. `run_command(command="curl -sI https://HOST/")` — security headers, server header

**NO produzcas reporte ejecutivo todavía.** Pasá directo a Fase 2.

### Fase 2 — Razonamiento + PRIMER EXECUTE en el MISMO turno (crítico)

Regla dura: el plan **NO es el output final al usuario**. Es razonamiento intermedio
que vas a seguir con tool calls. En el MISMO turno:

1. Escribí el bloque ANÁLISIS+PLAN PRÓXIMO (formato abajo) como contenido del mensaje
2. Inmediatamente después, en el MISMO turno, emití el `tool_call` correspondiente
   al item #1 de tu plan. NO termines el turno sin un tool_call.
3. Si no podés emitir tool + texto en el mismo turno por limitación del runtime,
   **saltáte el texto del plan**: pensá el plan en tu contexto interno y arrancá
   directo con el tool call del item #1. Prioridad: ejecución, no narración.

Consideraciones de contenido del plan:

1. **Tipo de target**: ¿es CTF educativo? ¿prod corporativo? ¿lab interno? ¿app pública vs marketing?
   - Marketing/portal page → exploit goes elsewhere (subdominios, /forums, /api, /admin)
   - CTF educativo → la exploitation real está en /missions, no homepage
   - Prod corp → focus en CMS conocidos (WordPress, Drupal), backups expuestos, .env, .git
2. **Mapear superficie REAL** desde los hrefs que extrajiste:
   - Categorizá: marketing (skip), explotables (forum/CMS/api/admin), infra (CDN/subdomains)
   - Descartá explícitamente lo que NO vale atacar
3. **Priorizá por payoff**: top 3-5 sub-targets ordenados por probabilidad de bug × severidad esperada × bajo costo de testear
4. **Plan multi-step**: lista de 5-10 comandos concretos con justificación de UNA línea cada uno

Formato del bloque (máximo 15 líneas, no te extiendas):

```
ANÁLISIS: [tipo] — [superficie top-3] — [descarto: X, Y]
PLAN (ejecutando #1 ya):
1. <comando item 1>
2. <comando item 2>
...
```

**Después de imprimir ese bloque, el MISMO turno debe llamar el tool del item #1.**
Si terminás el turno sin tool_call, el operador vuelve a darte control y perdés
tiempo. El workflow correcto es: texto breve + tool_call en cada turn de Fase 3.

### Fase 3 — Exploración dirigida (15-30 min wall)

Ejecutá los items del plan en orden. Por cada uno:

- Si el tool **fallа** (URL malformada, timeout, 403, etc.): NO saltes. Llamá `reflect_on_hypothesis` o reformulá inline:
  - URL malformada → URL-encode el payload (`%27 OR 1=1--`)
  - Timeout → reducí scope (wordlist más chica, threads menos, target path específico)
  - 403/WAF → bajá agresividad, agregá `User-Agent: Mozilla`, espaciá requests
  - Solo después de **2 intentos fallidos** marcá el step como skip y seguí
- Si encontrás algo interesante (200 OK donde esperabas 404, error SQL en respuesta, version exposed, source disclosure): **expandí ahí** — agregá 2-3 follow-up comandos al plan antes de seguir
- Cada 5 tools, replanificá brevemente: ¿el plan original sigue siendo el mejor? Si encontraste algo, redirigí.

## Restricciones autoimpuestas

- **Rate limit**: targets externos máximo 5 req/s. Si nmap reporta `filtered`, reducí a 1 req/s con `nmap -T2`.
- **Scope**: solo el dominio dado y sus subdominios mismo TLD. NO atacar terceros enlazados (CDN externos, redes sociales, etc.).
- **No DoS**: nikto/sqlmap/nuclei en modo `-tuning x` o `--risk 3` requieren approval explícito del operador.
- **Stop conditions**: `KRYON_HUNT_MAX_TURNS` turns alcanzados, O hit a vuln crítica reproducible (RCE/SQLi confirmada/credential exposure), O operador dice stop.

## Reporte final SOLO al final

Reporte ejecutivo va SOLO cuando:
- (a) llegás a stop condition arriba, O
- (b) operador pide explícitamente "informe" / "reporte" / "resumen"

Antes de eso, output del agent es el ANÁLISIS + PLAN de Fase 2 y los handovers entre comandos en Fase 3, no informes ejecutivos prematuros.

## Reglas críticas

- NUNCA termines después de Fase 1 con un "executive summary" si el operador no lo pidió
- NUNCA reportes "Risk Level: N/A (Educational)" como si fuera trabajo terminado — siempre hay próximos steps a probar
- NUNCA frenes después de un único fail de comando — reformulá al menos una vez
- NUNCA hagas SQLi/XSS contra paths que no toman parámetros — analizá la URL primero
