# F13.0 — Corpus pin + CVE list + semgrep baseline

Fecha: 2026-04-15

## Corpus pineado

| Proyecto | HEAD | LoC (approx) | Lenguaje |
|----------|------|--------------|----------|
| Apache Fineract | `60acf8586e3d9f2c5356cc78774a55546a0a5f41` | ~262K | Java |
| GnuCash | `9f8f4d9ed3a44d548fdbe361a087b73508663378` | ~435K | C/C++ |

Ubicación: `scripts/f13/workspace/{fineract,gnucash}/` (gitignored).

### Top módulos por LoC

**Fineract**
- fineract-core ~70K
- fineract-loan ~66K
- fineract-savings ~24K
- fineract-working-capital-loan ~19K
- fineract-provider ~17K

**GnuCash**
- gnucash/ ~239K (src principal)
- libgnucash/ ~186K

## CVE ground truth (NVD)

### Fineract — 19 CVEs

Patrón dominante: **SQL injection** (CVE-2017-5663, CVE-2018-1289/1290/1291/1292, CVE-2018-11800/11801, CVE-2023-25196/25197, CVE-2024-23538/23539, CVE-2024-32838, CVE-2025-58137). RCE (CVE-2022-44635), SSRF (CVE-2023-25195), privilege (CVE-2024-23537), credential exposure (CVE-2025-58130). Rango CVSS 4.3–9.9.

Lista completa: `scripts/f13/cve/fineract-nvd.json` + `summary.txt`.

### GnuCash — 3 CVEs

Todos viejos y triviales (2000-2010): libguile insecure install (CVE-2000-0145), arbitrary file overwrite (CVE-2007-0007), temp dir race (CVE-2010-3999). CVSS 3.6–7.5.

**Implicación**: GnuCash CVE-recall será dominado por 0 — no hay ground truth moderna. El juicio va a tener que depender de **precision N=50** y de **novedad de findings** (posibles CVE-candidates propios).

## Baseline semgrep

Rulesets: `p/ci + p/owasp-top-ten + p/java` (Fineract), `p/ci + p/owasp-top-ten + p/c` (GnuCash).
`p/cpp` no existe como ruleset pack (HTTP 404) — consolidado en `p/c`.

| Proyecto | Findings | Errores parse | Top regla |
|----------|----------|---------------|-----------|
| Fineract | **28** | 2 | `spring-sqli` (18) |
| GnuCash | **2** | 57 | Python/Flask (false cat) |

### Fineract — desglose

```
spring-sqli                                       18
weak-ssl-context                                   5
allow-privilege-escalation-no-securitycontext      3
run-shell-injection                                1
spring-actuator-dangerous-endpoints-enabled        1
```

Severidad: 1 ERROR, 27 WARNING.

### GnuCash — baseline débil

2 findings ambos son reglas Python/Flask aplicadas a archivos Python auxiliares (no al core C/C++). **57 entradas de error** en el JSON semgrep — desagregadas:

| Categoría | Count | Nota |
|-----------|-------|------|
| C/C++ fatal syntax error | **2** | `libgnucash/engine/qofbook.h`, `gnucash/gnome/dialog-payment.c` |
| C/C++ PartialParsing | **137** | código real GnuCash — semgrep no completa el AST |
| HTML PartialParsing | 89 | samples vendored de `borrowed/chartjs-2/` — ruido |
| JS Timeout | 6 | reglas js-security en samples chartjs — ruido |

Universo de archivos fuente reales: **310 `.c` + 430 `.h` + 268 `.cpp` = 1,008 files C/C++**.
Semgrep falla parcial o totalmente en **139 / 1,008 = ~13.8%** del código C/C++ real.

**Implicación para F13.3 (pitch GnuCash)**: El comparador semgrep es débil no porque no haya vulnerabilidades en GnuCash, sino porque **semgrep default no parsea 14% del código C/C++** (macros GLib/GTK heavy, probablemente). Condiciones para que el pitch tenga peso:

1. Reportar los 2 syntax errors C específicos de semgrep (ya enumerados arriba).
2. Confirmar en F13.1 que **Kryon procesa esos mismos archivos sin skip ni error silente** (logging explícito).
3. Si Kryon produce N findings válidos sobre esos archivos, el titular es: "semgrep 0 / Kryon N en ~14% del codebase donde semgrep es ciego".

Trampa a evitar: "semgrep no ve nada" ≠ "Kryon es mejor". Kryon debe correr limpio sobre esos mismos archivos y los findings tienen que validarse.

## Archivos generados

```
scripts/f13/
├── .gitignore
├── F13_0_SETUP.md              (este archivo)
├── parse_cves.py               (NVD JSON parser)
├── cve/
│   ├── fineract-nvd.json       (52 KB, 19 CVEs)
│   ├── gnucash-nvd.json        (13 KB, 3 CVEs)
│   └── summary.txt             (human-readable)
├── semgrep/
│   ├── fineract-semgrep.json   (811 KB, 28 findings)
│   └── gnucash-semgrep.json    (219 KB, 2 findings)
└── workspace/                  (gitignored)
    ├── fineract/               (pinned 60acf858)
    └── gnucash/                (pinned 9f8f4d9e)
```

## Gates para F13.1→F13.4

Pre-agreed ship gate (F13.4): al menos UNA de:

1. **Precision Kryon > semgrep** en muestra N=50 uniforme de findings
2. **≥1 CVE unique** (Kryon encuentra CVE que semgrep no) — aplicable casi exclusivamente a Fineract
3. **Readable output markedly** — demo PDF ejecutivo con remediation genuinamente accionable (no sólo "detectado")

**Anti-tuning**: los targets y los gates quedan pineados aquí. Prohibido tunear tras ver resultados de F13.1.

## Next

### F13.1 — scan plan (two-pass)

Kryon scan sobre ambos corpuses con **dos pasadas** del mismo run:

1. **Raw pass**: sin allow-list, sin triage filter. Output bruto para comparación técnica raw-vs-raw contra semgrep.
2. **Product pass**: mismo scan con allow-list F10.1 + triage F10.3-B aplicados. Output curado para la comparación de workflow (triaged-vs-raw).

Demo final tendrá dos tablas:
- **Raw engine**: Kryon compite como motor detection?
- **Curated product**: Kryon gana como workflow (allow-list + triage annotations que semgrep solo no tiene)?

Ventaja asimétrica del producto: aunque Kryon no supere en recall raw, si reduce 28 findings semgrep noisy a 15 KEEP accionables, ese es el pitch para el decisor no-técnico.

Además, en el scan GnuCash: log explícito sobre `libgnucash/engine/qofbook.h` y `gnucash/gnome/dialog-payment.c` para confirmar que Kryon los procesa sin error donde semgrep fatal-fails.

### F13.2 — ground truth

- Precision N=50 sobre muestra uniforme de findings (no recortar acá).
- CVE recall sobre Fineract (relevante).
- GnuCash CVE histórico: **30 min exploration cap**. Chequear si los ~3 CVEs 2000-2010 tienen código aún presente en HEAD `9f8f4d9e` via `git show <commit>^ -- <file>`. Si 1-2 CVEs son reproducibles en código actual, se rescatan como datos. Si no, se documenta el intento y se sigue.

### F13.3 / F13.4

- F13.3: comparator table raw-vs-raw y product-vs-raw.
- F13.4: demo PDF (Fineract como hero) + ship/negative decision.
