# Zero-Day Hunter Roadmap — Kryon → Mythos-class capabilities

> **Objetivo:** elevar a Kryon de "autonomous pentesting agent" a "autonomous 0-day research agent"
> capaz de encontrar vulnerabilidades inéditas en código fuente (estilo Claude Mythos Preview).

**Versión del plan:** 2026-04-14 · **Baseline:** Kryon v2.1.0 · **Target:** v2.3.0

---

## Contexto

### Lo que hizo Claude Mythos (abril 2026)

Anthropic reportó 500+ vulnerabilidades high-severity validadas, muchas **0-days con décadas sin detectar por fuzzers**. La sorpresa: **sin scaffold especializado, sin prompting custom**. El salto viene de 3 elementos combinados:

1. Capacidad emergente del modelo en razonamiento + ejecución agéntica
2. **Oracle de ground-truth** (ASAN/sanitizers) que elimina alucinaciones
3. Ciclo **Hypothesize → Verify → Report** con validator agent separado

Técnicas clave observadas:

- **Variant analysis**: leer `git log`, encontrar commits de seguridad, buscar call-sites sin parchar
- **File prioritization**: un agent rankea archivos 1-5 por superficie antes de deep-dive
- **Paralelismo**: N agents escanean archivos distintos simultáneamente
- **Validator separado**: otro agent confirma "¿es real e interesante?" sin compartir contexto con el hunter (evita confirmation bias — 89% agreement con humanos expertos)

### Baseline Kryon — qué funciona y qué no (sesión real `britimp.com.py`, 14-abr-2026)

**Funciona:**
- Tool chaining autónomo en fase recon inicial (nmap → whatweb → gobuster → nuclei → report)
- Sin alucinación de tools, sin llamadas duplicadas idénticas
- Reportes en español bien estructurados
- Learning loop recall al arranque

**Roto / degradado:**

| # | Problema | Evidencia sesión 74732376 |
|---|---|---|
| R1 | **Stop-early en follow-up** — hace 1-2 tools y espera input. Usuario tuvo que decir "continua" 4 veces. | Tras `/config 301` no siguió el redirect ni hizo gobuster recursivo |
| R2 | **Magic Doc re-inyectado 39x en 164 eventos** (24% del contexto es ruido repetido) | Context drift observado |
| R3 | **Respuesta repetida verbatim** (evento 160 ≈ 58) — modelo perdió el hilo | Confirma el impacto de R2 |
| R4 | **No lead tracking** — hallazgos high-signal (`error_log 403`, `/config 301`) ignorados | Faltan como follow-up TODOs |
| R5 | **`recall_similar_experiences` solo al arranque**, no al pivotar de intent | 2ª pregunta del usuario no activó recall |
| R6 | **Reportes de prosa intercalados entre tools** consumen turnos | 4 reports intermedios antes del final |

**Conclusión:** hay que arreglar el scaffold base (R1-R6) **antes** de apilar capacidades Mythos, o el hunter 0-day heredará los mismos problemas amplificados.

---

## Plan de 5 fases

### Fase 0 — Scaffold fixes (pre-requisito)

Sin esto las fases siguientes no rinden. **3-5 días.**

| Fix | Archivo | Cambio |
|---|---|---|
| R1 | `skills/playbooks/*.md` | Añadir regla explícita: *"Continue chaining tools until all leads are exhausted OR a dead-end is confirmed. Do not produce prose reports mid-engagement — only at finalize()."* |
| R2 | `services/session_memory.py` | Re-inyectar Magic Doc **solo si cambió desde la última inyección** (hash diff). Cap hard: max 5 inyecciones/sesión. |
| R4 | `services/lead_tracker.py` **(nuevo)** | Estructura `PendingLeads[]` en session memory. Cada hallazgo ambiguo (403, 301, archivos existentes pero protegidos, errores raros) se añade. Al final de cada turn, el prompt incluye *"pending leads: …"* — fuerza al modelo a atenderlos. |
| R5 | `agents/kryon_unified.py` | Trigger `recall_similar_experiences` en cada cambio detectado de intent (nuevo verbo/objetivo en user prompt), no solo al arranque. |
| R6 | system prompt unified agent | Prohibir reports intermedios con regla dura. Definir `finalize()` como único punto para prosa extensa. |

**Verificación:** reejecutar el engagement `britimp.com.py` con el mismo prompt inicial. Target: 0 repeticiones de "continua" del usuario, `/config 301` investigado automáticamente.

---

### Fase 1 — Source-code awareness

Kryon hoy es 90% blackbox. Mythos es 100% whitebox. Necesitamos capability whitebox. **1 semana.**

**Tools nuevas en `src/kryon/tools/code/`:**

```
code/
├── git_clone_and_index.py     # clona + construye mapa archivos + stats (loc, lang)
├── read_function.py            # extrae función por nombre vía tree-sitter (C, C++, Python, JS, Go, Rust)
├── git_log_security.py         # git log --grep para patterns: CVE-, security, overflow, auth, sanitize, bounds, leak
├── git_diff_fix.py             # dado commit SHA → extrae before/after + archivos tocados
├── find_callers.py             # grep semántico de todos los call-sites (AST-aware, no solo string match)
├── code_priority_score.py      # heurística: parser/deserial/crypto/auth/network-I/O → 5, UI/logging → 1
└── run_sandboxed.py            # ejecuta PoC en container aislado con ASAN/UBSAN, devuelve crash trace limpio
```

**Dependencias nuevas:**
- `tree-sitter` + grammars (C, C++, Python, JS, Go, Rust) — parsing AST multi-lenguaje
- Container harness con `clang -fsanitize=address,undefined` preinstalado
- `gdb` / `lldb` para triage de crashes

---

### Fase 2 — Skills de caza de 0-days

Tres playbooks nuevos en `src/kryon/skills/playbooks/zero-day/`:

#### `zero-day-hunter.md`

Ciclo Hypothesize-Verify-Report estricto:

```
1. PRIORITIZE: rankear top-K funciones del repo por surface score (tool: code_priority_score)
2. HYPOTHESIZE: para top-K leer función completa, formar hipótesis EXPLÍCITA:
     - CWE-candidate (ej. CWE-787 heap overflow)
     - Input path: cómo llega input del atacante a esta función
     - Trigger: qué input específico causa el crash
     - Impact: RCE, DoS, info leak
3. VERIFY: construir PoC mínimo → run_sandboxed con ASAN
   - Si crashea con ASAN → etiqueta validada (verified_crash)
   - Si no crashea → log hipótesis descartada (alimenta learning loop como negativo)
4. TRIAGE: gdb bt + minimizar input (delta-debug)
5. REPORT: CWE + reproduction + severity (CVSS calc) + suggested patch
```

Reglas anti-alucinación:
- **Nunca reportar bug sin crash de ASAN confirmado**
- Toda hipótesis descartada va al learning loop como "pattern que parecía bug pero no lo era"

#### `variant-analysis.md`

La técnica de mejor ratio esfuerzo/resultado según Mythos:

```
Input: un CVE reciente, commit SHA de fix, o link a advisory
1. git_diff_fix → entiende QUÉ cambió y POR QUÉ
2. find_callers de la función parchada → lista de call-sites
3. Para cada call-site evaluar: ¿aplica la misma protección?
4. Los que no la aplican → candidatos a 0-day variante
5. Para cada candidato → pasar al flujo zero-day-hunter.md con hipótesis pre-formada
```

#### `fuzz-harness-gen.md`

```
Input: función pública con input atacante-controlado
Output: harness libFuzzer o AFL++ con corpus semilla, compilado y listo para ejecutar
```

---

### Fase 3 — Validator agent + orquestador paralelo (HPTSA-style)

**1 semana.**

En `src/kryon/skills/`:

#### `planner_hunter.py` — coordinador

```python
async def hunt_zero_days(target_repo: str):
    # 1. Triage del repo
    surface = await triage_agent.run(repo=target_repo)  # top-K archivos por score
    
    # 2. Dispara N hunters en paralelo (contexto aislado c/u)
    hunters = [hunter_agent.spawn(file=f, context_budget=32000) for f in surface[:N]]
    findings = await asyncio.gather(*[h.run() for h in hunters])
    
    # 3. Validator separado (sin compartir contexto con hunter)
    validated = []
    for finding in flatten(findings):
        verdict = await validator_agent.run(finding=finding, repo=target_repo)
        if verdict.real_and_interesting:
            validated.append(finding)
    
    # 4. Dedup por (file, function, CWE)
    return dedup(validated)
```

**Crítico:** el validator **no comparte contexto con el hunter** — se le pasa solo el finding y el código. Esto replica el 89% agreement de Mythos con humanos.

#### Infra nueva:
- Queue + worker pool (asyncio-based, ya tenemos paralelismo en SDK)
- Bandit/UCB scheduler para elegir qué archivo explorar siguiente según hit-rate histórico
- Resultado: agregación + ranking por severidad

---

### Fase 4 — Corpus de patrones (combustible del reasoning)

**1-2 semanas. Continuo.**

El modelo necesita ejemplos concretos, no definiciones abstractas de CWE.

**Ampliar RAG en `src/kryon/knowledge/`:**

| Scraper nuevo | Fuente | Volumen esperado |
|---|---|---|
| `scrapers/oss_fuzz.py` | OSS-Fuzz build configs + historial de bugs | ~7000 entry points, ~30K bugs históricos |
| `scrapers/cve_diffs.py` | NVD + GitHub Security Advisories + patch URLs | ~200K CVEs con diff público |
| `scrapers/writeups.py` | Project Zero, Trail of Bits, GHSL, HackerOne público | ~10K writeups detallados |
| `scrapers/cwe_examples.py` | CWE MITRE + código real GitHub (no ejemplos sintéticos) | ~1K patterns × 10 ejemplos |

**Schema CVE-with-diff:**
```json
{
  "cve": "CVE-2024-XXXX",
  "cwe": "CWE-787",
  "function_name": "parse_header",
  "file": "src/parser.c",
  "before_code": "...",
  "after_code": "...",
  "description": "...",
  "severity": 9.8,
  "commit_sha": "..."
}
```

**Uso en runtime:** durante la caza, hunter llama `recall_similar_code_pattern(function_code)` → RAG devuelve *"esto se parece a CVE-2023-XXXX (heap overflow en zlib) — chequear si length check es antes o después del alloc"*.

---

## Sprint 1 — Minimum Viable 0-day Hunter

**Scope mínimo para validar arquitectura. 2 semanas.**

Incluye:
- Fase 0 completa (scaffold fixes R1-R6)
- Fase 1 subset: `git_clone_and_index`, `read_function`, `git_log_security`, `git_diff_fix`, `run_sandboxed`
- `zero-day-hunter.md` y `variant-analysis.md`
- Validator simple (mismo modelo, contexto aislado, 1-shot)

**Criterio de éxito (experimento científico):**

Tomar un CVE reciente en proyecto C pequeño (ej. libxml2, zlib, sudo) con commit de fix público. **Dar a Kryon solo el código pre-parche** (clonar en el SHA inmediatamente anterior al fix). Sin pistas sobre el CVE.

- ✅ **PASS**: Kryon redescubre el CVE (reporta función correcta + CWE correcto + PoC que crashea con ASAN)
- ⚠️ **PARTIAL**: Reporta función correcta pero CWE incorrecto, o no logra PoC
- ❌ **FAIL**: No encuentra nada o reporta falso positivo

Propuesta inicial de benchmark: **CVE-2022-0185** (libxml2, heap overflow, ~400 LoC en la función) o equivalente.

---

## Métricas de éxito por fase

| Fase | Métrica | Baseline | Target |
|---|---|---|---|
| 0 | Turnos-usuario / engagement | ~5 (muchos "continua") | ≤ 1 |
| 0 | Magic Doc re-inyecciones / sesión | 39 | ≤ 5 |
| 0 | Leads abandonados | ~3-5 | 0 |
| 1 | Tiempo p50 a primera hipótesis vulnerable en repo 10K LoC | N/A | < 5 min |
| 2 | True-positive rate (hipótesis → crash ASAN) | N/A | ≥ 15% |
| 3 | Agreement validator vs expert | N/A | ≥ 80% |
| 4 | Relevancia de RAG recall en hunting (top-3 útil) | N/A | ≥ 60% |

---

## Riesgos y decisiones abiertas

1. **Capacidad de Gemma4 26B MoE para razonamiento sobre código complejo**: no sabemos aún si basta para variant analysis no-trivial. **Mitigación:** benchmark temprano en Sprint 1; plan B es ruta dual-model (Gemma para orquestación, Qwen2.5-Coder 32B para análisis de código).
2. **Costo de sandbox ASAN en RAM**: builds con sanitizers pesan 2-4x. Requiere host con 32GB+ si se hacen múltiples en paralelo.
3. **Falsos positivos de validator**: si el validator es del mismo modelo, confirmation bias sigue siendo riesgo. Evaluar en Fase 3 si vale usar un modelo diferente (ej. Qwen) como validator adversarial.
4. **Alcance legal**: 0-day hunting en software de terceros requiere scope whitelisting estricto. El módulo `scope/` ya existe pero necesita extensión para repos (no solo hosts).

---

## Referencias

- [Claude Mythos Preview — Anthropic Red Team](https://red.anthropic.com/2026/mythos-preview/)
- [Zero-Days — Anthropic Red Team](https://red.anthropic.com/2026/zero-days/)
- [Project Glasswing — Anthropic](https://www.anthropic.com/glasswing)
- [Teams of LLM Agents can Exploit Zero-Day Vulnerabilities (HPTSA, arXiv:2406.01637)](https://arxiv.org/abs/2406.01637)
- [zero-day-llm-ensemble — lodetomasi/GitHub](https://github.com/lodetomasi/zero-day-llm-ensemble)
- [ÆSIR — Trend Micro](https://www.trendmicro.com/en_us/research/26/a/aesir.html)
- Sesión baseline: `kryon_74732376-c180-4f40-a69d-458748efc1d4` (`britimp.com.py`, 14-abr-2026)
