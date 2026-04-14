# F3 Implementation Plan — Planner-Hunter con Validator aislado

> **Target:** Kryon v2.2.0 "Swarm"
> **Duración estimada:** 1 semana
> **Baseline VRAM:** RTX 5070 Ti Laptop — **12 GB total** (11 GB libre en idle)
> **Modelo actual:** `gemma4:26b-32k` (17 GB en disco, partial offload)

---

## 1. Contexto y dependencias

### Input que consumimos

- **Mythos (Anthropic, abr 2026):** ciclo hypothesize→verify→report con validator separado. 89% agreement con humanos. Fuente del "no contexto compartido entre hunter y validator".
- **ARTEMIS (Stanford/CMU, dic 2025):** supervisor + sub-agent swarm, dynamic prompt generation, TODO recursivo pre-planner, smart summarization (horizon 16h), triage de 3 fases. 2º lugar contra 10 pentesters profesionales.
- **F0+F1+F2 ya en main:** scaffold fixes + 7 tools de código + 3 playbooks zero-day. Benchmark `bench_zlib_oob.py` pasa 6/6.

### Lo que F3 añade

- Un **coordinador** (`planner_hunter`) que descompone un objetivo en sub-tareas y dispatches N hunters.
- Un **validator aislado** que confirma hallazgos SIN ver el contexto del hunter (kill confirmation bias).
- Parallelism **bounded** (no ilimitado) para respetar la realidad de 12 GB VRAM.
- **Dynamic prompt generation** y **smart summarization** para extender horizon.

---

## 2. Restricción VRAM — el diseño cambia por esto

### Realidad física

| Modelo | Disco | VRAM al correr | Concurrencia posible |
|---|---|---|---|
| `gemma4:26b-32k` (MoE) | 17 GB | 8-10 GB (partial offload) | 1 instancia |
| `qwen2.5-coder:7b-q4` | ~5 GB | 5 GB | coexiste con gemma4 solo con swap |
| `deepseek-coder:6.7b-q4` | ~4 GB | 4 GB | coexiste con gemma4 solo con swap |

**No podemos co-hostear gemma4 + un validator 7B en 12 GB.** Ollama hace LRU eviction cuando cambia el modelo. Un swap cuesta ~3-5s de carga desde disco.

### Tres estrategias de VRAM (elegimos 1 + fallback)

**A) Single-model con context isolation** *(recomendada para MVP)*
- Hunter y validator usan `gemma4:26b-32k`, pero con **historiales separados** y **system prompts distintos**.
- Mythos indica que el contexto separado importa MÁS que el modelo distinto.
- Ventaja: 0 overhead, nada que descargar, funciona con 12 GB.
- Riesgo: confirmation bias reducido pero no eliminado.

**B) Dual-model con swap disciplinado** *(upgrade post-MVP)*
- Hunter: `gemma4:26b-32k`. Validator: `qwen2.5-coder:7b` o similar.
- Ollama swap automático (LRU). Penalty ~3-5s por handoff, amortizado sobre engagements largos.
- Requiere `ollama pull qwen2.5-coder:7b-instruct-q4_K_M` (~5 GB disco).
- Activable por env: `KRYON_VALIDATOR_MODEL=qwen2.5-coder:7b`.

**C) API-backed validator** *(solo si usuario tiene API key)*
- Hunter local (gemma4), validator vía Anthropic/OpenAI API.
- Mejor calidad de validator, sin costo VRAM, pero rompe el "runs locally, zero cost".
- Opt-in: `KRYON_VALIDATOR_BACKEND=anthropic` con fallback a A si no hay key.

**Decisión:** **F3 ships con A por default**, B y C como flags opcionales. Empezamos simple.

### Parallelism real vs aparente

Ollama serializa inferencia por modelo (`OLLAMA_NUM_PARALLEL=1` es default). Dos hunters "paralelos" comparten la misma cola de inferencia.

**Lo que sí paraleliza sin VRAM extra:**
- Tool execution (git ops, compilaciones ASAN, filesystem) — CPU/disk bound
- Mientras hunter A corre `run_sandboxed` (compile + run, sin modelo), hunter B puede hacer inference
- Gain empírico esperado: 30-50% throughput vs sequential

**Lo que exige más VRAM:**
- `OLLAMA_NUM_PARALLEL=2+` duplica KV cache → +2-4 GB VRAM por slot extra
- Con 11 GB libre, podemos probar `NUM_PARALLEL=2` para el hunter, pero no más

**Default F3:** `KRYON_HUNTER_PARALLELISM=2`, `OLLAMA_NUM_PARALLEL=1` (conservador).

---

## 3. Arquitectura F3

```
                        ┌─────────────────────────┐
 User prompt ──────────▶│  planner_hunter         │
                        │  (supervisor agent)     │
                        │                         │
                        │  1. build TODO[] list   │
                        │  2. generate per-file   │
                        │     dynamic prompts     │
                        │  3. spawn hunters       │
                        │  4. aggregate + dedup   │
                        └──────────┬──────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
     ┌───────────────┐    ┌───────────────┐    ┌───────────────┐
     │  hunter #1    │    │  hunter #2    │    │  hunter #N    │
     │  (isolated    │    │  (isolated    │    │  (isolated    │
     │   context)    │    │   context)    │    │   context)    │
     │               │    │               │    │               │
     │  file: A.c    │    │  file: B.c    │    │  file: X.c    │
     │  H→V cycle    │    │  H→V cycle    │    │  H→V cycle    │
     └───────┬───────┘    └───────┬───────┘    └───────┬───────┘
             │                    │                    │
             └──── findings ──────┼────────────────────┘
                                  ▼
                        ┌─────────────────────────┐
                        │  validator agent        │
                        │  (isolated context,     │
                        │   3-phase triage)       │
                        │                         │
                        │  phase 1: relevance     │
                        │  phase 2: reproduce     │
                        │  phase 3: classify      │
                        └──────────┬──────────────┘
                                   │
                                   ▼
                        ┌─────────────────────────┐
                        │  final report bundle    │
                        │  (only confirmed bugs)  │
                        └─────────────────────────┘
```

---

## 4. Tareas F3 (9 items con dependencias)

### F3.1 — Supervisor tools (2 días)

**Archivo:** `src/kryon/skills/supervisor_tools.py`

Ports de ARTEMIS supervisor API. Siete herramientas:

```python
spawn_hunter(file_path, hypothesis_hint, cwe_candidate) -> hunter_id
terminate_hunter(hunter_id, reason) -> None
send_followup(hunter_id, nudge) -> None
write_supervisor_note(key, content) -> None
read_supervisor_notes() -> dict
update_supervisor_todo(todo_list) -> None
read_supervisor_todo() -> list
```

Internamente: `HunterPool` de asyncio que mantiene hasta `KRYON_HUNTER_PARALLELISM` hunters activos. Queue FIFO cuando está lleno.

**Entrega:** tests unitarios con hunters mock (return findings after sleep). Verifica que pool respeta el cap.

### F3.2 — Dynamic prompt generator (1 día)

**Archivo:** `src/kryon/skills/dynamic_prompt.py`

Template ARTEMIS: "aquí está el archivo X, aquí las funciones top, aquí los patterns dangerosos encontrados, aquí un CWE candidato — formula tu hipótesis y verifica". Evita que el hunter lea contexto irrelevante.

```python
def generate_hunter_prompt(
    file_path: str,
    priority_evidence: dict,   # output de code_priority_score
    cwe_hint: str = None,      # si viene de variant-analysis
    parent_cve: str = None,
) -> str: ...
```

**Entrega:** 5 prompts generados contra las top-5 files de zlib (smoke test). Cada uno <= 2000 tokens.

### F3.3 — Planner agent (2 días)

**Archivo:** `src/kryon/skills/planner_hunter.py`

El coordinador. Implementa el loop:

```python
async def hunt_zero_days(repo_url, budget_hunters=10, timeout_s=3600):
    # 1. Clone + index + priority score
    idx = git_clone_and_index(repo_url)
    scored = code_priority_score(idx['repo_path'])

    # 2. Build TODO list (ARTEMIS-style)
    todos = build_todo_list(scored.top[:budget_hunters])
    update_supervisor_todo(todos)

    # 3. Spawn hunters in controlled parallel
    findings = []
    async with HunterPool(max_active=KRYON_HUNTER_PARALLELISM) as pool:
        for todo in todos:
            prompt = generate_hunter_prompt(todo.file, todo.evidence)
            hunter_id = await pool.spawn(prompt)
            # when hunter calls finished, collect its findings
            results = await pool.await_result(hunter_id)
            findings.extend(results)

    # 4. Hand findings to validator (phase 5)
    confirmed = await validator_agent.triage_batch(findings, repo=idx['repo_path'])

    # 5. Dedup + rank + report
    return dedup_by_file_function_cwe(confirmed)
```

**Entrega:** `kryon hunt-zero-days <repo_url>` CLI command, end-to-end runnable (con hunters mock al principio).

### F3.4 — Validator agent de 3 fases (2 días)

**Archivo:** `src/kryon/skills/validator_agent.py` + `src/kryon/skills/playbooks/validator.md`

ARTEMIS-style triage, contexto aislado:

```python
class ValidatorAgent:
    def __init__(self, model: str = None):
        # model override — si None, usa KRYON_VALIDATOR_MODEL o KRYON_MODEL
        self.model = model or os.environ.get("KRYON_VALIDATOR_MODEL", os.environ.get("KRYON_MODEL"))
        # FRESH context — no historia del hunter, solo finding + repo
        self.agent = create_agent(
            name="Validator",
            instructions=VALIDATOR_SYSTEM_PROMPT,
            tools=[read_function, find_callers, run_sandboxed, git_diff_fix],
        )

    async def triage_one(self, finding) -> Verdict:
        # Fase 1: relevance — ¿el crash es del código target, o del harness?
        r1 = await self._relevance_check(finding)
        if not r1.ok: return Verdict(rejected=True, phase="relevance", reason=r1.reason)

        # Fase 2: reproduction — re-ejecutar desde cero, sin contexto previo
        r2 = await self._reproduce(finding)
        if not r2.crashed: return Verdict(rejected=True, phase="reproduction", reason="no crash on reproduction")

        # Fase 3: classification — CWE correcto, severity, exploit chain plausible
        r3 = await self._classify(finding, r2.crash_trace)
        return Verdict(
            confirmed=True,
            cwe=r3.cwe,
            severity=r3.severity,
            summary=r3.summary,
            reproduction_poc=r2.minimal_input,
        )
```

El prompt del validator tiene 1 regla cardinal: **"No tienes el contexto del hunter. Evalúa el finding como si lo vieras por primera vez. Si faltan detalles para confirmar, rechaza con `phase=insufficient_data`."**

**Entrega:** tests con findings sintéticos (real + hallucinated). Target: rechazar 100% de hallucinated, aceptar ≥90% de real.

### F3.5 — Smart summarization / session splits (1 día)

**Archivo:** extensión en `src/kryon/services/micro_compact.py`

Cuando un hunter emite `finished`, su historial se compacta antes de que el supervisor lea el resultado:

```python
def compact_hunter_session(messages: list[dict], keep_last_n: int = 5) -> list[dict]:
    # Mantener: prompt inicial, últimos N turns, todos los findings confirmados
    # Descartar: tool outputs completos (ya procesados), hipótesis descartadas (solo nombres)
    ...
```

Esto extiende el horizon efectivo del supervisor de <2h a ≥16h (ARTEMIS claim).

**Entrega:** benchmark — 1 engagement largo (libxml2, 30+ archivos) sin OOM ni degradación de coherencia.

### F3.6 — Deepening heuristic (1 día)

**Archivo:** extensión en `skills/playbooks/zero-day-hunter.md`

Antes de emitir finding, el hunter DEBE intentar al menos 1 escalation step:

- Heap OOB read → intentar leak (ASAN report incluye info filtrada?)
- Heap OOB write → intentar controlar flow (return hijack plausible?)
- UBSan integer overflow → propagar a un path que usa el valor para alloc/index

Si la escalation falla, el finding se reporta con severity un nivel menor. Si funciona, bump severity.

**Entrega:** regla explícita añadida al playbook + test contra el zlib OOB (escalation debe detectar que el OOB read es de bytes adyacentes al window, info leak probable).

### F3.7 — Validator VRAM swap opcional (1 día)

**Archivo:** `src/kryon/services/model_swapper.py`

Wrapper sobre Ollama para forzar eviction controlada. Cuando el validator se invoca y `KRYON_VALIDATOR_MODEL != KRYON_MODEL`:

1. Señal a Ollama de descargar el hunter model (`ollama stop gemma4:26b-32k`)
2. Lanzar inferencia en validator model (auto-load)
3. Tras validator, re-cargar hunter model proactivamente si hay más hunters en cola

Penalty: ~3-5s por swap. Solo se activa si `KRYON_DUAL_MODEL=true`.

**Entrega:** smoke test midiendo overhead real. Si > 15s por swap, abortar la estrategia dual-model.

### F3.8 — REPL command `/hunt` (0.5 día)

**Archivo:** `src/kryon/repl/commands/hunt.py`

```
/hunt <repo_url> [--parallel N] [--budget K] [--validator-model M]
/hunt status                    # ver hunters activos
/hunt stop <hunter_id>          # matar uno
/hunt report                    # último bundle de findings
```

Permite al usuario controlar el swarm interactivamente sin escribir prompts.

### F3.9 — Benchmark extendido (1 día)

**Archivo:** `scripts/bench_f3_libxml2.py`

Upgrade de `bench_zlib_oob.py`. Ahora contra libxml2 en un SHA con ≥3 CVEs públicos (ej. pre-2024 state). Mide:

- Tiempo total con `parallelism=1` vs `parallelism=2` vs `parallelism=4`
- VRAM peak (via `nvidia-smi --query-gpu=memory.used --loop=1`)
- True-positive rate (confirmados vs findings totales)
- Validator agreement vs manual review

**Criterio de éxito:**
- Redescubre ≥1 CVE real
- TP rate ≥ 30%
- No OOM en `parallelism=2`
- Swap dual-model (si activado) overhead < 10% del tiempo total

---

## 5. Configuración — nuevas env vars

```bash
# Parallelism (conservador por 12GB VRAM)
KRYON_HUNTER_PARALLELISM=2

# Validator model (single-model por default)
KRYON_VALIDATOR_MODEL=gemma4:26b-32k        # same as hunter
# KRYON_VALIDATOR_MODEL=qwen2.5-coder:7b    # dual-model (opt-in)

# Dual-model swap (solo si distinto al hunter)
KRYON_DUAL_MODEL=false

# Budget por hunt
KRYON_HUNT_MAX_HUNTERS=10
KRYON_HUNT_TIMEOUT_S=3600

# Ollama parallelism (requiere más VRAM — default 1)
OLLAMA_NUM_PARALLEL=1
```

---

## 6. Orden de ejecución sugerido

```
F3.1 supervisor_tools        ──┐
                               ├─▶ F3.3 planner_hunter ──┐
F3.2 dynamic_prompt          ──┘                          │
                                                          ├─▶ F3.8 REPL /hunt ──▶ F3.9 bench
F3.4 validator_agent  ───────────────────────────────────┤
                                                          │
F3.5 smart_summarization  ───────────────────────────────┤
                                                          │
F3.6 deepening_heuristic  ───────────────────────────────┘
                                                          │
F3.7 model_swapper (opt-in)  ───────── activable cuando F3.4 estable
```

**Paralelizable:** F3.1/F3.2 son independientes. F3.4/F3.5/F3.6 también. El bloqueo principal es F3.3 → F3.8/F3.9.

---

## 7. Riesgos + mitigaciones

| Riesgo | Probabilidad | Impacto | Mitigación |
|---|---|---|---|
| Gemma4 26B no puede actuar como supervisor coherente durante 30+ turns | Media | Alta | F3.5 smart summarization; fallback a session splits cada 10 turns |
| Parallel hunters colapsan Ollama queue, tiempos peor que sequential | Media | Media | Benchmark F3.9 lo mide; si pasa, cap automático a parallelism=1 |
| Validator same-model no aporta (confirmation bias persiste) | Alta | Media | F3.4 incluye prompt adversarial ("busca razones para rechazar"); F3.7 habilita dual-model como plan B |
| Swap dual-model > 15s por transición | Baja | Alta | F3.7 aborta estrategia; stays en single-model |
| OOM al cargar gemma4:26b-32k con `OLLAMA_NUM_PARALLEL=2` | Alta | Media | Default queda en 1; parallelism real viene de overlap de tool execution no de inference |

---

## 8. Entregables verificables al final

- [ ] `kryon hunt-zero-days https://github.com/madler/zlib` ejecuta end-to-end sin intervención
- [ ] Valida ≥1 crash con ASAN, pasa por validator aislado, produce finding bundle
- [ ] `scripts/bench_f3_libxml2.py` corre y publica métricas (TP rate, tiempo, VRAM peak)
- [ ] 0 OOM eventos en un engagement de 30+ archivos
- [ ] Documentación en `docs/ZERO_DAY_ROADMAP.md` actualizada con F3 completo

---

## 9. Lo que F3 NO hace (queda para F4/F5)

- **Corpus RAG enriquecido** (OSS-Fuzz, CVE-diffs, writeups) → F4
- **tree-sitter real** para AST en vez de regex → F5
- **Fuzzing integration** (libFuzzer persistente) → F5
- **Multi-repo parallel hunts** → fuera de scope MVP
- **Exploit generation** (shellcode, ROP chains) → explícitamente fuera — el hunter reporta bugs, no los weaponiza

---

## 10. Métricas de éxito

| Métrica | Baseline (MVP actual) | Target post-F3 |
|---|---|---|
| Tiempo hunt repo ~10K LoC | N/A (LLM-serial manual) | < 30 min con parallel=2 |
| True-positive rate | estimado ~15% (Mythos base) | ≥ 30% (con validator) |
| Hallucinated findings rechazados | 0% (sin validator) | ≥ 90% (con validator) |
| Validator agreement vs expert | N/A | ≥ 80% (target ARTEMIS) |
| VRAM peak durante hunt | N/A | ≤ 11 GB (single-model) |
| Horizon efectivo | ~2h | ≥ 8h (con smart summarization) |

---

**Listo para arrancar con F3.1 + F3.2 en paralelo (son independientes).**
