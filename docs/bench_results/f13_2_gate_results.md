# F13.2 — Gate results

Fecha: 2026-04-15. Corpus: GnuCash @ `9f8f4d9e`. Sample: 50 findings stratified por CWE.

## Engine gate (precision sobre CWE-121 + CWE-190, excl. CWE-476 known-noisy)

| Categoría | Pool | Sampled | TP | FP | UNK | Precision | 95% CI (bootstrap) |
|-----------|------|---------|----|----|-----|-----------|--------------------|
| CWE-476 null-deref | 143 | 30 | 3 | 27 | 0 | 10% | [0%, 20%] |
| CWE-121 buf overflow | 17 | 17 | 5 | 10 | 2 | 33% | [13%, 60%] |
| CWE-190 int overflow | 3 | 3 | 0 | 0 | 3 | — | all UNK |

Pooled engine N=15 TP/FP: precision point **33%**, CI **[13%, 60%]**.

**Threshold: ≥40%. Status: FAIL** (punto estimate debajo, CI lower bound muy por debajo).

## Workflow gate (TriageAnnotator qwen3-coder temp=0 sobre los 50)

Latencia total: 228s (avg 4.6s, max 19.7s). Sin filtros, serial, sin retries.

### Confusion matrix (4 cells, ground truth × triage verdict)

|              | TP (real bug) | FP (no bug) | UNK (ambig.) | Totales verdict |
|--------------|---------------|-------------|--------------|-----------------|
| KEEP         |     **4**     |    **3**    |      0       |       7         |
| SUPPRESS     |       1       |     27      |      4       |      32         |
| UNCERTAIN    |       3       |      7      |      1       |      11         |
| Totales GT   |       8       |     37      |      5       |      50         |

### Gate metrics

- **KEEP precision** = 4 / (4+3) = **57.1%**
- **SUPPRESS recall** (FPs caught by triage) = 27 / 37 = **73.0%**
- **KEEP recall** (TPs preserved) = 4 / 8 = **50.0%**
- **UNCERTAIN rate** = 11 / 50 = **22%** (LLM se abstiene)

### Distribución verdict × CWE

| CWE | KEEP | SUPPRESS | UNCERTAIN |
|-----|------|----------|-----------|
| CWE-121 | 2 | 4 | 11 |
| CWE-190 | 0 | 2 | 1 |
| CWE-476 | 5 | 25 | 0 |

Observación: **CWE-121 (engine crítico) es donde el LLM más se abstiene** (11/17 UNCERTAIN). CWE-476 tiene las decisiones más claras (25 SUPPRESS, 5 KEEP, 0 UNCERTAIN) — el patrón null-assign-deref con sentinel check es reconocible para qwen3.

## Gate decision

| Gate | Threshold | Result | Status |
|------|-----------|--------|--------|
| Engine | precision pooled ≥40% | 33% [13%, 60%] | **FAIL** |
| Workflow | KEEP precision ≥65% | **57.1%** | **MARGINAL (zona gris)** |

Per pre-acordada gate tree:

- Ambos válidos → ship F13 con dos historias. **NO.**
- Solo workflow válido → pivot "engine recall, workflow filtra". **NO** (workflow no alcanza el 65%).
- Engine marginal + workflow marginal → pivot documentado, re-scope.

**Decisión: sprint F13 insuficiente sobre GnuCash. Engine FAIL + workflow MARGINAL.**

## Lecturas accionables

1. **SUPPRESS recall 73% es señal útil** aun con KEEP precision 57%. El triage suprime 27/37 FPs correctamente. Si el pitch reframea "Kryon reduce noise 73%" en lugar de "Kryon produce KEEP bucket accionable", el workflow sigue defendible. Pero la regla original era KEEP precision y no la movemos.

2. **UNCERTAIN rate 22%** indica que qwen3-coder ante código real se abstiene en uno de cada 5 casos. En F10.3-B sobre spike los UNCERTAIN eran <5%. La complejidad del código GnuCash (GLib macros, C++ templates) degrada la discriminación del modelo.

3. **Ground-truth noise**: la verificación manual de `price_props` reveló que el labeler programático tiene error rate ~1/3 en CWE-476 TP (mis `if ($P)` regex no agarraron patrones `std::tie`, structured bindings, out-param reassignment). El 10% CWE-476 precision reportado puede ser en realidad 5-15%. El 33% CWE-121 tiene una incerteza similar en ±10pp por ruido humano. F13.2 limitation documentada.

4. **Hipótesis F10.3-B "LLM triage rescata engine débil" queda descartada sobre corpus real**. En spike curado funcionaba (SUPPRESS precision 75%, KEEP precision 80%). Sobre código GnuCash real, KEEP precision cae a 57%. La arquitectura actual no escala del micro-corpus al macro-corpus.

## Next — re-scope options

1. **Opción A**: cerrar F13 sprint negativo, documentar, redirigir a F14 "engine refactor Java" (aportaría ruleset nuevo sobre Fineract — que semgrep ya ganó).
2. **Opción B**: re-scope F13 sobre otro corpus C/C++ con engine menos noisy — p.ej. librería más chica y parser-heavy donde null-deref rule no domine. zlib, libxml2, cjson.
3. **Opción C**: cerrar F13 con PDF demo que muestre HONESTAMENTE: "engine no alcanza gate, workflow zona gris, no lo vendemos como ship-ready. Aprendizajes para F14." Útil como artefacto interno, NO como pitch BCP.

Mi voto: **C** (documentar honesto) + **A en paralelo** (F14 engine Java como próximo sprint — ese sí tiene chance de diferenciarse en Fineract).

Fineract reformat (F13.1 cierre): hacer como closing. 15 min, ningún gate adicional involucrado, deja el sprint con ambos corpuses tratados aunque la decisión sea no-ship.
