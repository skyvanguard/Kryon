# F11.1 — Tool-augmented triage sprint: **NEGATIVE, arc F10→F11 closed**

Fecha: 2026-04-15. Corpus: GnuCash @ `9f8f4d9e`. Same 50 findings as F13.2.

## Hipótesis testeada

Darle `read_function` + `read_lines` al LLM triage (qwen3-coder temp=0) sobre findings reales (C/C++ GnuCash) rescata la KEEP precision que cayó de 80% (Juliet spike F10.3-B) a 57% (real-world F13.2).

## Setup

- Modelo: qwen3-coder:30b-32k, temperature=0, top_p=1.
- Prompt: reescrito desde cero con investigate-first framing (no "baseline prompt + tools"). System prompt instruye "you MUST investigate before deciding".
- Tools: `read_function(file, line)` + `read_lines(file, start, end)`. Budget 6 calls per finding, 12-turn safety cap.
- Per-finding wall cap: 90s, timeout → KEEP (conservador).
- Seed=43 (diferente de F13.2 seed=42) para shuffle orden.
- Ground truth: mismos 50 findings labeled de F13.2 (3 TP/FP por CWE-476 = 10%, 17 TP/FP CWE-121, 3 UNK CWE-190).
- Gate: CI non-overlap vs baseline F13.2, **no** threshold absoluto.

## Validación smoke (5 findings)

Zero-tool-call rate: 0/5 (0%) ✅. Prompt induce uso de tools correctamente. Proceed.

## Resultado full run (50 findings)

### Confusion matrix

|            | TP | FP |
|------------|----|-----|
| KEEP       | 2  | 9   |
| SUPPRESS   | 6  | 26  |
| UNCERTAIN  | 0  | 1   |
| ERROR      | 0  | 1   |

### Primary gate (CI non-overlap)

| | Baseline F13.2 | F11.1 | Result |
|---|---|---|---|
| KEEP precision | 57.1% [14%, 86%] (N=7) | **18.2%** [0%, 46%] (N=11) | **FAIL** (CIs overlap + point estimate WORSE) |

### Secondary metrics

| Métrica | Baseline | F11.1 | Delta |
|---------|----------|-------|-------|
| KEEP recall (TPs preserved) | 50% (4/8) | 25% (2/8) | **-25pp worse** |
| SUPPRESS recall (FPs caught) | 73.0% | 70.3% | flat |
| UNCERTAIN rate | 22% | **2%** | -20pp (tools inducen commit) |
| Avg latency | 4.6s | 18.7s | +4× |
| Avg tool calls | 0 | 2.74 | as designed |

## Lectura — no lo esperado

La hipótesis asumía que más contexto → mejor decisión. Los datos muestran otra cosa:

**Tools hicieron al modelo overconfident, no better.**

- UNCERTAIN rate colapsó de 22% a 2%: el modelo dejó de hedgear cuando no sabía y empezó a commit equivocado.
- 6 TPs reales fueron SUPPRESSed en F11.1 (vs 1 en baseline): con tools, el modelo se "convence" a sí mismo de que bugs reales son safe después de leer más código. Anti-patrón de un auditor de seguridad.
- KEEP precision dropped 39pp. KEEP recall dropped 25pp. Ambas métricas principales worse.
- SUPPRESS recall flat — tools no ayudan a identificar FPs mejor.

El UNCERTAIN en baseline era un **safety signal implícito** (hold para revisión humana). Tools removieron ese safety sin agregar accuracy. Resultado: modelo confident-wrong en vez de uncertain-correct.

## Lo que F11.1 mata como hipótesis abierta

- **F10.3-B "LLM triage rescata engine débil"**: rechazado sobre real-world corpus. En spike curado funcionaba; sobre GnuCash, ninguna configuración (snippet-only O tool-augmented) alcanza gate.
- **F11 "tools rescatan workflow"**: rechazado. Primer sprint que lo testea con método blindado (CI + tool-usage gate + secondary metrics). Dato fuerte — ningún otro bench lo había medido.
- **Arco F10→F11 abierto desde F11.0 spike 2h cap**: cerrado negativo. No merece más trabajo sin evidencia técnica nueva (nuevo modelo, nueva framework de investigación, no solo "más tools" o "más prompt tuning").

## Patrón consolidado (4 sprints negativos)

1. **F7**: Joern 0 findings únicos vs pattern-only.
2. **F9**: pattern-only techó 47% FPR.
3. **F13**: engine precision 33%, snippet-triage 57%.
4. **F11.1**: tool-augmented triage 18% (WORSE than snippet-only).

Cuatro resultados negativos consecutivos sobre variaciones de "análisis estático + LLM mejora precision sobre C/C++ real". No es azar metodológico. **La tecnología que tenemos hoy (qwen3-coder + semgrep + CPG + Python orquestación) tiene un techo en este dominio.**

## Consecuencia para el producto

El producto NO es detección. Ya lo sabíamos desde F13 cierre. F11.1 lo confirma con datos más fuertes.

El producto ES:
- Deployment local (on-prem, sin data leakage)
- Compliance PY banking (conocimiento específico BCP/SIB/SEPRELAD)
- Workflow de auditoría (approval UX, live progress, PDF report, engage CLI)
- Integración best-of-breed (semgrep upstream + capa de orquestación)

El pitch técnico honesto a BCP:
> "Kryon integra análisis estático maduro (semgrep + reglas curadas) en un workflow de auditoría bancaria con deployment local. No competimos en detección pura — usamos lo mejor de la industria y agregamos la capa de producto que falta: compliance, reporting ejecutivo, y operación on-prem para datos regulados."

## Next — honesto

No hay siguiente sprint obvio. La pregunta ya no es técnica sobre Kryon — es de mercado:

- ¿BCP compra "deployment + workflow" sin engine diferenciado?
- ¿Los competidores (Fortify, Checkmarx, Veracode) ya cubren workflow suficientemente?
- ¿El valor único está en el conocimiento regulatorio PY, no en el software?

Esas preguntas no se resuelven con sprint técnico. Se resuelven hablando con BCP, o con otro banco LATAM, o con auditoría externa.

Cualquier sprint técnico adicional **hasta que esa conversación ocurra** arriesga ser ejecución pulida de la pregunta equivocada.
