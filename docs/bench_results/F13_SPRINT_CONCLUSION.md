# F13 — Banking bench sprint conclusion

Fecha: 2026-04-15. Corpus pineados: Apache Fineract `60acf858` (262K Java LoC) + GnuCash `9f8f4d9e` (435K C/C++ LoC).

## TL;DR

**Engine-as-differentiator hypothesis rejected.** Three sprints (F7, F9, F13) produced consistent negative evidence. F13 specifically:

- Engine precision sobre C/C++ real (excl. known-noisy CWE-476): **33%** (CI [13%, 60%]), gate ≥40% **FAIL**.
- Workflow (qwen3-coder triage temp=0, snippet-only) KEEP precision: **57%**, gate ≥65% **FAIL** (zona gris).
- Sobre Fineract (Java): Kryon engine == vanilla semgrep (no custom Java rules, SemgrepHunter hardcoded C). No lift posible.

**Product pivot**: no vendemos "mejor engine". Vendemos local deployment + compliance + workflow + experiencia PY banking.

## Per-sprint gates

| Sprint | Claim tested | Result | Verdict |
|--------|-------------|--------|---------|
| F13.0 | Corpus+baseline reproducible | pineado + CVE list + semgrep baseline | ✅ |
| F13.1 | Kryon scan produces findings | 163 GnuCash (Kryon engine) vs 2 (semgrep raw) | ✅ output |
| F13.2 engine | precision ≥40% pooled | 33% [13%, 60%] | ❌ FAIL |
| F13.2 workflow | KEEP precision ≥65% | 57% (MARGINAL, gate no alcanza) | ❌ FAIL |
| F13.3 | comparator table | dos lentes producidas | ✅ |
| F13.4 | ship decision | **no-ship F13 como "better engine"** | ✅ honest |

## El patrón que F13 reveló

Tres sprints consecutivos negativos sobre la hipótesis "engine propietario le gana a semgrep":

1. **F7**: Joern CPG aportó 0 findings únicos vs pattern-only.
2. **F9**: pattern-only techó en 47% FPR sobre corpus real.
3. **F13**: engine GnuCash precision 33%, Fineract Java == semgrep upstream.

Si la misma hipótesis falla tres veces, la cuarta necesita **evidencia nueva**, no otro sprint del mismo tipo. F14 "Kryon Java engine" queda en **backlog sin fecha** — sin razón técnica nueva no merece sprint.

## El otro hallazgo — domain shift del triage

Workflow precision:
- Juliet spike (F10.3-B): KEEP precision **80%**, UNCERTAIN <5%
- GnuCash real (F13.2): KEEP precision **57%**, UNCERTAIN **22%**

No es tuning — es **domain shift**. qwen3-coder con snippet-only no discrimina sobre código real con GLib macros, C++ templates, out-param patterns, structured bindings. El UNCERTAIN 22% confirma que el modelo sabe que no sabe.

## Next candidate sprint — F11 tool-augmented triage

Hipótesis: darle al LLM `read_function()` + `read_lines()` sobre GnuCash rescata workflow precision al permitir que explore contexto más allá del snippet.

Gate F11 completion:
- Re-triage los mismos 50 findings con context tools activos.
- KEEP precision ≥65% sobre los 50 con ground truth existente.
- Pass → workflow story vive (pitch "engine noisy + context-aware workflow filtra").
- Fail → producto real está en deployment + compliance, no en análisis.

F11 ya tiene spike parcial (F11.0 tool-augmented spike 2h cap). No es sprint nuevo — es cerrar el arco F10-F11 que quedó abierto.

**No se arranca F11 sin pausa de 1 día** para replantear qué se vende a BCP. Esa conversación es el gate real antes de más trabajo técnico.

## Artefactos F13

Ubicación: `docs/bench_results/` + `scripts/f13/`.

- `f13_fineract_raw.jsonl` — 28 findings semgrep Java (= Kryon engine Java actual)
- `f13_gnucash_raw.jsonl` — 163 findings Kryon engine C/C++
- `f13_gnucash_labeled.jsonl` — 50 findings con TP/FP ground truth
- `f13_gnucash_triaged.jsonl` — 50 findings con verdict qwen3 temp=0
- `f13_gnucash_precision.md` — per-category precision + bootstrap CI
- `f13_2_gate_results.md` — confusion matrix + decisión
- `F13_0_SETUP.md` — corpus pin + CVE list + baseline (sprint framing)
- `F13_SPRINT_CONCLUSION.md` — este documento

## Decisión ejecutiva

F13 cierra como **sprint negativo documentado**. No como pitch BCP.

El pitch BCP se construye sobre:
- Deployment local (on-prem RTX 3090, sin datos a tercero)
- Compliance PY banking (BCP/SIB/SEPRELAD conocimiento específico)
- Workflow (approval UX, live progress, PDF report, engage CLI)
- Experiencia dominio (no "mejor static analyzer que semgrep")

El mensaje técnico honesto: "Kryon integra best-of-breed (semgrep + triage LLM + custom rules) sobre deployment y workflow diseñados para auditoría bancaria LATAM. Engine propietario C/C++ en desarrollo, Java actualmente via semgrep upstream."
