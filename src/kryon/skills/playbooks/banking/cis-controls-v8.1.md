---
name: cis-controls-v8.1
description: "CIS Critical Security Controls v8.1 — crosswalk audit (AUTO via existing checks) + MANUAL governance safeguards"
triggers:
  tech: []
  ports: [22, 443, 8443]
  keywords:
    - "cis controls"
    - "cis control"
    - "cis v8"
    - "cis v8.1"
    - "cis 8.1"
    - "critical security controls"
    - "controles criticos"
    - "controles críticos"
    - "salvaguarda"
    - "salvaguardas"
    - "implementation group"
    - "ig1"
    - "ig2"
    - "ig3"
priority: 24
required_tools:
  - run_compliance_audit
  - generate_compliance_pdf
  - run_command
pre_hooks:
  - tool: run_compliance_audit
    args:
      framework: cis-controls
      host: "{ctx.host}"
      ssh_user: "{ctx.ssh_user}"
      ssh_key_path: "{ctx.ssh_key_path}"
    inject_as: cis_controls_crosswalk_findings
    required: true
    timeout_s: 240
---

## Qué es y qué NO es

**CIS Critical Security Controls v8.1** (marzo 2026): **18 controles / 153
salvaguardas**, organizados por Implementation Group (IG1 56 · IG2 74 · IG3 23)
y por función de seguridad NIST CSF 2.0 (Govern · Identify · Protect · Detect ·
Respond · Recover). v8.1 agregó sobre v8 la función **Govern** (25 salvaguardas)
y la clase de activo **Documentation** (23 salvaguardas).

> No confundir con los **CIS Benchmarks** (hardening por tecnología:
> `cis-ubuntu-22.04-l1`, etc.). Eso es otra cosa y vive en `cis/frameworks/`.

## Cómo lo audita Kryon (AUTO vs MANUAL — honestidad regulatoria)

CIS Controls es ~mitad gobierno/proceso. Kryon **NO** finge auditar lo que no
puede medir:

- **AUTO** — ~32 salvaguardas técnicas se verifican de forma determinista
  reutilizando los checks que Kryon ya corre (PCI numéricos, AD-, FGT-, PVE-,
  UNF-, WIN-, TOMCAT-, VOIP-, OT) vía el crosswalk
  `compliance/cis/cis_controls_crosswalk.py`. Veredicto fail-closed: cualquier
  check FAIL mapeado ⇒ la salvaguarda es FAIL.
- **MANUAL** — el resto (función Govern, awareness/training, incident response,
  service-provider management, pentest program) sale como `MANUAL` y **requiere
  evidencia de entrevista / revisión documental**. Nunca presentarlas como
  "PASS".

Controles con cobertura AUTO hoy: 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16.
Controles 100% MANUAL: 1 (inventario), 2 (software inv.), 14 (awareness),
15 (proveedores), 17 (IR), 18 (pentest program).

## Ejecución

```bash
# Crosswalk audit (corre todos los checks deterministas una vez y los agrega
# a las 153 salvaguardas). Reproducibility-hashed.
run_compliance_audit(framework="cis-controls", host=..., ssh_user=..., ssh_key_path=...)

# Reporte PDF (matriz AUTO/MANUAL por IG + función)
generate_compliance_pdf(framework="cis-controls", host=..., client_name="...")
```

Aliases aceptados: `cis-controls`, `cisc`, `cis8`, `cis8.1`, `cis-v8.1`.

## Scoping por Implementation Group

- **IG1 (56 salvaguardas)** — higiene básica esencial. Punto de partida para
  cualquier organización. La mayoría del valor AUTO de Kryon cae acá.
- **IG2 (+74)** — organizaciones con equipos de IT/seguridad dedicados.
- **IG3 (+23)** — organizaciones con exposición/recursos para amenazas
  avanzadas (incluye pentest interno, red team, etc.).

Para un banco, definir el IG objetivo con el cliente antes de scoping; el
reporte muestra el IG de cada salvaguarda para priorizar.

## Cómo narrar los resultados

1. Listar primero los **AUTO FAIL** (con el `evidence_checks` que los respalda).
2. Resumir la cobertura: cuántas AUTO PASS / FAIL / N/A y cuántas MANUAL.
3. Para las MANUAL, ofrecer el checklist de evidencia (entrevista + documentos),
   NUNCA marcarlas como cumplidas sin evidencia del cliente.
4. Mapear cada AUTO FAIL a su función NIST CSF 2.0 e IG para priorizar.

## Estado

`production-capable (subset AUTO)` + `template (governance/MANUAL)`. El catálogo
de 153 salvaguardas se extrae del PDF oficial español y se valida 18/18 contra
las tablas de IG (`scripts/extract_cis_controls_v81.py`). El crosswalk es
conservador (precisión sobre recall): se omite un mapeo antes que forzar uno
débil.
