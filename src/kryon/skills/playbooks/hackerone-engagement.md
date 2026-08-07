---
name: hackerone-engagement
description: "HackerOne bug bounty engagement flow with mandatory scope enforcement. Orchestrates program discovery → scope validation → scope-guarded web pentest → report submission with operator approval."
triggers:
  tech: ["hackerone", "h1", "bug-bounty", "bounty", "bugbounty"]
  keywords:
    - "hackerone"
    - "bugbounty"
    - "bug bounty"
    - "h1 program"
    - "cacería de bugs"
    - "programa h1"
    - "h1 submit"
    - "reportar h1"
    - "in-scope h1"
    - "scope hackerone"
priority: 10
required_tools:
  - h1_list_programs
  - h1_get_program_scope
  - h1_assert_in_scope
  - h1_list_my_reports
  - h1_submit_report
  - run_web_pentest
  # record_engagement_findings NO se expone: run_web_pentest ya auto-graba
  # los findings CONFIRMED (ver "Integración con F64" abajo). Exponer la tool
  # suelta invita al 4B a re-serializar el blob findings_json a mano — donde
  # el modelo local malforma el JSON y loopea (mismo trap que web-pentest).
  - request_approval
---

## HackerOne Engagement Flow (scope-enforced)

When the user asks to audit a HackerOne program, run a bug bounty
engagement, or submit a report, this skill coordinates the end-to-end
flow with **mandatory scope enforcement**. Probing out-of-scope =
program ban + possible legal action. You never improvise around this.

## Mandatory flow

### Step 1 — Discover available programs

```python
h1_list_programs(limit=25)
```

Returns every program the authenticated user participates in. Ask
the operator which program to engage. Never pick without confirmation.

### Step 2 — Pull program scope

```python
h1_get_program_scope(program_handle="<handle>")
```

Returns the list of `eligible_for_submission=true` assets with their
identifiers, types, max severity, and instruction notes. Show these
to the operator so they confirm the engagement target falls inside.

### Step 3 — Scope-guarded pentest

The web pentest tool accepts `hackerone_program_handle`. When set,
it validates the target URL against program scope via `is_in_scope`
BEFORE any probe fires. Out-of-scope → returns
`{"error": "BLOCKED_OUT_OF_SCOPE", ...}` with no requests sent.

```python
run_web_pentest(
    target_url="https://<in-scope-asset>",
    hackerone_program_handle="<handle>",   # MANDATORY for H1 engagements
    mode="offline",                         # reproducible + defensible
    # Add banking_context fields only if scope covers those endpoints:
    idor_template_url="...",
    idor_known_id="...",
)
```

### Step 4 — Review findings with operator

Show operator every CONFIRMED finding. For each one they want to
report, you'll generate the submission text and **require
`request_approval` sign-off on the exact text** before submission.

### Step 5 — Submit report (approval-gated)

```python
# First: generate the draft text + show to operator
# Then call request_approval(...) with the full draft
# Only proceed to h1_submit_report AFTER approved=True

h1_submit_report(
    program_handle="<handle>",
    title="<concise vulnerability title>",
    severity="high",  # one of: none | low | medium | high | critical
    vulnerability_info="<full finding description + POC URL>",
    impact="<business impact narrative — what an attacker gains>",
    steps_to_reproduce="<numbered, copy-paste reproducible steps>",
    weakness_id=0,  # optional H1 weakness id from CWE mapping
)
```

The response contains the created report id + URL on
hackerone.com/reports/<id>.

## Reglas críticas

- **NUNCA** llamar `run_web_pentest` sin `hackerone_program_handle` cuando
  el engagement es de HackerOne. El scope guard es obligatorio.
- **NUNCA** llamar `h1_submit_report` sin un `request_approval` previo
  con el texto exacto. El operador tiene que firmar la descripción
  textual — no un resumen.
- Si el operador pide probar una URL que el scope guard rechaza, **NO
  override**. Pedir que amplíen scope con el program team o que elijan
  otro asset.
- Si `HACKERONE_API_USERNAME` / `HACKERONE_API_TOKEN` faltan, las tools
  retornan un error con el link a `/settings/api` de HackerOne. No
  hardcodear credenciales; viven en `~/.kryon/secrets.env` con
  perms 600.
- Rate limit HackerOne: 600 req/min por token. Si el tool retorna "rate
  limit reached", esperar y reintentar. No bypassear.

## Severity mapping (para submit_report)

Usar OWASP + CVSS 3.1 como referencia:

| Finding class | H1 severity |
|---|---|
| RCE, authn bypass, privesc, PII dump at scale | **critical** |
| Stored XSS con escalamiento, SSRF internal, SQLi con data access | **high** |
| Reflected XSS, CSRF en state-change, open redirect con phishing | **medium** |
| Info disclosure menor, security header missing, rate-limit weak | **low** |
| Self-XSS, click-jacking en página sin acciones | **none** |

Siempre cita el CVSS score específico. Las compliance_citations del
finding (de F59) son complementarias — H1 severity manda en el submit.

## Integración con F64 pattern library

Después de cada engagement H1:

1. `run_web_pentest` auto-graba findings CONFIRMED con
   `tech_fingerprint=<stack>` + `engagement_id=<repro_hash>`.
2. Con suficientes engagements, la biblioteca se convierte en el moat
   vs XBOW: mismos patterns + regulación local + scope-aware.

## Cuando NO usar este skill

- Engagement de cliente directo (no H1) → usar `web-pentest` directamente.
- Bugcrowd / Intigriti / YesWeHack → requieren integraciones paralelas
  (F66+, TODO).
- Submission manual fuera de Kryon → el operador puede siempre usar el
  web UI de HackerOne; este skill es opcional.
