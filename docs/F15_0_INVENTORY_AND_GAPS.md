# F15.0 — PCI-DSS v4 deterministic auditor: inventory + gap analysis

Fecha: 2026-04-15. Sprint: F15.0 (prep + scoping). Framework: **PCI-DSS v4.0.1**
(v4 es lo actualizado; PY banking lo adopta).

## Arquitectura objetivo (no negociable)

Separación estricta de capas:

```
[Evidence Collector] → [Deterministic Check Engine] → [Verdict (PASS|FAIL|N/A)]
     commands raw         YAML/Python rules                   ↓
                                                    [PDF generator]
                                                         ↓
                    [LLM Contextualizer]  ←  (contexto + remediation prose ONLY,
                                              never modifies verdict or evidence)
```

Regla: **LLM jamás modifica verdicts ni evidence**. Solo escribe prosa explicativa
en la sección "Contexto y Remediación" del PDF. Verdict binario + comando ejecutado
+ output raw pasan al PDF sin intermediación LLM. Esto es requisito regulatorio
para auditoría: si el LLM suaviza "FAIL" a "parcialmente cumple", es responsabilidad
civil del auditor.

## Inventario: qué existe hoy

### 1. `src/kryon/compliance/pci_dss.py` — **metadata catalog ONLY**

25 `ComplianceControl` dataclass entries con:
- id (e.g. `2.2.2`)
- title, description, category
- testing_procedures: lista de strings prose (e.g. `["Credential audit"]`)
- expected_evidence: lista de strings prose

**Plus**: `map_finding_to_pci_controls(finding)` — keyword matcher que tagea
findings producidos por nmap/semgrep con control IDs PCI.

**Esto NO es un auditor**. Es un diccionario de referencia + mapper de findings
downstream. Zero deterministic checks that query a system and return PASS/FAIL.

### 2. `src/kryon/skills/playbooks/banking/pci-dss-audit.md` — **LLM playbook**

140 líneas de shell commands organizados por requirement PCI (Req 1-12). Comandos
bien escritos (ver sección Req 4 testssl.sh / Req 3 PAN grep con Luhn validation
note). Pero: **ejecutados por el LLM**, no por un runner determinístico. El LLM
decide el orden, elige qué saltar, narra resultados.

### 3. `src/kryon/skills/playbooks/server-hardening.md` — **LLM playbook Linux**

172 líneas, cubre SSH hardening, iptables, fail2ban. Flow `diagnostico →
propuesta → apply` bien diseñado pero nuevamente LLM-driven. Los comandos de
diagnóstico son 80% portables a checks determinísticos.

### 4. Ninguna implementación determinística encontrada

Grep sobre `src/kryon/tools/` y `src/kryon/compliance/`: no hay funciones
`check_ssh_permitroot()`, `check_tls_version()`, ni YAML rule files.
Los únicos "check_/audit_" hits son en tools privesc/evasion (no compliance).

**Conclusión inventario: coverage actual de PCI-DSS v4 = 0% determinístico.
Metadata catalog + LLM playbook existen como spec/docs, no como auditor.**

## Gap matrix vs PCI-DSS v4 secciones mínimas (2, 6, 8, 10)

Gate F15: **≥80% cobertura** sobre estas 4 secciones (controles con testing
procedures concretos y accionables — requiere 1 check determinístico por control).

### Sección 2 — Secure Configurations (catálogo tiene 2 controles)

| Control | Título | Check determinístico propuesto | Estado |
|---------|--------|--------------------------------|--------|
| 2.2.2 | Vendor default accounts | MySQL root empty/default, SSH default users, SNMP `public` community | ❌ missing |
| 2.2.7 | Non-console admin encryption | SSH v2 only, no telnet listening, RDP NLA on, VNC with TLS | ❌ missing |

**Coverage S2: 0/2.**

### Sección 6 — Develop/Maintain Secure Systems (catálogo tiene 4 controles)

| Control | Título | Check determinístico propuesto | Estado |
|---------|--------|--------------------------------|--------|
| 6.2.4 | SW engineering techniques (SAST/DAST) | Evidencia: ran semgrep/nuclei + report attached | ⚠️ partial (existe semgrep wrapper, no bundled audit run) |
| 6.3.1 | Vulnerability identification | Versión OS + servicios vs NVD feed cache | ❌ missing |
| 6.3.3 | Critical patches within 1mo | `apt list --upgradable`, age of last-updated package | ❌ missing |
| 6.4.1 | Public web app protection | WAF header check, nuclei templates contra web exposed | ❌ missing |

**Coverage S6: 0.5/4.**

### Sección 8 — Authentication (catálogo tiene 3 controles)

| Control | Título | Check determinístico propuesto | Estado |
|---------|--------|--------------------------------|--------|
| 8.3.4 | Account lockout | `/etc/security/faillock.conf` presence + deny=6, PAM lockout | ❌ missing |
| 8.3.6 | Password complexity | PAM `pwquality.conf` minlen/minclass; SSH maxauthtries | ❌ missing |
| 8.4.2 | MFA for CDE | Google-Authenticator PAM module present, SSH ChallengeResponseAuth | ❌ missing |

**Coverage S8: 0/3.**

### Sección 10 — Logging & Monitoring (catálogo tiene 2 controles)

| Control | Título | Check determinístico propuesto | Estado |
|---------|--------|--------------------------------|--------|
| 10.2.1 | Audit trails | `auditd` running, `/etc/audit/rules.d/*.rules` con reglas mínimas PCI | ❌ missing |
| 10.4.1 | Daily log review | `/etc/logrotate.d/` + `logrotate -d` dry-run + rsyslog to SIEM | ❌ missing |

**Coverage S10: 0/2.**

### Total secciones 2/6/8/10

| Sección | Checks necesarios | Implementados | Coverage |
|---------|-------------------|---------------|----------|
| 2 | 2 | 0 | 0% |
| 6 | 4 | 0.5 | 12.5% |
| 8 | 3 | 0 | 0% |
| 10 | 2 | 0 | 0% |
| **TOTAL** | **11** | **0.5** | **4.5%** |

**Gap: 95.5% — sprint F15.1 build 10.5 checks para alcanzar ≥80% (gate requiere
9/11 mínimo, margen 10%).**

## F15.1 proposed work (build phase)

### Arquitectura código

```
src/kryon/compliance/checks/
├── __init__.py
├── base.py               # CheckResult dataclass (control_id, verdict, evidence_cmd, output, remediation_hint)
├── runner.py             # CheckRunner.run_all() / run_by_section()
├── section_2/
│   ├── c_2_2_2_default_accounts.py
│   └── c_2_2_7_non_console_admin.py
├── section_6/
│   ├── c_6_2_4_sast_evidence.py
│   ├── c_6_3_1_vuln_id.py
│   ├── c_6_3_3_patch_currency.py
│   └── c_6_4_1_web_protection.py
├── section_8/
│   ├── c_8_3_4_lockout.py
│   ├── c_8_3_6_password_complexity.py
│   └── c_8_4_2_mfa.py
└── section_10/
    ├── c_10_2_1_audit_trails.py
    └── c_10_4_1_log_review.py
```

Cada check file exporta `CHECK = Check(control_id=..., category=..., query_fn=...)`.
`query_fn` toma un `Target` (host, creds, os) y retorna `CheckResult`. 100% Python
puro + subprocess. Zero LLM en detection path.

### Rúbrica de CheckResult

```python
@dataclass(frozen=True)
class CheckResult:
    control_id: str
    verdict: Literal["PASS", "FAIL", "N/A", "ERROR"]
    evidence_command: str
    evidence_output: str
    evidence_parsed: dict           # key parsed from output for PDF rendering
    remediation_hint: str           # static; LLM may enrich but not modify
    duration_ms: int
```

### Gates F15.1 (pre-acordados, no mover)

1. **Framework coverage ≥80%**: ≥9/11 checks sobre secciones 2/6/8/10 implementadas y pasando smoke tests.
2. **External ground truth**: correr sobre Ubuntu 22.04 VM con config CIS-nonconforming deliberada. Comparar verdicts vs **Lynis** + **OpenSCAP** con profile `xccdf_org.ssgproject.content_profile_pci-dss`. No es competencia — es baseline de referencia. Reportar agreement rate y diffs.
3. **Reproducibility**: 3 runs back-to-back sobre mismo target deben producir output JSON byte-exact (excluding timestamps). Regulation compliance requires determinism.
4. **PDF legibility**: sample 3 findings del PDF generado, validar que non-technical reader (compliance officer, contador) entiende hallazgo y remediation. Método: prompt LLM different (opus o un non-coder) para que juzgue legibilidad + 1 review humana.

### Gate decision tree

- 4/4 gates pass → ship F15.1 y mover a F15.2 (compliance workflow integration con engage CLI).
- 3/4 pass (PDF legibility fail común) → iterate PDF template, no re-bench.
- Coverage <80% o external agreement <70% → documentar y re-scope (no declarar victoria parcial).

## Cost/effort estimate F15.1

- 11 checks × ~30 min cada = 5.5h build
- External bench setup (CIS-nonconforming VM + Lynis + OpenSCAP runs): 2h
- PDF template y legibility review: 2h
- Reproducibility harness: 1h
- **Total: ~10-12h** (1.5 sprint standard)

Si entra en budget → single sprint. Si no → F15.1a (build 6 checks minimum 3
secciones) + F15.1b (resto + external bench).

## Estratégico

Primer sprint donde el éxito técnico **no depende del techo de capacidad LLM**.
Determinismo + Python + YAML = corre en 1GB RAM. LLM opcional para cosmética del
PDF. Independiente de F11.1 negative result. Independiente de F13 engine rejection.

Pitch BCP honesto sobre esto:
> "Kryon auditor de cumplimiento PCI-DSS v4 para entornos financieros. 100%
> determinístico, on-prem, reproducible. Verdicts generados por reglas auditables
> en código abierto. Cada finding incluye comando ejecutado y output raw para
> evidencia regulatoria. La narrativa ejecutiva del reporte es opcionalmente
> asistida por LLM, pero los veredictos nunca lo son."

Ese mensaje es defensible y diferencial en el mercado LATAM donde los auditores
comerciales son caros, en inglés, y no saben que SEPRELAD existe.
