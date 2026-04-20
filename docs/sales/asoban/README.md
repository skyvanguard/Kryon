# Kryon para Banca — Paquete de Incorporación (ASOBAN)

Paquete comercial para iniciar engagements con bancos miembros de
ASOBAN y entidades supervisadas por el BCP Paraguay. Orientado a la
conversación con el CISO, el CTO y el oficial de cumplimiento.

## Contenido

| Documento | Destinatario | Propósito |
|---|---|---|
| [01_propuesta_ejecutiva.md](01_propuesta_ejecutiva.md) | C-level / Comité de Riesgo | Propuesta de valor en 2 páginas |
| [02_cuestionario_alcance.md](02_cuestionario_alcance.md) | CISO + CTO | Relevamiento pre-engagement |
| [03_sow_plantilla.md](03_sow_plantilla.md) | Legal + Compras | Plantilla de Statement of Work |
| [04_coverage_regulatorio.md](04_coverage_regulatorio.md) | Oficial de Cumplimiento | Matriz de cobertura BCP/SIB/SEPRELAD/PCI/SWIFT |
| [05_faq_ciso.md](05_faq_ciso.md) | CISO | Preguntas frecuentes sobre seguridad, datos, modelo LLM local |
| [06_nda_plantilla.md](06_nda_plantilla.md) | Legal | Acuerdo de confidencialidad (jurisdicción PY) |

## Flujo recomendado de venta

```
1. Llamada inicial (30 min)
   → Entregar 01_propuesta_ejecutiva.md + 04_coverage_regulatorio.md

2. Si hay interés, reunión técnica con CISO (1 h)
   → Completar 02_cuestionario_alcance.md durante la reunión
   → Entregar 05_faq_ciso.md como material de apoyo

3. NDA firmado (antes de cualquier dato técnico)
   → 06_nda_plantilla.md ajustado a la razón social del banco

4. SOW firmado (objeto del contrato)
   → 03_sow_plantilla.md con alcance, precio, plazos, cláusulas

5. Kick-off técnico
   → Se inicia engagement bajo el flujo operacional de Kryon
     (ver docs/operations/engagement-playbook.md)
```

## Generación automática del one-pager

Para producir un PDF ejecutivo con la cobertura actualizada:

```bash
python scripts/sales/generate_asoban_onepager.py \
  --cliente "Banco Ejemplo S.A." \
  --output reports/asoban-onepager-banco-ejemplo.pdf
```

El script lee el inventario real de frameworks registrados
(`src/kryon/compliance/cis/frameworks/`) y genera un PDF con:

- Datos del prospecto
- Matriz de cobertura por framework (número de controles, CRITICAL)
- Referencias cruzadas a BCP PY Res. 12/2021
- Propuesta de alcance recomendada por perfil de banco

## Uso ético

Este paquete es para contacto comercial formal con bancos. Nunca
enviar spam, nunca usar en listas frías compradas, nunca incluir
datos reales de otros clientes como referencia sin autorización
escrita.
