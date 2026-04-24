# Sales Kit — BritImp × Kryon

Material comercial completo para la presentación a directivos de BritImp y
engagements posteriores. Todo en markdown / CSV para que podás editar, imprimir
o convertir a PDF según necesites.

## Qué contiene

| Archivo | Uso | Cómo exportar |
|---|---|---|
| [`PITCH_DECK_BRITIMP.md`](./PITCH_DECK_BRITIMP.md) | 20 slides para proyectar el lunes | Copiá a Google Slides, Keynote o usá `marp CLI` para HTML |
| [`PRICING_SHEET.md`](./PRICING_SHEET.md) | Tarifario Cloud + Local (PYG/USD) | Pandoc → PDF · o imprimí directo desde VS Code markdown preview |
| [`COMPARATIVE_ONE_PAGER.md`](./COMPARATIVE_ONE_PAGER.md) | 1 página vs. competencia | Print-to-PDF desde Chrome · A4 doble faz a color |
| [`FINANCIAL_MODEL.csv`](./FINANCIAL_MODEL.csv) | Proyección 3 años con sensibilidades | Abrir en Excel / Google Sheets / Numbers |

Y el runbook de demo ejecutable:

- [`../DEMO_SCRIPT_BRITIMP.md`](../DEMO_SCRIPT_BRITIMP.md) — 15 min de guión
  literal para la reunión, incluye FAQ y fallbacks.

## Orden recomendado para el lunes

1. **Viernes/sábado** — leer `PITCH_DECK_BRITIMP.md` end-to-end. Armar slides
   en Google Slides (te toma ~90 min con los screenshots del dashboard).
2. **Sábado** — correr la demo completa 2 veces con el `DEMO_SCRIPT_BRITIMP.md`.
   Cronometrá. Ajustá pacing.
3. **Domingo mañana** — grabar video backup de 3 min con OBS por si falla la
   demo en vivo el lunes.
4. **Domingo tarde** — imprimir `PRICING_SHEET.md`, `COMPARATIVE_ONE_PAGER.md`
   y 1 copia del caso de estudio F48. Llevá 3 copias de cada uno.
5. **Domingo noche** — exportar `FINANCIAL_MODEL.csv` a Google Sheets y
   verificar fórmulas si querés presentarlo en reunión de seguimiento.
6. **Lunes 08:00** — `docker compose up`, Chrome fullscreen en localhost:3000,
   login con admin@kryon.py. Probá las 6 pantallas.
7. **Lunes en reunión** — seguí `DEMO_SCRIPT_BRITIMP.md` palabra por palabra.

## Cómo convertir markdown a PDF bonito

```bash
# Opción 1: Pandoc (mejor calidad tipográfica)
pandoc docs/sales/PRICING_SHEET.md -o pricing.pdf \
  --pdf-engine=xelatex -V geometry:margin=1in

# Opción 2: Marp CLI (mejor para slides)
npx @marp-team/marp-cli docs/sales/PITCH_DECK_BRITIMP.md \
  --pdf --allow-local-files

# Opción 3: VS Code Markdown Preview → print → save as PDF
#   Extension recomendada: "Markdown PDF" de yzane

# Opción 4: pandoc con estilo premium
pandoc docs/sales/COMPARATIVE_ONE_PAGER.md \
  -o comparative.pdf --pdf-engine=xelatex \
  -V fontsize=11pt -V linkcolor=blue -V papersize=a4
```

## Después de la reunión

Completá `DEMO_SCRIPT_BRITIMP.md` sección 14 (qué hacer después). Dentro de
24 horas mandá:
- Email resumen con los 3 puntos clave discutidos
- Deck en PDF
- Caso de estudio F48
- Propuesta de fecha para segunda reunión comercial

---

*Confidencial · Material interno BritImp × Kryon · Abril 2026*
