# Statement of Work (SOW) — Plantilla

> Esta plantilla requiere revisión legal antes de ser firmada. Los
> campos entre `{{...}}` deben completarse por el representante
> comercial junto con el banco.

---

## Partes

Entre **{{RAZON_SOCIAL_KRYON}}**, en adelante "Kryon", y
**{{RAZON_SOCIAL_BANCO}}**, en adelante "el Cliente", ambos
constituyen este Statement of Work, en adelante "SOW".

## 1. Objeto del contrato

Kryon prestará servicios de **auditoría técnica de ciberseguridad y
generación de evidencia reproducible** sobre la infraestructura
técnica del Cliente, cubriendo los marcos regulatorios acordados.

## 2. Alcance técnico

### 2.1 Frameworks aplicables

Se auditarán los siguientes marcos (marcados con ✅ en el cuestionario
de alcance anexo):

- {{FRAMEWORK_1}} — {{CANTIDAD_CONTROLES_1}} controles
- {{FRAMEWORK_2}} — {{CANTIDAD_CONTROLES_2}} controles
- {{FRAMEWORK_3}} — {{CANTIDAD_CONTROLES_3}} controles
- (…)

**Total:** {{TOTAL_CONTROLES}} controles deterministas · {{TOTAL_CRITICAL}}
controles de severidad CRÍTICA.

### 2.2 Hosts en alcance

- {{NUMERO_HOSTS_LINUX}} hosts Linux
- {{NUMERO_HOSTS_WINDOWS}} hosts Windows
- {{NUMERO_BASES_DATOS}} bases de datos
- {{NUMERO_ATMS}} cajeros automáticos (si aplica)
- (ver anexo A: inventario técnico)

### 2.3 Fuera de alcance (exclusiones expresas)

- Pruebas de penetración intrusivas o explotación activa
- Ingeniería social sobre empleados
- Pruebas de denegación de servicio
- Modificación o escritura en sistemas de producción
- Extracción de datos de clientes (PAN, PIN, credenciales)
- Cualquier sistema no listado en el anexo A

## 3. Metodología

1. **Kick-off técnico** — reunión de inicio, verificación de accesos,
   firma de anexos.
2. **Reconocimiento pasivo** — inventario automatizado read-only.
3. **Ejecución de controles deterministas** — scripts firmados contra
   hosts en alcance, en ventanas operativas acordadas.
4. **Análisis y validación** — revisión de hallazgos por analista
   senior antes de incluir en reporte.
5. **Reporte preliminar** — entrega al CISO para revisión interna
   **antes** del reporte final (10 días hábiles).
6. **Revisión conjunta** — sesión para aclarar hallazgos, descartar
   falsos positivos y priorizar remediación.
7. **Reporte final** — PDF bilingüe + evidencia JSON + hash de
   reproducibilidad.
8. **Transferencia de conocimiento** — {{NUMERO_SESIONES}} sesiones de
   entrenamiento al equipo interno.

## 4. Plazos

| Fase | Inicio | Fin | Duración |
|---|---|---|---|
| Kick-off + setup | {{FECHA_INICIO}} | | 5 días hábiles |
| Ejecución de controles | | | {{DURACION_EJECUCION}} días hábiles |
| Análisis y validación | | | 5 días hábiles |
| Reporte preliminar | | | 3 días hábiles |
| Ventana de revisión | | | 5 días hábiles |
| Reporte final | | | 2 días hábiles |
| Transferencia | | | {{NUMERO_SESIONES}} sesiones |
| **TOTAL** | | {{FECHA_FIN}} | {{DURACION_TOTAL}} días hábiles |

## 5. Entregables

- **E1:** Cuestionario de alcance firmado (anexo A).
- **E2:** Inventario técnico detectado (JSON + PDF).
- **E3:** Reporte preliminar bilingüe (PDF).
- **E4:** Reporte final bilingüe (PDF + JSON evidencia).
- **E5:** Plan de remediación priorizado (XLSX).
- **E6:** Presentación ejecutiva para Comité de Riesgo (PPTX, 20 slides).
- **E7:** {{NUMERO_SESIONES}} sesiones de entrenamiento (grabadas).

Cada entregable tiene **criterios de aceptación** listados en el anexo B.

## 6. Inversión

| Concepto | Monto (USD) |
|---|---|
| Licencia Kryon (período del engagement) | {{LICENCIA}} |
| Servicios profesionales de implementación | {{SERVICIOS}} |
| Transferencia de conocimiento | {{TRANSFERENCIA}} |
| **Subtotal** | {{SUBTOTAL}} |
| IVA 10% (si aplica) | {{IVA}} |
| **Total** | **{{TOTAL}}** |

### Forma de pago

- 40% a la firma del SOW
- 40% contra entrega del reporte preliminar
- 20% contra entrega del reporte final + aceptación formal

Moneda: USD o guaraníes al tipo de cambio del BCP del día de
facturación.

## 7. Confidencialidad

Aplica el NDA previamente firmado ({{REFERENCIA_NDA}}). Además:

- Toda evidencia generada es propiedad intelectual del Cliente.
- Kryon retiene copia cifrada 90 días para soporte post-engagement,
  luego destrucción verificable.
- Kryon NO puede usar los hallazgos del Cliente como caso de estudio
  público sin autorización escrita.
- Kryon usa modelo de lenguaje **local**; no se envían datos del
  Cliente a proveedores de IA en la nube.

## 8. Protección de datos

- Se cumple con la Ley 6534/2020 de Protección de Datos Personales de
  Paraguay.
- No se procesan datos de clientes del banco sin anonimización previa.
- Los datos técnicos (logs, configs) se retienen cifrados en reposo
  con AES-256.

## 9. Responsabilidades

### Del Cliente

- Proveer accesos read-only listados en el cuestionario de alcance.
- Designar un punto de contacto técnico con disponibilidad horaria.
- Acompañar sesiones técnicas con personal interno si así lo
  establece su política.
- Responder a las solicitudes de aclaración en un plazo de 3 días
  hábiles.

### De Kryon

- Ejecutar solo comandos previamente revisados y firmados.
- Nunca escribir, modificar o borrar datos en producción.
- Reportar inmediatamente (< 4 horas) cualquier hallazgo de severidad
  CRITICAL que pudiera ser explotado activamente.
- Entregar los productos en los plazos acordados.

## 10. Cláusula de terminación

Cualquier parte puede terminar el SOW con 15 días de preaviso
escrito. En caso de terminación:

- Se paga proporcionalmente el trabajo ejecutado.
- Kryon entrega toda evidencia generada hasta la fecha.
- Se destruye toda copia en posesión de Kryon según política de
  retención.

## 11. Jurisdicción

Las partes se someten a la jurisdicción de los tribunales ordinarios
de la ciudad de Asunción, Paraguay, renunciando a cualquier otro
fuero.

## 12. Firmas

| Parte | Nombre | Cargo | Firma | Fecha |
|---|---|---|---|---|
| Por el Cliente | | | | |
| Por Kryon | | | | |

---

**Anexos:**
- Anexo A: Cuestionario de Alcance (documento 02)
- Anexo B: Criterios de Aceptación por Entregable
- Anexo C: Plantilla de NDA (documento 06) — ya firmada, referencia
- Anexo D: Matriz de Cobertura Regulatoria (documento 04)
