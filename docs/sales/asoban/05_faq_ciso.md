# FAQ — Preguntas Frecuentes del CISO

Documento de apoyo para la reunión técnica con el CISO. Aborda
objeciones típicas que surgen antes de firmar el SOW.

---

### 1. ¿Kryon envía datos del banco a servicios en la nube?

**No.** Kryon corre 100% local en la infraestructura del cliente o en
servidor dedicado de Kryon. El modelo LLM es local (Qwen3-14B dense
via Ollama) y no hace llamadas externas. Esto se verifica por el
CISO revisando el tráfico de red durante el engagement.

### 2. ¿Kryon puede modificar sistemas de producción?

**No durante auditoría.** El modo por defecto es read-only
(`KRYON_DRY_RUN=true`). Para remediación asistida, Kryon tiene un
sistema de clasificación de comandos (`command_safety.py`) que bloquea
comandos destructivos y requiere aprobación explícita en cada paso.

### 3. ¿Cómo se garantiza la reproducibilidad de la evidencia?

Cada reporte incluye un hash SHA-256 que cubre:
- Orden de los controles
- Veredictos exactos (PASS/FAIL/N/A/ERROR)
- Stdout/stderr de cada comando
- Exit code

Si el auditor externo re-ejecuta los mismos comandos y obtiene el
mismo hash, la evidencia es idéntica. Esto permite al CISO defender
un hallazgo 18 meses después con la misma fuerza que el día 1.

### 4. ¿Qué pasa si un control genera un falso positivo?

Kryon separa la evidencia determinística (veredicto + comando + output)
de la narrativa LLM (prosa explicativa). Los veredictos los genera
el motor determinista; el LLM solo produce texto legible.

Si el CISO identifica un falso positivo, se documenta en una
"exception list" versionada en el repositorio. El control sigue
corriendo pero el FP queda marcado para no alertar de nuevo en
auditorías futuras.

### 5. ¿El modelo LLM "alucina" hallazgos?

El LLM nunca genera veredictos. Todo PASS/FAIL viene del motor
determinístico que evalúa el `pass_when` definido en el YAML del
control. El LLM solo genera:

- Narrativa explicativa en lenguaje natural
- Propuestas de remediación
- Resumen ejecutivo

Todas las secciones generadas por LLM llevan marca visible
`[LLM NARRATIVA]` en el PDF, de modo que el auditor regulatorio
sepa exactamente qué defender con evidencia y qué tratar como guía.

### 6. ¿Cómo se gestionan credenciales durante el engagement?

- Credenciales SSH se reciben vía canal cifrado (Keybase, Proton
  Mail con clave PGP, bóveda Bitwarden compartida).
- Se almacenan en el archivo `~/.kryon/secrets.env` con permisos 0600,
  fuera del repositorio.
- Al finalizar el engagement, se rotan por el equipo del banco
  (política del cliente) y Kryon destruye su copia de forma verificable.

### 7. ¿Kryon cumple con la Ley 6534/2020 de Paraguay?

Sí. Kryon no procesa datos personales de clientes del banco. Solo
analiza configuraciones técnicas (logs, permisos, registros de
sistema). Cualquier dato sensible (PAN, PIN, credenciales) NUNCA se
captura — los controles están diseñados para redactar automáticamente.

### 8. ¿Cómo se integra con mi SIEM actual?

Kryon emite eventos en formato **ECS (Elastic Common Schema)** y
**CEF**, compatibles con Splunk, Elastic SIEM, IBM QRadar, Sentinel.
La integración se configura en la fase de kick-off y toma 1-2 días
hábiles.

### 9. ¿Puedo usar Kryon entre auditorías sin consultor?

Sí. La entrega incluye:
- Licencia operativa para el equipo interno del banco
- Entrenamiento (3-5 sesiones) al equipo de Ciberseguridad
- Documentación en español
- Soporte por canal privado durante los primeros 90 días

Después del onboarding, el banco puede ejecutar Kryon trimestral o
mensualmente sin intervención externa.

### 10. ¿Cómo se factura el modelo? ¿Por host? ¿Por uso?

Modelo de licencia **fijo anual** basado en:
- Tamaño del banco (activos totales)
- Número de frameworks activos
- Número de hosts en alcance
- Soporte + actualizaciones

Sin sorpresas, sin facturación por ejecución, sin "overage fees" como
en herramientas enterprise de ciberseguridad tradicionales.

### 11. ¿Qué pasa si el BCP actualiza la Res. 12/2021?

Kryon mantiene los marcos actualizados. Cada cambio regulatorio:
1. Se incorpora al YAML del framework.
2. Pasa por el regression harness (tests automáticos).
3. Se publica en una release versionada del repo.
4. El cliente recibe notificación + diff con lo nuevo.

Tiempo típico entre publicación regulatoria y disponibilidad en Kryon:
**30-45 días hábiles**.

### 12. ¿Puede el banco auditar el código fuente de Kryon?

Sí. Kryon provee:
- Acceso de solo lectura al repositorio privado durante el engagement.
- Documentación de arquitectura en español.
- Opción de auditoría de seguridad del propio Kryon por tercero
  designado por el banco (costo adicional, acuerdo por separado).

### 13. ¿Qué certificaciones tiene Kryon?

Kryon es una herramienta, no una entidad certificada. El equipo que
opera Kryon posee:
- OSCP, OSWE, OSEP (penetration testing)
- CISSP, CISM (gobierno)
- CISA (auditoría)
- Experiencia directa en banca LATAM (5+ años)

Las certificaciones relevantes son las del **equipo** que ejecuta el
engagement, no de la herramienta misma.

### 14. ¿Cómo manejan un incidente en producción causado por Kryon?

Nunca debería ocurrir porque Kryon es read-only. Pero, por
precaución:

- Todo engagement corre con backup reciente verificado por el banco.
- Kryon mantiene `rollback-recovery` playbook activo durante toda la
  auditoría.
- Hay un War Room 24/7 durante engagements activos.
- Póliza de responsabilidad civil profesional del proveedor: USD 2M.

### 15. ¿Cómo se sale del contrato si no satisface?

Cláusula 10 del SOW: terminación con 15 días de preaviso escrito. Se
paga solo lo ejecutado hasta la fecha. Kryon entrega toda la
evidencia generada hasta ese punto. No hay penalidades por salida.
