---
name: core-banking-assessment
description: "Evaluación de seguridad de Core Banking — T24, Flexcube, Finacle, IBS, SIPAP/SINACOFI"
triggers:
  tech: []
  ports: [3389, 1433, 1521, 1414, 5000, 5001, 2030]
  keywords: ["core banking", "t24", "flexcube", "finacle", "ibs", "core bancario", "sipap", "sinacofi", "bcp"]
priority: 15
required_tools:
  - run_command
  - nuclei_scan
  - search_vulnerabilities
  - query_knowledge_base
---

> **Estado: TEMPLATE — no validado contra un engagement real.**
> Este playbook describe la metodología que Kryon seguiría en un core
> bancario, pero los checks vendor-specific (T24/Flexcube/Finacle) son
> skeletons: requieren acceso al ambiente del cliente + credenciales +
> ajuste por instalación antes de arrojar hallazgos accionables. No
> usar este playbook como prueba de capacidad sin un pilot con el
> vendor correspondiente.

## Core Banking Security Assessment

Evaluación de core banking systems. Cubre productos comunes en LATAM/Paraguay:
T24 (Temenos), Flexcube (Oracle), Finacle (Infosys), IBS (Cobis), Bantotal,
SIPAP (Sistema de Pagos del BCP), SINACOFI.

### Pre-engagement (obligatorio)

1. **Autorización escrita** del banco — pentests a core bancario tienen
   implicaciones regulatorias (SIB, BCP, Superintendencia de Bancos)
2. **Ventana de mantenimiento** acordada — core banking = 24/7, no se testea
   en horario productivo sin autorización
3. **Ambiente**: DEV, QA, UAT, PRE-PROD, PROD — confirmar cuál
4. **NDA firmado** y data handling agreement
5. **Backup completo** antes de empezar
6. **Runbook de rollback** del cliente

### Fase 1: Recon del entorno

```bash
# Identificar productos de core banking por banners/puertos
nmap -sV -p 21,22,23,25,80,443,1414,1433,1521,2030,3389,5000,5001,8080,8443,9080,9443 TARGET

# Puertos típicos:
# - T24: 7005, 7007 (TAFJ), 9080 (Browser)
# - Flexcube: 2030 (middleware), 7777 (DB), 8080 (GB)
# - Finacle: 5000, 9090, 9091
# - SWIFT CBS: 1414 (MQ), 443 (alliance), 2701 (Swift Alliance Access)
```

### Fase 2: Arquitectura típica

```
[Channels]        [Middleware]         [Core Banking]
Mobile App   →    API Gateway     →    Application Servers
Web Banking  →    ESB (Kafka/MQ)  →    T24/Flexcube/Finacle
Branch PCs   →    Load Balancer   →    Core DB (Oracle/SQL Server/DB2)
ATM Switch   →                    →    Batch processes
                                  →    Reporting DWH
```

Cada componente es un target. Priorizar:
1. **API Gateway** (expuesto a internet)
2. **Mobile banking backend** (APIs)
3. **Web banking** (aplicación web)
4. **Middleware** (IBM MQ, Kafka, WebSphere)
5. **Core DB** (segregado — difícil desde fuera)

### Fase 3: APIs bancarias

Testing específico para bancos (high-value targets):

```bash
# API discovery
nuclei -u https://api.banco.com.py -t exposures/apis/

# Endpoints típicos a probar
for endpoint in \
  "/api/v1/accounts" "/api/v1/customers" "/api/v1/transactions" \
  "/api/v1/transfer" "/api/v1/balance" "/api/v1/statements" \
  "/api/internal/admin" "/api/swagger" "/api/v2/openapi.json"; do
  curl -s -o /dev/null -w "%{http_code} $endpoint\n" https://TARGET$endpoint
done

# BOLA/IDOR — cambiar IDs en URLs de cuentas
# Ejemplo: /api/v1/accounts/123/balance → /api/v1/accounts/124/balance
```

### Fase 4: Vulnerabilidades específicas de core banking

**1. BOLA/IDOR en transferencias**
```bash
# Intentar transferencia desde cuenta ajena
curl -X POST https://api/v1/transfer -H "Authorization: Bearer USER_A_TOKEN" \
  -d '{"from_account": "USER_B_ACCOUNT", "to_account": "MY_ACCOUNT", "amount": 1}'
```

**2. Race conditions en pagos** (double-spend)
```bash
# Usar skill race-condition: enviar N requests simultáneos con mismo saldo
for i in {1..20}; do
  curl -X POST https://api/v1/pay -d '{"amount": "ENTIRE_BALANCE"}' &
done
wait
# Verificar si se procesaron múltiples
```

**3. Token reuse / JWT vulns**
- Verificar si tokens expiran (JWT `exp` claim)
- Verificar si `alg=none` funciona
- Algorithm confusion RS256→HS256

**4. SWIFT/ISO-20022 message injection**
- Si hay endpoint SWIFT, probar inyección de XML/MT messages
- Verificar validación de BIC, IBAN, amount format

**5. Callback/webhook validation**
- URLs de callback de pasarelas de pago pueden ser manipuladas
- HMAC signature verification missing

### Fase 5: Pruebas de fraude

**Detectores a auditar:**
- Velocity rules (N transacciones en T segundos)
- Geo-velocity (login desde 2 países en poco tiempo)
- Device fingerprinting
- Behavioral biometrics
- Money mule detection

**Escenarios de testing:**
- Transferencias bajo umbral de detección (smurfing)
- Cambio de dispositivo sin MFA reprompt
- Account takeover via password reset weaknesses
- SIM swap simulation

### Fase 6: Componentes Paraguay-específicos

**SIPAP (Sistema de Pagos del BCP)**:
- Conexiones solo desde IPs permitidas por el BCP
- Firma digital de mensajes (certificados emitidos por el BCP)
- Testing requiere coordinación con la Superintendencia de Bancos

**SINACOFI**:
- Central de riesgos — queries a CIB
- Rate limiting para evitar abuse

**Pagos PSE / Bancard / Infonet**:
- Integración vía webhooks
- Verificar HMAC de callbacks
- Test: manipular status de pago en callback

### Reglas críticas

- **NUNCA** hacer transferencias reales de prueba sin aprobación expresa
- **NUNCA** extraer datos reales de clientes al reporte — masked only
- **NUNCA** correr exploits activos en PROD sin autorización explícita de CISO + Gerencia
- **SIEMPRE** documentar cada request en log de actividades
- **SIEMPRE** tener canal directo con el NOC del banco durante el test
- Respetar horarios — no afectar ventana crítica de cierre (usualmente 18:00-20:00 PY)

### Informe final bancario

Estructura específica requerida por reguladores:
1. Resumen ejecutivo (CEO-level, sin jerga técnica)
2. Alcance y metodología
3. Findings priorizados por riesgo financiero (no solo CVSS)
4. Impacto estimado (potential loss $ + reputational)
5. Remediation timeline aligned con SIB/BCP reporting requirements
6. Attestation de compliance (PCI-DSS si aplica)
