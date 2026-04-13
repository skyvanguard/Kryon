---
name: fraud-detection
description: "Auditoría de sistemas antifraude bancario — velocity, behavioral analytics, ML models"
triggers:
  tech: []
  keywords: ["antifraude", "fraud detection", "velocity rules", "aml", "kyc", "money mule", "behavioral analytics", "ueba bancario"]
priority: 22
required_tools:
  - run_command
  - query_knowledge_base
---

## Audit de Detección de Fraude Bancario

Evaluación de sistemas antifraude. Objetivo: confirmar que los controles
detectan patrones reales de fraude sin bloquear excesivamente (falsos positivos).

### Qué testear

Bancos tienen múltiples capas de detección. Auditamos cada una:

1. **Rule-based engine** (reglas duras: velocity, geolocation, device)
2. **Behavioral analytics / UEBA** (desviación del comportamiento normal)
3. **ML models** (features + scoring probabilístico)
4. **AML / Sanctions screening** (OFAC, UN, OFAC SDN list)
5. **KYC / onboarding** (document verification, liveness)

### Fase 1: Mapping del sistema

Preguntas al cliente:
- ¿Qué engine de reglas usan? (FICO Falcon, SAS, Actimize, Feedzai, custom)
- ¿Tienen modelo ML en producción? ¿Qué features usa?
- ¿Dónde se inyecta el scoring? (pre-auth, post-auth, batch)
- ¿Qué triggers bloquean? (hard block vs soft review)

### Fase 2: Pruebas de velocity

**Rules típicas:**
- Max N transacciones en T minutos
- Max $X por hora
- Max países distintos en login por día
- Max intentos de PIN fallidos

```bash
# Test velocity en transferencias
# Escenario: usuario tiene $10000, rule "max 3 transfers in 5 min"
for i in {1..10}; do
  curl -X POST https://api/v1/transfer \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"to\": \"account_$i\", \"amount\": 1000}" \
    -w "request $i: %{http_code}\n"
  sleep 5
done
# Verificar: ¿bloqueó después de la 3ra? ¿Qué mensaje dio?
# IMPORTANTE: esto es detectable — coordinar con cliente
```

### Fase 3: Geolocation anomalies

```bash
# Login desde IP de Paraguay, luego 30 seg después desde IP de Rusia
# Usar VPN / proxy para simular

# IP1 (Paraguay): login
curl -X POST https://api/v1/login --interface eth0 \
  -d '{"user": "test", "pass": "pass"}'

# Cambiar VPN a Rusia
# IP2 (Rusia): intentar transferir
curl -X POST https://api/v1/transfer --interface vpn_ru \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"to": "account", "amount": 1000}'

# Esperado: step-up auth (SMS OTP, biometric prompt) o block
```

### Fase 4: Device fingerprinting

```bash
# Cambiar headers que identifican el device
curl -X POST https://api/v1/login \
  -H "User-Agent: Mozilla/5.0 (DIFFERENT)" \
  -H "X-Device-ID: RANDOM_$(openssl rand -hex 8)" \
  -H "X-Fingerprint: $(openssl rand -hex 32)"
# ¿El sistema pide 2FA por "dispositivo nuevo"?
```

### Fase 5: Account Takeover (ATO) simulation

ATOs son el vector #1 de fraude en banca digital. Test:

1. **Credential stuffing** (usando credenciales leaked de otros servicios):
   - Rate limiting en login?
   - Account lockout después de N intentos?
   - CAPTCHA después de X fallos?
   - IP blocklist de proxy/Tor?

2. **Password reset abuse**:
   - ¿Email puede ser cambiado con solo PIN/DNI?
   - ¿SMS de recovery va al número que el atacante puede cambiar?
   - ¿Preguntas de seguridad son googleables? (nombre mascota, ciudad nacimiento)

3. **SIM swap detection**:
   - ¿El sistema detecta cambio reciente de carrier?
   - ¿Bloquea MFA vía SMS si hay SIM swap reciente?

4. **Session hijack**:
   - ¿Tokens rotan en operaciones sensibles?
   - ¿Cookies tienen `HttpOnly`, `Secure`, `SameSite=Strict`?

### Fase 6: Money mule detection

Patrones típicos de money mule:
- Cuenta recién abierta
- Recibe transferencia grande
- Distribuye en múltiples transferencias pequeñas < threshold
- Envía a cuentas internacionales
- Retiro en efectivo inmediato

```bash
# Simular patrón con cuentas de testing
# Cuenta A (mule): recibe $10000 ficticio
# A envía 20 transferencias de $499 (bajo threshold de $500)
# A envía 1 transferencia a account extranjera
# A hace retiro de ATM

# El sistema debería:
# - Flaggear "structuring" (smurfing)
# - Flaggear "rapid distribution"
# - Flaggear "foreign transfer + mule pattern"
```

### Fase 7: AML / Sanctions screening

```bash
# Intentar transferencia a nombre en lista OFAC
# Ejemplo: "Kim Jong Un" como beneficiario
# Esperado: bloqueo + compliance alert

# Verificar que escanea:
# - OFAC SDN list
# - UN consolidated sanctions list
# - EU sanctions
# - UK HMT
# - PEP lists (Politically Exposed Persons)

# Tests:
# - Nombres con caracteres especiales/Unicode (bypass?)
# - Nombres en diferentes scripts (Cyrillic, Arabic)
# - Transliteraciones ("Putin" vs "Путин")
```

### Fase 8: KYC bypass attempts

Para nuevas cuentas:

1. **Liveness detection bypass**:
   - Foto de foto (rebroadcast attack)
   - Video pregrabado
   - Deepfake simple

2. **Document verification**:
   - Fotocopias en color
   - Documentos editados (removido filigrana)
   - Documentos de países con validadores débiles

3. **Face match con selfie vs documento**:
   - Dos personas con parecido
   - Morph attack (cara mezclada)

### Métricas a reportar

- **False Positive Rate** por regla (cuántas transacciones legítimas son bloqueadas)
- **False Negative Rate** (cuántos fraudes conocidos pasaron)
- **Detection Rate** por tipo de fraude
- **Response Time** (ms desde transacción hasta decisión)
- **Escalation Accuracy** (cuántas revisiones manuales eran realmente fraude)

### Findings típicos

- Rate limiting insuficiente en login → CRÍTICO
- Password reset sin step-up → CRÍTICO
- AML/Sanctions no cubre Unicode variants → ALTO
- Device fingerprinting solo usa UA → MEDIO
- Velocity rules no aplican a internas (entre cuentas mismo banco) → ALTO
- ML model sin feedback loop (no reentrenamiento con fraudes confirmados) → MEDIO
- MFA puede ser bypaseado post-login para transferencias → CRÍTICO

### Compliance

- **FATF Recommendations** (40 Recomendaciones)
- **Basel AML requirements**
- **Ley 1015 / 5876 (Paraguay)** — prevención de lavado de activos
- **SEPRELAD (PY)** — reportes de transacciones sospechosas
- **BCP Resolución 7/2017** (PY) — prevención LA/FT
