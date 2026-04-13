---
name: mobile-banking-audit
description: "Auditoría de apps de mobile banking — iOS/Android, certificate pinning, root detection, secure storage"
triggers:
  tech: ["android", "ios"]
  keywords: ["mobile banking", "app bancaria", "banca movil", "bancard app", "mobile app bank", "itau banking", "banco app"]
priority: 17
required_tools:
  - run_command
  - execute_code
---

## Mobile Banking App Security Audit

Auditoría específica para apps de banca móvil. Alto valor = alto riesgo.

### Pre-engagement

- APK / IPA del cliente (no descargar de store — puede ser una versión vieja)
- Cuentas de prueba con fondos ficticios (ambiente UAT)
- Device de prueba (Android rooteado + iOS jailbroken para análisis dinámico)
- SSL kill switch tools: Frida, Objection, mitmproxy

### Fase 1: Static Analysis (APK)

```bash
# Usar android-mobsf skill si está disponible, sino manual:

# Decompile APK
apktool d banco.apk -o banco_decompiled
jadx -d banco_jadx banco.apk

# Buscar secretos hardcoded
grep -rE "(api[_-]?key|apikey|secret|token|password|pwd)" banco_decompiled/ --include="*.xml" --include="*.smali" | head -50
grep -rE "BEGIN (RSA|PRIVATE|EC) (PRIVATE )?KEY" banco_decompiled/

# Buscar URLs hardcoded
grep -rE "https?://[a-z0-9.-]+\.(com|com\.py|com\.ar)" banco_decompiled/ | sort -u | head -20

# Certificate pinning — ¿está implementado?
grep -rE "TrustManager|X509TrustManager|HostnameVerifier|pinCertificate|certificatePinner|pin-set" banco_decompiled/
```

### Fase 2: Dynamic Analysis (iOS/Android)

```bash
# Bypass root/jailbreak detection con Frida
frida -U -n com.banco.app -l frida-scripts/anti-root.js

# Certificate pinning bypass
frida -U -n com.banco.app -l frida-scripts/ssl-pinning-bypass.js
# O con Objection
objection -g com.banco.app explore
# En objection shell:
# android sslpinning disable
# android root disable

# Proxear tráfico con Burp/mitmproxy
# Config WiFi proxy en device → capturar tráfico
mitmproxy --mode transparent --showhost
```

### Fase 3: Tests específicos de banca móvil

**1. Secure Storage**

```bash
# Android: revisar /data/data/com.banco.app/
adb shell "su -c 'ls -la /data/data/com.banco.app/'"
adb shell "su -c 'cat /data/data/com.banco.app/shared_prefs/*.xml'"
# Buscar: passwords, tokens, PII en SharedPreferences
# Debe estar en Android Keystore, no en SharedPreferences

# iOS: dump Keychain
objection -g com.banco.app explore -s "ios keychain dump"
```

**2. Biometric bypass**

```bash
# Verificar que biometric está vinculado a operación sensible, no solo login
# Test: deshabilitar biometric en el medio de una transferencia
frida -U -n com.banco.app -l disable-biometric.js
```

**3. MFA / Token generation**

- Si el app genera OTP, verificar si está seedeado con entropy suficiente
- Si es TOTP, verificar `time-based` vs `counter-based`
- Test: extraer seed del keystore → reproducir tokens

**4. Transaction signing**

- Verificar que transferencias están firmadas con clave privada por-device
- Test: replay attack — capturar request, modificar amount/destination, re-enviar

**5. Deep linking abuse**

```bash
# Intentos de ejecutar acciones via deep link sin confirmación
adb shell am start -a android.intent.action.VIEW -d "banco://transfer?to=ATTACKER&amount=1000000"
```

**6. Screen recording / clipboard**

- ¿Permite screenshot en pantallas sensibles? (debe `FLAG_SECURE`)
- ¿Copia PAN al clipboard?
- ¿Muestra balance en task switcher?

**7. Session management**

- Test inactivity timeout (debe ser ≤5 min en bancos)
- Test logout invalida token server-side (no solo client-side)
- Test concurrent sessions (¿permite 2 sesiones del mismo user?)

### Fase 4: API backend del mobile

Muchas vulns están en el backend, no en la app. Test:

```bash
# Interceptar con mitmproxy/Burp
# Endpoints típicos:
# /api/v1/login → verificar rate limit, account lockout
# /api/v1/transfer → BOLA, race condition
# /api/v1/otp/validate → verificar que OTP es single-use
# /api/v1/biometric/register → verificar device binding

# Ejemplos de tests
curl -X POST https://api/v1/login -d '{"user": "0000000001", "pin": "0000"}' -w "%{http_code}\n"
# Repetir 100 veces — ¿account locked? ¿IP blocked? ¿CAPTCHA triggered?
```

### Findings críticos (bloqueantes para prod)

- Hardcoded API keys en APK/IPA
- Sin certificate pinning
- Sin root/jailbreak detection
- PAN/CVV guardados en SharedPreferences (no Keystore)
- Transferencias sin re-autenticación biométrica
- Token OTP reusable (no single-use server-side)
- Session sin timeout
- Backup permitido (`android:allowBackup="true"`)
- Debug flag habilitado en release (`android:debuggable="true"`)
- WebView con `setJavaScriptEnabled(true)` y `setAllowFileAccess(true)`

### Compliance mapping

- **PCI-DSS**: Req 3 (storage), 4 (transmission), 8 (auth)
- **OWASP Mobile Top 10**: M1 Improper Platform Usage, M2 Insecure Data Storage, M4 Insecure Auth, M5 Insufficient Cryptography
- **LATAM regs**: BCP Resolución 1/2018 (PY), BCRA Com A 7266 (AR), Ley 1682 (CO)
