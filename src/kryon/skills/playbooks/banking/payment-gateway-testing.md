---
name: payment-gateway-testing
description: "Testing de pasarelas de pago — Stripe, PayPal, Bancard, Infonet, MercadoPago"
triggers:
  tech: []
  ports: [80, 443]
  keywords: ["pasarela", "payment gateway", "stripe", "paypal", "bancard", "infonet", "mercadopago", "pse", "3dsecure", "3ds", "wompi"]
priority: 18
required_tools:
  - run_command
  - nuclei_scan
---

## Payment Gateway Testing

Testing de integraciones con pasarelas de pago. Common vulns: webhooks sin validar,
amount tampering, idempotency issues, 3DS bypass.

### Arquitectura de pago típica

```
Cliente → Merchant (tu app) → Pasarela → Adquirente → Red (Visa/MC) → Emisor
                     ↑                          ↓
                     └────── Webhook ───────────┘
```

### Fase 1: Integration flow mapping

Identificar endpoints:
- **Client-side**: SDK de pasarela (Stripe.js, Bancard SDK)
- **Server-side**: endpoint que crea la orden, endpoint de webhook
- **Pasarela**: URL donde se redirige al usuario

```bash
# Buscar SDKs en la página
curl -s https://target.com | grep -iE "stripe|paypal|bancard|mercadopago|infonet"

# Encontrar endpoints del merchant
# Típicamente /api/checkout/create, /api/payment/callback
```

### Fase 2: Amount / currency tampering

```bash
# Interceptar create-order
# POST /api/checkout/create
# {"amount": 10000, "currency": "PYG", "items": [...]}

# Modificar:
# 1. amount → 1 (pagar 1 PYG por un producto de 10000)
curl -X POST https://target/api/checkout/create -d '{"amount": 1, "currency": "PYG", "items": [{"id": "ITEM_123"}]}'

# 2. currency → USD (1 USD en vez de 10000 PYG)
curl -X POST https://target/api/checkout/create -d '{"amount": 10000, "currency": "USD", "items": [...]}'

# 3. Cantidad negativa (refund abuse)
curl -X POST https://target/api/checkout/create -d '{"amount": -10000, ...}'
```

**Fix esperado**: el backend debe calcular el amount desde los items del server-side, no aceptar el amount del cliente.

### Fase 3: Webhook security

Las pasarelas notifican al merchant via webhook. Muchos bugs acá.

```bash
# Identificar webhook endpoint
# /api/webhook/stripe, /api/payment/notify, /api/bancard/confirm

# Tests:
# 1. ¿Acepta webhooks sin HMAC?
curl -X POST https://target/api/webhook/stripe -d '{"event":"payment.succeeded","amount":1000000,"order_id":"MY_ORDER_123"}'
# Esperado: 400 o 401 por falta de firma
# Observado a veces: 200 OK → fraude completo

# 2. ¿Valida el source IP?
# Stripe publica IPs oficiales, algunos merchants no validan

# 3. Replay attack
# Capturar un webhook válido → re-enviarlo → ¿segundo procesamiento?
# Fix: idempotency key en el webhook

# 4. Race condition en webhook vs redirect
# Webhook llega antes que el redirect → orden queda "paid" sin que el user complete 3DS
```

### Fase 4: 3D Secure bypass

```bash
# Algunos merchants NO requieren 3DS para transacciones bajo cierto monto
# Test: transacciones justo bajo el threshold
# Ejemplo: threshold $100, probar $99.99 sin 3DS

# Liability shift: sin 3DS, el merchant asume el fraude
# Verificar: ¿se aceptan pagos con tarjetas NO enroladas en 3DS?

# Attack: stolen card numbers → pagos < threshold → merchant pierde
```

### Fase 5: Refund abuse

```bash
# ¿El endpoint de refund valida que la transacción original es del mismo user?
curl -X POST https://target/api/refund -H "Authorization: USER_A_TOKEN" \
  -d '{"transaction_id": "TX_OF_USER_B", "amount": "FULL"}'

# ¿Hay race conditions?
# Múltiples refund requests paralelos de la misma transacción
for i in {1..10}; do
  curl -X POST https://target/api/refund -d '{"transaction_id":"TX_123"}' &
done
```

### Fase 6: Idempotency

Pasarelas modernas (Stripe, Bancard, MercadoPago) usan idempotency keys.

```bash
# Enviar mismo request 2 veces con misma idempotency key
curl -X POST https://api.pasarela.com/charges \
  -H "Idempotency-Key: KEY_123" \
  -d '{"amount": 1000}'
# Segunda vez
curl -X POST https://api.pasarela.com/charges \
  -H "Idempotency-Key: KEY_123" \
  -d '{"amount": 1000}'
# Esperado: segundo retorna el mismo charge, no crea nuevo

# Test del lado merchant: ¿el merchant maneja idempotency?
# Si no, un webhook replay = doble procesamiento
```

### Fase 7: PAN / CVV exposure

```bash
# ¿El merchant ve el PAN?
# Integraciones "merchant of record" (Stripe Elements, Bancard Vpos) NO deben exponer PAN
# El PAN debe ir directo del browser a la pasarela (iframe/JS SDK)

# Test: interceptar requests del cliente
# En el form, escribir "4111 1111 1111 1111" → mirar con mitmproxy
# ¿El PAN sale del dominio del merchant?
# Si sí → merchant está manejando card data → requiere PCI-DSS SAQ D (mucho más strict)
```

### Fase 8: Test card numbers (para no mover plata real)

Pasarelas tienen test cards:
- Stripe: 4242 4242 4242 4242 (Visa success), 4000 0000 0000 0002 (declined)
- Bancard (PY): 4005 5500 0000 0001 (tarjeta test Bancard)
- MercadoPago: 5031 4332 1540 6351 (Mastercard test AR)

### Findings críticos

- Webhook sin HMAC validation → CRÍTICO
- Amount tampering en create-order → CRÍTICO
- Refund sin ownership check → CRÍTICO
- Replay attack exitoso → CRÍTICO
- PAN tocando el servidor del merchant → CRÍTICO (PCI-DSS scope blast)
- 3DS bypass bajo threshold → ALTO
- Idempotency missing → ALTO
- Race condition en pagos → ALTO

### Compliance

- **PCI-DSS SAQ A** (si el merchant NO toca PAN) vs **SAQ D** (si toca)
- **3D Secure 2.x** (EMVCo) — obligatorio en Europa (PSD2), creciendo en LATAM
- **PCI 3DS** core + SDK requirements
- **BCP (PY) Resolución 4/2018** para medios de pago electrónicos
