---
name: cwe-125-oob-read
description: "Detección y clasificación de CWE-125 Out-of-bounds Read en código C/C++. Discrimina vs CWE-119 (parent) y CWE-787 (OOB write)."
triggers:
  tech: []
  ports: []
  file_extensions: [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"]
  keywords:
    - "cwe-125"
    - "out-of-bounds read"
    - "oob read"
    - "buffer over-read"
    - "buffer over read"
    - "memory disclosure"
    - "memcpy"
    - "memmove"
    - "memcmp"
    - "strncpy"
    - "payload"
    - "heartbeat"
    - "heartbleed"
    - "cve-2014-0160"
    - "cve-2014-3567"
    - "cve-2015-0204"
    - "openssl"
    - "tls"
    - "dtls"
priority: 5
required_tools:
  - run_command
---

# CWE-125 — Out-of-bounds Read (clasificación SAST)

Esta skill se activa cuando el agente audita código C/C++ buscando
vulnerabilidades de memoria. **NO confundir CWE-125 con su padre
CWE-119 ni con su hermano CWE-787 (OOB write)**.

## Discriminación CWE-119 vs CWE-125 vs CWE-787

| CWE | Significado | Cuándo usar |
|---|---|---|
| **CWE-119** | Improper Restriction of Operations within Bounds (genérico padre) | Solo cuando NO se puede determinar si es lectura o escritura |
| **CWE-125** | **Out-of-bounds Read** (info leak) | Programa **lee** más allá del buffer → leak de memoria adyacente |
| **CWE-787** | Out-of-bounds Write | Programa **escribe** más allá del buffer → corrupción heap/stack |

**Regla práctica**: si el sink es `memcpy(dst, src_user_controlled, len_user_controlled)` y `src` apunta a memoria del programa, es CWE-125. Si `dst` queda fuera de bounds, es CWE-787. **Casi siempre que veas un buffer over-read es CWE-125, NO CWE-119**.

## Sink patterns CWE-125

Funciones que leen memoria con tamaño controlado por entrada:

```c
memcpy(buf, attacker_ptr, attacker_len)
memmove(dst, src, attacker_len)
memcmp(buf, attacker_data, attacker_len)
strncpy(dst, src, attacker_len)
read(fd, buf, attacker_len)
recv(sock, buf, attacker_len, ...)
```

Donde `attacker_len` es:
- Un campo de longitud del protocolo (heartbeat payload length)
- Un parámetro HTTP Content-Length
- Un campo de TLS extension length
- Cualquier valor n2s/n2l/ntohs/ntohl derivado de input

## Familias de bugs CWE-125 (sin spoilers de CVEs específicos)

- **Protocolo handshake/heartbeat**: TLS/DTLS heartbeat (en cualquier
  implementación SSL/TLS), keepalive packets, DTLS cookie processing.
- **Parser binario**: cualquier formato con length-prefixed fields donde
  el length viene del input no validado (X.509, ASN.1, protobuf, MIME).
- **Big number / crypto math**: parsing de hex/decimal a BIGNUM sin
  validar el output length.
- **Strings tradicionales**: `strlen` sobre buffer no-terminado,
  `strncpy` con length controlado.

## Metodología de detección

Al auditar código C/C++ con potencial OOB read:

```bash
# 1. Buscar todos los memcpy/memmove con length variable
run_command grep -rn "memcpy\|memmove" {source_path} | grep -v "sizeof\|strlen"

# 2. Buscar campos de longitud parseados de protocolo
run_command grep -rn "n2s\|n2l\|ntohs\|ntohl" {source_path}

# 3. Buscar funciones que procesan heartbeat/keepalive
run_command grep -rn "process_heartbeat\|process_keepalive" {source_path}

# 4. Para cada candidate, verificar si la length se valida ANTES
# del memcpy contra el tamaño REAL del buffer (no contra MAX).
```

## Formato de finding obligatorio

Cuando identifiques OOB read, reportá EXACTAMENTE así:

```
CWE-125 en <archivo>:<linea>
```

**NUNCA CWE-119 ni CWE-200** para casos de buffer over-read claros.
CWE-200 es Information Exposure (consecuencia), CWE-125 es la causa
raíz. CWE-119 es el genérico padre — siempre prefiera el hijo más
específico.

## Banca-safe

Esta skill es 100% read-only:
- Solo `grep`/`find`/`cat` sobre código fuente pre-clonado
- NO compila ni ejecuta ningún binario
- NO conecta a red
- NO modifica el código auditado

Ideal para audits banking SAST donde el código se entrega bajo NDA.
