---
name: cwe-502-deserialization
description: "Detección y clasificación de CWE-502 Deserialization of Untrusted Data en código Java, Python, .NET. Discrimina vs CWE-915 (object property modification) y CWE-94 (code injection)."
triggers:
  tech: []
  ports: []
  file_extensions: [".java", ".py", ".cs", ".rb", ".php"]
  keywords:
    - "cwe-502"
    - "deserialization"
    - "deserialisation"
    - "untrusted data"
    - "jndi"
    - "jndi lookup"
    - "rmi lookup"
    - "ldap lookup"
    - "objectinputstream"
    - "readobject"
    - "yaml.load"
    - "pickle.loads"
    - "marshal"
    - "log4j"
    - "logback"
    - "logging-log4j2"
    - "java"
    - "spring"
priority: 5
required_tools:
  - run_command
---

# CWE-502 — Deserialization of Untrusted Data (clasificación SAST)

Esta skill se activa cuando el agente audita código que puede
deserializar input externo. **NO confundir CWE-502 con CWE-915
(property modification) ni con CWE-94 (code injection genérico) ni
con CWE-119 (que es memory bounds, irrelevante para Java)**.

## Discriminación CWE-502 vs hermanas

| CWE | Significado | Cuándo usar |
|---|---|---|
| **CWE-502** | **Deserialization of Untrusted Data** | Programa deserializa data externa sin validar → ejecuta código arbitrario |
| CWE-915 | Improperly Controlled Property Modification | Solo modifica propiedades del objeto, no ejecuta |
| CWE-94 | Code Injection (genérico) | Inyección de código sin involucrar deserialización |
| CWE-78 | OS Command Injection | Específicamente comando del sistema operativo |
| CWE-117 | Improper Output Neutralization for Logs | Log injection, no implica RCE |

**Regla práctica**: si el sink involucra `ObjectInputStream.readObject`, `JndiLookup`, `Context.lookup`, `pickle.loads`, `yaml.load(...)` (sin SafeLoader), o cualquier lookup que materialice objetos remotos → **CWE-502**, NUNCA CWE-119 ni CWE-200.

## Sink patterns CWE-502 por lenguaje

### Java
```java
// Direct ObjectInputStream
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();  // <-- CWE-502 sink

// JNDI lookup (Log4Shell-style)
Context ctx = new InitialContext();
ctx.lookup(userControlledString);  // <-- CWE-502 sink
DirContext.lookup(uri);
NamingManager.getURLContext(...).lookup(...);

// Logging frameworks (any logger that does JNDI lookups on
// user-controlled strings)
JndiLookup.lookup(name);
```

### Python
```python
pickle.loads(untrusted)      # CWE-502
yaml.load(untrusted)          # CWE-502 (use safe_load instead)
marshal.loads(untrusted)      # CWE-502
shelve.open(...)              # potential CWE-502 if filename controlled
```

### .NET
```csharp
BinaryFormatter.Deserialize(stream)   // CWE-502
LosFormatter.Deserialize(stream)      // CWE-502
DataContractSerializer.ReadObject(stream)  // CWE-502 if KnownTypes loose
TypeNameHandling.All // JSON.NET attribute that enables CWE-502
```

## Familias de bugs CWE-502 (sin spoilers)

- **Logging framework JNDI lookup**: cualquier logger que pase
  user-controlled string a `Context.lookup`/`JndiLookup.lookup`.
- **HTTP body deserialization**: REST endpoints que deserializan
  JSON/XML/binary sin allowlist de classes.
- **Cookie/session deserialization**: cookies serializadas (rails
  Marshal, java HttpSession).
- **Message queues**: workers que reciben pickled payloads de
  queues no autenticadas.
- **Caching**: Redis/Memcached values deserializados sin validar.

## Metodología de detección

```bash
# Java
run_command grep -rn "readObject\|JndiLookup\|Context\.lookup\|InitialContext\.lookup" {source_path}
run_command grep -rn "ObjectInputStream\|Hessian\|Kryo" {source_path}

# Python
run_command grep -rn "pickle\.loads\|yaml\.load\|marshal\.loads" {source_path} | grep -v "safe_load\|Loader=yaml.SafeLoader"

# .NET
run_command grep -rn "BinaryFormatter\|LosFormatter\|TypeNameHandling" {source_path}
```

Para cada match, verificá:
1. ¿La fuente del data deserializado viene de input no controlado? (HTTP, log message, cookie, queue)
2. ¿Hay allowlist de classes / SafeLoader / type-name validation?
3. ¿Existe sanitization previa? (rare en deserialization)

## Formato de finding obligatorio

```
CWE-502 en <archivo>:<linea>
```

**NUNCA CWE-119, CWE-200, CWE-89 ni CWE-94** para casos de
deserialization claros. La causa raíz es deserialization aún cuando
el efecto final sea RCE o info leak — siempre prefiera el CWE más
específico al efecto observable.

## Banca-safe

Esta skill es 100% read-only:
- Solo `grep`/`find`/`cat` sobre código fuente pre-clonado
- NO compila ni ejecuta ningún binario
- NO realiza ataques de prueba (PoC deserialization gadgets)
- NO conecta a red

Ideal para audits banking SAST de aplicaciones Java/Python/.NET.
