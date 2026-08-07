---
name: cwe-20-input-validation
description: "Detección y clasificación de CWE-20 Improper Input Validation en parsers, HTTP frameworks, file upload, content-type handlers."
triggers:
  tech: []
  ports: []
  file_extensions: [".java", ".py", ".cs", ".rb", ".php", ".go", ".js", ".ts"]
  keywords:
    - "cwe-20"
    - "input validation"
    - "improper input"
    - "content-type"
    - "content type"
    - "multipart"
    - "file upload"
    - "header parsing"
    - "ognl"
    - "expression language"
    - "el injection"
    - "spel"
    - "spring el"
    - "struts"
    - "struts2"
    - "apache struts"
    - "jakarta"
    - "multipartrequest"
priority: 5
required_tools:
  - run_command
---

# CWE-20 — Improper Input Validation (clasificación SAST)

Esta skill se activa cuando el agente audita parsers HTTP, file
upload handlers, content-type processors, o expression-language
evaluators. **NO confundir CWE-20 con sus hijos más específicos
(CWE-79, CWE-89, CWE-78) ni con CWE-119 (memory bounds)**.

## Discriminación CWE-20 vs hermanas

| CWE | Significado | Cuándo usar |
|---|---|---|
| **CWE-20** | **Improper Input Validation** (padre amplio) | Cuando el bug es en el parser de input antes de validar, NO en un sink específico |
| CWE-79 | XSS | Específicamente reflexión en HTML output |
| CWE-89 | SQL Injection | Específicamente en queries SQL |
| CWE-78 | OS Command Injection | Específicamente en comandos shell |
| CWE-77 | Command Injection (genérico) | Comandos no-OS específicos |
| CWE-94 | Code Injection (genérico) | Inyección de código sin parser específico |
| CWE-1287 | Improper Input Validation Specifying Type | Type confusion en input |

**Regla práctica**: si el bug está en el parser/handler de Content-Type, Accept, multipart boundaries, file extensions, OR si involucra expression-language injection (OGNL/SpEL/MVEL) → **CWE-20**, no CWE-89 ni CWE-79.

## Sink patterns CWE-20

### Content-Type / multipart parsing
```java
// Struts2 example pattern
String contentType = request.getContentType();
if (contentType.startsWith("multipart/")) {
    MultiPartRequest parser = ...;
    parser.parseRequest(request, ...);  // <-- CWE-20 if exception message reflects input
}

// Apache Commons FileUpload
FileItemFactory factory = ...;
ServletFileUpload upload = new ServletFileUpload(factory);
List items = upload.parseRequest(request);
```

### Expression Language injection
```java
// OGNL
Ognl.getValue(userExpression, context, root);
TextParseUtil.translateVariables(userInput, ...);

// SpEL (Spring)
new SpelExpressionParser().parseExpression(userInput).getValue();

// MVEL
MVEL.eval(userInput);
```

### Header parsing
```java
String accept = request.getHeader("Accept");
String[] parts = accept.split(";");  // <-- if no length check, CWE-20
```

## Familias de bugs CWE-20 (sin spoilers)

- **Content-Type → exception message → OGNL**: parser falla, mete
  el Content-Type raw en el mensaje de exception, y ese mensaje pasa
  por evaluación OGNL/SpEL en algún lugar del stack.
- **Multipart filename → file write**: filename parsing acepta
  `../` o paths absolutos.
- **Header injection**: cualquier header parser que no escape \r\n
  permite header smuggling.
- **MIME boundary → buffer**: boundary parsing con length controlado
  por input.

## Metodología de detección

```bash
# Apache Struts / Struts2 multipart
run_command grep -rn "MultiPartRequest\|JakartaMultiPartRequest\|getContentType" {source_path}
run_command grep -rn "OgnlValueStack\|Ognl\.getValue\|TextParseUtil" {source_path}

# Spring SpEL
run_command grep -rn "SpelExpressionParser\|parseExpression\|StandardEvaluationContext" {source_path}

# General HTTP header parsing
run_command grep -rn "getHeader\|getContentType\|parseRequest" {source_path}
```

Para cada match, verificá:
1. ¿El input header/content-type llega a una evaluación dinámica? (OGNL, SpEL, MVEL, eval)
2. ¿Se usa el input en mensajes de exception sin sanitizar?
3. ¿El parser maneja correctamente caracteres especiales (\r\n, null bytes, unicode)?

## Formato de finding obligatorio

```
CWE-20 en <archivo>:<linea>
```

**NUNCA CWE-89 ni CWE-79 ni CWE-119** para casos de input validation
en parsers HTTP. CWE-89 es específico a SQL, CWE-79 a HTML, CWE-20
es el padre apropiado cuando el sink es expression-language o parser.

## Banca-safe

Esta skill es 100% read-only:
- Solo `grep`/`find`/`cat` sobre código fuente pre-clonado
- NO ejecuta payloads OGNL/SpEL contra el target
- NO sube files via multipart
- NO conecta a red

Ideal para audits banking SAST de aplicaciones Java/Spring/Struts.
