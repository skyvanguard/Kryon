---
name: cwe-89-sqli
description: "Detección y clasificación de CWE-89 SQL Injection (in-band, blind, time-based). Discrimina vs CWE-943 (NoSQL injection) y CWE-90 (LDAP injection)."
triggers:
  tech: []
  ports: []
  file_extensions: [".java", ".py", ".cs", ".rb", ".php", ".go", ".js", ".ts", ".kt", ".scala", ".sql"]
  keywords:
    - "cwe-89"
    - "sqli"
    - "sql injection"
    - "sql-injection"
    - "executequery"
    - "execute_query"
    - "rawquery"
    - "raw_query"
    - "prepared statement"
    - "preparedstatement"
    - "string.format query"
    - "concat sql"
    - "sqlmap"
    - "union select"
    - "boolean blind"
    - "time-based blind"
priority: 5
required_tools:
  - run_command
pre_hooks:
  # F203.U — DAST sqlmap probe via F191 multi-endpoint hook. Cuando el
  # target es webapp (URL HTTP), pre-fire sqlmap contra una curated list
  # de endpoints típicamente inyectables (Juice Shop, DVWA, WebGoat,
  # PortSwigger, common API auth patterns).
  # Banca-safe: sqlmap con --batch --technique=B --level 2 --risk 2
  # read-only, timeout 30s/endpoint. NO dump, NO escritura.
  - python: ./sqlmap_cwe89_hook.py:run
    args:
      target: "{ctx.target}"
    inject_as: sqlmap_multi_endpoint_probe
    required: false
    timeout_s: 360
---

# CWE-89 — SQL Injection (clasificación SAST)

Se activa cuando el agente audita código que ejecuta queries SQL.
**NO confundir CWE-89 con CWE-943 (NoSQL injection), CWE-90 (LDAP
injection), ni CWE-20 (input validation genérico)**.

## Discriminación CWE-89 vs hermanas

| CWE | Significado | Cuándo usar |
|---|---|---|
| **CWE-89** | **SQL Injection** | Concatenación de input en query SQL (MySQL/Postgres/Oracle/SQLite/MSSQL) |
| CWE-943 | NoSQL Injection | MongoDB `$where`, Redis EVAL, ElasticSearch query DSL |
| CWE-90 | LDAP Injection | LDAP filter concatenation |
| CWE-91 | XML Injection (XPath) | XPath query string concat |
| CWE-77 | Command Injection (genérico) | No-SQL, no-shell command |

**Regla práctica**: si el sink es JDBC `Statement.execute*` con string concat, ORM con raw query, o cualquier `cursor.execute(f"...")` con f-string interpolation → **CWE-89**.

## Sink patterns CWE-89 por lenguaje

### Java (JDBC / Hibernate)
```java
// CWE-89 sinks
Statement stmt = conn.createStatement();
stmt.executeQuery("SELECT * FROM users WHERE id=" + userId);
stmt.executeUpdate(String.format("DELETE FROM x WHERE id=%d", userId));

// Hibernate native
Query q = session.createNativeQuery("SELECT * FROM users WHERE name='" + name + "'");
session.createSQLQuery("...");

// Safe (allowlist):
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);
```

### Python (psycopg2 / pymysql / SQLAlchemy raw)
```python
# CWE-89 sinks
cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
cursor.execute("SELECT * FROM x WHERE name='%s'" % name)
cursor.execute("UPDATE x SET y=" + value)

# SQLAlchemy raw
result = db.execute(f"SELECT * FROM {table_name}")  # CWE-89 even if input "looks safe"

# Safe:
cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
```

### Node.js
```js
// CWE-89 sinks
db.query("SELECT * FROM users WHERE id=" + req.params.id, cb);
db.query(`SELECT * FROM x WHERE name='${name}'`);

// Safe:
db.query("SELECT * FROM users WHERE id=?", [req.params.id], cb);
```

### PHP
```php
// CWE-89 sinks
mysql_query("SELECT * FROM x WHERE id=" . $_GET['id']);
mysqli_query($conn, "DELETE FROM y WHERE id=" . $id);
$pdo->query("SELECT * FROM z WHERE name='" . $name . "'");

// Safe (PDO prepared):
$stmt = $pdo->prepare("SELECT * FROM x WHERE id = :id");
$stmt->execute([':id' => $id]);
```

### Ruby (Rails)
```ruby
# CWE-89 sinks
User.where("name = '#{params[:name]}'")
User.find_by_sql("SELECT * FROM x WHERE id=#{id}")

# Safe:
User.where("name = ?", params[:name])
User.where(name: params[:name])
```

## Familias de bugs CWE-89 (sin spoilers)

- **Login endpoint**: `SELECT * FROM users WHERE email='$email' AND pass='$pass'` clásico.
- **Search filter**: query parameters concatenados en WHERE clause.
- **ORDER BY dynamic**: nombre de columna concatenado sin allowlist.
- **Table name dynamic**: `SELECT * FROM $table` con input controlado.
- **Stored procedure call**: parámetros interpolados en CALL.

## Metodología de detección

```bash
# Java
run_command grep -rn "executeQuery\|executeUpdate\|createNativeQuery\|createSQLQuery" {source_path}
run_command grep -rn "Statement\|prepareStatement" {source_path}

# Python
run_command grep -rn "cursor\.execute\|db\.execute\|connection\.execute" {source_path}
run_command grep -rn "\.execute(f['\"]" {source_path}
run_command grep -rn "\.execute([^,]*%[^,]*)" {source_path}

# Node.js
run_command grep -rn "\.query(.*\+.*)\|\.query(\`" {source_path}

# PHP
run_command grep -rn "mysql_query\|mysqli_query\|->query\|->exec" {source_path}

# Ruby
run_command grep -rn "find_by_sql\|where(['\"]\\#{\|connection\.execute" {source_path}
```

Para cada match, verificá:
1. ¿Hay string concat (`+`, `%`, f-string) con input?
2. ¿Se usa PreparedStatement / parameterized query?
3. ¿El ORM está en modo raw o seguro?

## Formato de finding obligatorio

```
CWE-89 en <archivo>:<linea>
```

**NUNCA CWE-20, CWE-94 ni CWE-77** para SQL injection. CWE-89 es
específico — usalo siempre que el sink sea SQL.

## Banca-safe

100% read-only. NO ejecuta sqlmap real contra la app, NO crea
queries de prueba. Para validación real usar sqlmap/ZAP en
ambiente lab separado.
