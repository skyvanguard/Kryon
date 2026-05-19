---
name: cwe-22-path-traversal
description: "Detección y clasificación de CWE-22 Path Traversal (directory traversal, '../'). Discrimina vs CWE-23 (relative path traversal), CWE-36 (absolute path), CWE-73 (file & path inclusion)."
triggers:
  tech: []
  ports: []
  file_extensions: [".java", ".py", ".cs", ".rb", ".php", ".go", ".js", ".ts", ".kt", ".scala"]
  keywords:
    - "path traversal"
    - "directory traversal"
    - "lfi"
    - "local file inclusion"
    - "rfi"
    - "remote file inclusion"
    - "../"
    - "..%2f"
    - "..\\\\"
    - "file inclusion"
    - "zipslip"
    - "zip slip"
    - "archive extraction"
    - "fopen"
    - "file.read"
    - "readfile"
    - "downloadfile"
priority: 18
required_tools:
  - run_command
---

# CWE-22 — Path Traversal (clasificación SAST)

Se activa cuando el agente audita código que lee/escribe archivos
con paths construidos a partir de input. **NO confundir CWE-22
con CWE-73 (file inclusion en interpretadores como PHP `include`),
CWE-94 (code injection genérico), ni CWE-918 (SSRF — diferente
mecanismo)**.

## Discriminación CWE-22 vs hermanas

| CWE | Significado | Cuándo usar |
|---|---|---|
| **CWE-22** | **Path Traversal (`../`)** | Filesystem read/write con input que escapa el chroot/basedir |
| CWE-23 | Relative Path Traversal | Específicamente paths relativos con `../` |
| CWE-36 | Absolute Path Traversal | Input es absolute path `/etc/passwd` directo |
| CWE-73 | File & Path Inclusion (PHP-style) | `include $_GET['file']` — ejecuta código del path |
| CWE-434 | Unrestricted File Upload | Upload, NO read — diferente sink |
| CWE-918 | SSRF | URL fetch server-side, NO filesystem |

**Regla práctica**: si el sink es `open(path)`, `File.read(path)`, `Files.readAllBytes(path)`, `sendfile(path)`, o ZIP extract con entry name controlado → **CWE-22**. Si es PHP `include`/`require` con dynamic path → **CWE-73**.

## Sink patterns CWE-22 por lenguaje

### Java
```java
// CWE-22 sinks
File file = new File(basedir, userInput);  // userInput="../../../../etc/passwd"
Files.readAllBytes(Paths.get(filename));
new FileInputStream(uploadDir + "/" + filename).read(...);

// ZipSlip (special case of CWE-22)
ZipFile zip = new ZipFile(uploaded);
for (ZipEntry e : zip.entries()) {
    File out = new File(baseDir, e.getName());  // e.getName()="../../../../etc/cron.d/x"
    out.createNewFile();
}

// Safe:
Path resolved = Paths.get(basedir).resolve(filename).normalize();
if (!resolved.startsWith(basedir)) throw new SecurityException();
```

### Python
```python
# CWE-22 sinks
with open(f"{base}/{filename}", "r") as f: data = f.read()
content = pathlib.Path(base) / user_input
content.read_bytes()
shutil.copyfile(src, f"./uploads/{name}")

# Tarslip / Zipslip
import tarfile
tar = tarfile.open(...)
tar.extractall("./uploads")  # tar entries pueden ser ../../

# Safe:
import os
target = os.path.realpath(os.path.join(base, name))
if not target.startswith(os.path.realpath(base)):
    raise ValueError("path traversal")
```

### Node.js
```js
// CWE-22 sinks
const filepath = path.join(__dirname, 'uploads', req.params.file);
fs.readFile(filepath, cb);
res.sendFile(filepath);
res.download(`./files/${req.query.file}`);

// Safe:
const resolved = path.resolve(uploadDir, req.params.file);
if (!resolved.startsWith(uploadDir)) return res.status(400).send();
```

### PHP
```php
// CWE-22 sinks
$content = file_get_contents($_GET['file']);
readfile($base . "/" . $_GET['name']);
fopen("./uploads/" . $_REQUEST['filename'], "r");

// CWE-73 (file inclusion, NOT just read):
include $_GET['page'];  // -- this is CWE-73 not CWE-22
require_once $_REQUEST['module'];
```

### Go
```go
// CWE-22 sinks
data, _ := os.ReadFile(filepath.Join(baseDir, userInput))
http.ServeFile(w, r, "./files/" + r.URL.Query().Get("name"))

// Safe:
clean := filepath.Clean(userInput)
target := filepath.Join(baseDir, clean)
if !strings.HasPrefix(target, baseDir) { return errors.New("traversal") }
```

## Familias de bugs CWE-22 (sin spoilers)

- **Download/preview endpoints**: `GET /download?file=`
- **Avatar/profile picture**: `/avatar/{username}.png` con username controlado.
- **Static file serving**: middleware que sirve `/static/{path}`.
- **Template loaders**: `loadTemplate(name)` con name controlado.
- **Backup restore**: archivo restaurado a path del archivo dentro del backup.
- **ZipSlip / TarSlip**: extracción de archivos con entry names `../`.
- **Symlink trickery**: el path target es un symlink que apunta afuera.

## Metodología de detección

```bash
# Java
run_command grep -rn "new File(\|Files\.readAllBytes\|FileInputStream\|ZipFile" {source_path}

# Python
run_command grep -rn "open(f['\"]\|Path(\|pathlib\.\|extractall" {source_path}

# Node.js
run_command grep -rn "path\.join.*req\.\|fs\.readFile\|res\.sendFile\|res\.download" {source_path}

# PHP
run_command grep -rn "file_get_contents\|readfile\|fopen\|file_put_contents" {source_path}

# Go
run_command grep -rn "filepath\.Join.*\\.\\(URL\\|Query\\|Form\\)\|http\.ServeFile" {source_path}

# Generic: buscar concatenación de paths con input
run_command grep -rn "uploads/.*\\\$\\|files/.*req\\." {source_path}
```

Para cada match, verificá:
1. ¿Se llama `realpath/normalize` y se compara con basedir?
2. ¿Hay allowlist de filenames (regex `^[a-z0-9_.-]+$`)?
3. ¿Se valida que no haya `../` en input?
4. Para ZipSlip: ¿se valida cada entry name antes de extraer?

## Formato de finding obligatorio

```
CWE-22 en <archivo>:<linea>
```

**NUNCA CWE-73 ni CWE-200** para filesystem read traversal. CWE-73 es
específicamente cuando el path se interpreta como código (PHP include).

## Banca-safe

100% read-only. NO crea symlinks ni archivos en el target, NO sube
ZIPs maliciosos. Validación real con curl en lab separado.
