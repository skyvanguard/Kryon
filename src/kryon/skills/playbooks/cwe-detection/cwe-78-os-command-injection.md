---
name: cwe-78-os-command-injection
description: "Detección y clasificación de CWE-78 OS Command Injection (shell metachars, exec/system/popen). Discrimina vs CWE-77 (generic command), CWE-94 (code injection), CWE-89 (SQL)."
triggers:
  tech: []
  ports: []
  file_extensions: [".java", ".py", ".cs", ".rb", ".php", ".go", ".js", ".ts", ".kt", ".sh"]
  keywords:
    - "command injection"
    - "os command injection"
    - "shell injection"
    - "rce"
    - "remote code execution"
    - "exec("
    - "system("
    - "popen"
    - "subprocess"
    - "runtime.exec"
    - "shell=true"
    - "shell metachars"
    - "shell_exec"
    - "passthru"
    - "child_process"
priority: 18
required_tools:
  - run_command
---

# CWE-78 — OS Command Injection (clasificación SAST)

Se activa cuando el agente audita código que invoca el sistema
operativo (shell, fork+exec, child process). **NO confundir
CWE-78 con CWE-77 (generic command), CWE-94 (server code eval),
CWE-89 (SQL), ni CWE-117 (log injection)**.

## Discriminación CWE-78 vs hermanas

| CWE | Significado | Cuándo usar |
|---|---|---|
| **CWE-78** | **OS Command Injection** | Comando shell con input (bash/sh/cmd.exe/powershell) |
| CWE-77 | Command Injection (genérico) | Comando no-shell, p.ej. message queue command |
| CWE-94 | Code Injection (eval) | `eval()`, `exec()` de código Python/Ruby/etc, NO shell |
| CWE-95 | Eval Injection | Específicamente `eval()` con dynamic content |
| CWE-88 | Argument Injection | `--option=value` injection sin shell metachars |

**Regla práctica**: si el sink invoca `/bin/sh -c`, `cmd.exe /c`, `Runtime.exec`, `subprocess.run(shell=True)`, o cualquier wrapper que evalúe metachars (`;`, `&&`, `|`, `` ` ``, `$()`), es **CWE-78**.

## Sink patterns CWE-78 por lenguaje

### Java
```java
// CWE-78 sinks (shell metachars permitidos)
Runtime.getRuntime().exec("sh -c " + userInput);
Runtime.getRuntime().exec(new String[]{"sh", "-c", userInput});
new ProcessBuilder("bash", "-c", userInput).start();

// CWE-88 (argument injection, NOT shell):
Runtime.getRuntime().exec(new String[]{"ping", userInput});  // -- still problematic
```

### Python
```python
# CWE-78 sinks
os.system("ping " + host)
os.popen("kill -9 " + pid)
subprocess.call(cmd_str, shell=True)
subprocess.Popen(f"convert {filename} out.png", shell=True)
subprocess.run("rm -rf " + path, shell=True)

# Safe (argv list, no shell):
subprocess.run(["ping", host], shell=False)
```

### Node.js
```js
// CWE-78 sinks
const { exec } = require('child_process');
exec(`ping ${host}`, callback);
exec('ls ' + dir);

// Safe:
const { execFile } = require('child_process');
execFile('ping', [host], callback);
```

### PHP
```php
// CWE-78 sinks
exec("ping " . $_GET['host']);
system("ls " . $dir);
shell_exec("convert " . $file);
passthru("ffmpeg -i " . $input);
`ls $dir`;  // backticks
```

### Ruby
```ruby
# CWE-78 sinks
`ls #{params[:dir]}`           # backticks
system("ping #{host}")
exec("kill -9 #{pid}")
%x[curl #{url}]                # %x equivalent to backticks
IO.popen("convert #{file} out.png")
```

### Go
```go
// CWE-78 sinks
exec.Command("sh", "-c", "ping " + host).Run()
exec.Command("bash", "-c", userInput).Output()

// Safe (argv, no shell):
exec.Command("ping", host).Run()
```

## Familias de bugs CWE-78 (sin spoilers)

- **File operation wrappers**: aplicaciones que ofrecen "preview/convert"
  features pasando filename a `convert/ffmpeg/imagemagick` via shell.
- **Network tools UI**: web admin que expone `ping/traceroute/dig` con
  parámetro shell.
- **Log tail features**: dashboards que ejecutan `tail -f $file` con
  filename controlado.
- **Custom backup scripts**: backup endpoints que invocan `tar/rsync/zip`
  con paths controlados.
- **Webhook handlers**: subprocess invocado en respuesta a HTTP webhook
  payload.

## Metodología de detección

```bash
# Java
run_command grep -rn "Runtime\.getRuntime\(\)\.exec\|ProcessBuilder" {source_path}

# Python
run_command grep -rn "os\.system\|os\.popen\|subprocess\..*shell=True" {source_path}

# Node.js
run_command grep -rn "child_process\.exec\|require.*exec.*\`\|cp\.exec\(" {source_path}

# PHP
run_command grep -rn "exec(\|system(\|shell_exec\|passthru\|\\\$_GET.*\`" {source_path}

# Ruby
run_command grep -rn "system(\|exec(\|backticks\|IO\.popen\|%x\\[" {source_path}

# Go
run_command grep -rn "exec\.Command.*sh.*-c\|exec\.CommandContext" {source_path}
```

Para cada match, verificá:
1. ¿Hay metachars del shell en input que no sean escapados? (`;`, `&&`, `|`, backtick, `$()`)
2. ¿Se usa `shell=True` / `-c` flag?
3. ¿Hay allowlist de comandos? (raro, pero defensivo)

## Formato de finding obligatorio

```
CWE-78 en <archivo>:<linea>
```

**NUNCA CWE-77, CWE-94 ni CWE-20** cuando el sink es shell del OS.
CWE-78 es el hijo específico de CWE-77 para OS shells.

## Banca-safe

100% read-only. NO ejecuta payloads RCE contra el target. Validar
con curl/burp en lab separado, nunca en producción.
