---
name: wordpress-brute-active
description: "Active WordPress foothold with a DETERMINISTIC pre-fire: wpscan rockyou brute -> theme-editor webshell -> www-data -> loot, run BEFORE the LLM so the chain doesn't depend on a small local model driving it. Solo activable con keywords fuertes (NO matchea 'wordpress' genérico) — requiere autorización escrita del operator."
triggers:
  tech: []
  ports: []
  keywords:
    # F204 — keywords ESPECÍFICOS para evitar auto-activación amplia (la regresión F203.U: pre_hooks
    # caros en keywords amplios matan el wall budget). NO incluye "wordpress" / "wpscan" / "wp" solos.
    - "active wordpress pentest"
    - "active wp pentest"
    - "wordpress brute"
    - "wp brute"
    - "fire wpscan"
    - "pentest activo wordpress"
    - "brute wordpress login"
    - "wordpress foothold deterministic"
priority: 3
required_tools:
  - run_command
  - web_fetch_smart
  # Post-foothold validation/escalation (present under KRYON_RED_TEAM).
  - validate_rce
  - validate_auth_bypass
pre_hooks:
  # F204 — full WordPress foothold, deterministic-first. Cracks the admin password (wpscan rockyou
  # wp-login brute, ~114s), then on a confirmed crack: wp-admin login -> theme-editor 404.php webshell
  # -> trigger for id -> loot user.txt + /opt + wp-config. The cred + shell + looted creds are injected
  # as authoritative facts so the agent builds on a real foothold instead of re-driving wpscan (which
  # Ornith-9B does only ~1-in-N runs). Banca-safe: read-only until the webshell, which only fires AFTER
  # a confirmed crack. 300s brute + ~60s webshell/loot, so timeout_s 420.
  - python: ./cwe-detection/wpscan_brute_hook.py:run
    args:
      target: "{ctx.target}"
    inject_as: wordpress_deterministic_foothold
    required: false
    timeout_s: 420
---

# Active WordPress Foothold (F204) — deterministic brute + webshell

**⚠️ ACTIVA SOLO con autorización escrita.** Esta skill ejecuta un brute-force real
(`wpscan` + rockyou) y, si crackea, **escribe** un webshell en el theme activo del WordPress
del target. Solo se dispara con la frase explícita **"active wordpress pentest"** (o
"wordpress brute" / "fire wpscan" / "pentest activo wordpress") + `KRYON_RED_TEAM=true`.

## Por qué pre_hook determinista (no dejarlo al modelo)

El chain-planner YA tiene las reglas (`_rule_wordpress_wpscan` + `_rule_wp_admin_webshell`) y cada paso
está validado en aislamiento. El problema es que el **modelo local chico (Ornith-9B) no maneja
confiablemente la cadena multi-paso**: en 13 corridas en vivo contra THM Internal, cada una falló
distinto — a veces drivea wpscan, a veces loopea recon, a veces explora Jenkins. La cadena determinista
en sí funciona (`admin:my2boys` → `uid=33(www-data)` → cred SSH de aubreanna en `/opt/wp-save.txt`).

El **pre_hook corre la cadena ANTES del LLM** e inyecta el resultado como hecho autoritativo. Así el
agente arranca desde un **foothold ya establecido** (cred + shell + creds lootadas) en vez de tener que
ejecutar la cadena él mismo. Convierte "autónomo-con-suerte" en "determinista-confiable".

## Qué hace el pre_hook (`cwe-detection/wpscan_brute_hook.py`)

1. **Base + vhost**: prueba `/`, `/blog`, `/wordpress`, `/wp`, `/cms`, `/news` por fingerprint WP;
   detecta el vhost canónico (siteurl de WP en el body, ej. `internal.thm`) y lo siembra en `/etc/hosts`
   (WordPress redirige el IP pelado al vhost — login/theme-editor solo funcionan ahí).
2. **Crack**: `wpscan -e u` (enum usuarios) + `wpscan ... -P rockyou --password-attack wp-login
   --max-threads 40` (brute, ~114s). wp-login (no xmlrpc-multicall, que errorea en WP endurecido).
3. **Webshell** (solo si crackeó): login con cookie → `theme-editor.php` (nonce `id="nonce"` en WP 5.x)
   → sobreescribe `404.php` del theme activo con un webshell PHP de 1 línea → trigger `?0=id` → www-data.
4. **Loot**: `user.txt` + `/opt/*` + `DB_*`/passwords de `wp-config` vía el webshell.

## Qué hacer con el resultado inyectado

El pre_hook deja en contexto: la cred admin, el `uid=` del webshell, la URL del webshell
(`.../404.php?0=<cmd>`), y cualquier cred/flag lootada. **NO re-brutees ni re-plantes** — son hechos
confirmados. Pasos siguientes (manuales/agente):

- **Pivote con creds lootadas**: si hay creds SSH (ej. `aubreanna:...` de `/opt/wp-save.txt`), probar
  `ssh -F /dev/null -o StrictHostKeyChecking=no <user>@<host>` → user shell.
- **Privesc desde www-data**: enumerar el shell (`sudo -l`, SUID, cron, capabilities) vía
  `?0=<cmd>`. Servicios internos (ej. Jenkins en `127.0.0.1:8080` / `172.17.0.x:8080`) → port-forward
  SSH → Groovy Script Console → RCE → docker/root.
- **Registrar findings** con `validate_rce` / `validate_auth_bypass` para el reporte.

## Banca-safe / scope

- Read-only hasta el webshell; el webshell **solo se planta tras un crack confirmado** (sin crack, sin
  escritura). El `404.php` queda modificado — restaurarlo post-engagement (theme-editor → contenido
  original, o reinstalar el theme).
- Solo contra targets con **autorización escrita**. La frase-gatillo explícita + `KRYON_RED_TEAM`
  evitan disparos accidentales.
