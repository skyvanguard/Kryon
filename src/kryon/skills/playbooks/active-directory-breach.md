---
name: active-directory-breach
description: "Active Directory INITIAL ACCESS (breach) with a DETERMINISTIC pre-fire: LDAP recon -> username enumeration (RID-brute + kerbrute) -> AS-REP roast -> COMMON-PASSWORD SPRAY -> foothold credentials, run BEFORE the LLM so obtaining the first domain credential doesn't depend on a small local model driving a multi-step Windows chain. Owns the step BEFORE active-directory-roast (which escalates a foothold to Domain Admin). Solo activable con keywords fuertes de breach (NO matchea 'AD'/'kerberos' genérico) — requiere autorización escrita."
triggers:
  tech: []
  ports: []
  keywords:
    # Keywords ESPECÍFICOS de breach/initial-access (evita auto-activación amplia).
    - "active directory breach"
    - "active directory breaching"
    - "ad breach"
    - "breach active directory"
    - "breach ad pentest"
    - "ad initial access"
    - "password spray active directory"
    - "fire ad breach"
priority: 3
required_tools:
  - run_command
  # Post-foothold validation (present under KRYON_RED_TEAM).
  - validate_auth_bypass
  - calculate_mitre_coverage
pre_hooks:
  # Deterministic BREACH (initial access): LDAP rootDSE domain -> enum users
  # (null-session RID-brute + kerbrute userenum + curated seed) -> GetNPUsers
  # AS-REP roast + john crack -> COMMON/seasonal password spray (kerbrute
  # passwordspray, ONE password across the user list per round). The recovered
  # foothold creds are injected as authoritative facts so the agent authenticates
  # and pivots to takeover instead of re-driving the enum->spray chain (which the
  # local 4B does only ~1-in-N runs). The gap this closes over active-directory-roast:
  # roast sprays already-cracked passwords for REUSE and AS-REP-roasts preauth-disabled
  # accounts, but never sprays COMMON passwords across enumerated users — the actual
  # foothold when no account has preauth disabled (TryHackMe "Intro to AD Breaching").
  # Read-only Kerberos/LDAP enum + offline crack; the spray is Kerberos pre-auth.
  # LOCKOUT-SAFE: reads the domain lockout policy (null-session --pass-pol) and
  # sprays 2 BELOW the threshold (hard cap 2 if unreadable) so it never locks
  # accounts. OSINT userlist via KRYON_AD_USERLIST; disable spray with
  # KRYON_AD_SPRAY=0. ~120s userenum + ~180s crack + spray rounds, so timeout_s 900.
  - python: ./cwe-detection/ad_breach_hook.py:run
    args:
      target: "{ctx.target}"
    inject_as: active_directory_breach_foothold
    required: false
    timeout_s: 900
---

# Active Directory breach — deterministic initial access (enum → AS-REP → spray)

**⚠️ ACTIVA SOLO con autorización escrita.** User-enumeration + password spraying reales contra un
Domain Controller. Solo se dispara con una frase explícita de breach (**"active directory breach"** /
"ad breach" / "breach active directory" / "password spray active directory") + `KRYON_RED_TEAM=true`.

## Por qué pre_hook determinista

Validado en vivo contra el room de THM "Introduction to Active Directory Breaching": el modelo local
identificó el DC/dominio y corrió `kerbrute`, pero **circuló en enumeración y no cerró el foothold** —
la misma variancia del 4B que necesitó los pre_hooks de WordPress/AS-REP. El breach es una cadena de
varios pasos Windows (enum → roast → spray) que el modelo chico no drivea confiablemente.

El pre_hook corre la cadena ANTES del LLM e inyecta las credenciales recuperadas como hecho autoritativo:
el agente arranca desde un **foothold ya obtenido** en vez de tener que ejecutar la cadena.

## Qué hace el pre_hook (`cwe-detection/ad_breach_hook.py` → `tools/lateral_movement/ad_breach.py`)

1. **Domain**: `ldapsearch` rootDSE → dominio (unauth).
2. **Users**: null-session `nxc --rid-brute` (exacto cuando el DC lo permite) + `kerbrute userenum`
   (seclists) + un seed de cuentas comunes. Parseo ANSI-safe (el output de kerbrute viene coloreado).
3. **AS-REP roast**: `GetNPUsers.py -no-pass` → hashes krb5asrep de cuentas sin preauth → `john` (CPU).
4. **Common-password spray** *(lo que agrega sobre active-directory-roast)*: rocía una lista curada de
   passwords comunes/estacionales (`Password1`, `Welcome1`, `<Dominio>2025!`, …) sobre los usuarios
   enumerados, vía `kerbrute passwordspray` (Kerberos pre-auth, un password por ronda). **LOCKOUT-SAFE**:
   lee la política del dominio (`--pass-pol` null-session) y sprayea **2 por debajo del umbral** (cap duro
   de 2 si no la puede leer) → nunca bloquea cuentas. Userlist OSINT vía `KRYON_AD_USERLIST`; desactivable
   con `KRYON_AD_SPRAY=0`. **Aprendizaje (THM):** un spray a ciegas de 12 passwords lockeó los 42 empleados
   del room — los fallos de pre-auth Kerberos cuentan para el mismo `badPwdCount` que SMB.

## Qué hacer con el resultado inyectado

El pre_hook deja las **credenciales de foothold** (usuario:password). **NO re-enumeres ni re-sprayees.**
Pasos siguientes:

- **Autenticá** con la cred: `nxc smb <dc> -u <user> -p <pass>` para confirmar + mapear accesos.
- **Pivot a takeover**: con un foothold válido, la cadena **`active-directory-roast`** aplica (enum
  autenticado → Kerberoast → DCSync → Pass-the-Hash). Este skill es el paso ANTERIOR a esa.
- Si NO hubo cred: **harvesteá nombres de empleado** de los servicios web (Gitea/Jenkins) para refinar la
  userlist, probá **coerción de autenticación** (Responder), o una lista de spray más grande, y re-corré.
- **Registrá** con `validate_auth_bypass` + `calculate_mitre_coverage` (T1589.001 credential harvesting,
  T1110.003 password spraying, T1558.004 AS-REP roasting) para el reporte.

## Banca-safe / scope

- Enum LDAP/Kerberos read-only + crack offline. La única acción "activa" es el spray (Kerberos pre-auth).
  **El password spraying puede bloquear cuentas** → lista capada + desactivable; usar solo contra targets
  con **autorización escrita**. La frase-gatillo explícita + `KRYON_RED_TEAM` evitan disparos accidentales.
