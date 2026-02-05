"""
KRYON Decision Engine
======================

Intelligent exploit selection and prioritization for autonomous operations.

Clearance Level: Omega-Command (Autonomous Decision Authority)
Mission: Select optimal exploits based on service detection and success probability

This module provides:
- Exploit database with CVE mappings
- Service-to-exploit matching
- Success probability calculation
- Exploit prioritization based on multiple factors
- Difficulty-aware selection
"""

from enum import Enum
from typing import Any


class ExploitDifficulty(Enum):
    """Exploit difficulty levels."""

    TRIVIAL = 1  # One-click exploits
    EASY = 2  # Simple exploitation
    MEDIUM = 3  # Moderate skill required
    HARD = 4  # Advanced techniques needed
    EXPERT = 5  # Highly specialized exploitation


class ExploitType(Enum):
    """Types of exploits."""

    RCE = "remote_code_execution"
    LFI = "local_file_inclusion"
    RFI = "remote_file_inclusion"
    SQLI = "sql_injection"
    XSS = "cross_site_scripting"
    XXE = "xml_external_entity"
    SSRF = "server_side_request_forgery"
    AUTH_BYPASS = "authentication_bypass"
    PRIVESC = "privilege_escalation"
    INFO_DISCLOSURE = "information_disclosure"
    DOS = "denial_of_service"


# Exploit Database
EXPLOIT_DATABASE = {
    # Web Server Exploits
    "apache": {
        "Apache 2.4.49": {
            "exploit_name": "apache_path_traversal_cve_2021_41773",
            "exploit_type": ExploitType.RCE,
            "cve": "CVE-2021-41773",
            "severity": "critical",
            "success_rate": 0.95,
            "difficulty": ExploitDifficulty.EASY,
            "description": "Path traversal and RCE in Apache 2.4.49",
            "metasploit_module": "exploit/multi/http/apache_normalize_path_rce",
            "public_exploit": True,
            "requirements": [],
        },
        "Apache 2.4.50": {
            "exploit_name": "apache_path_traversal_cve_2021_42013",
            "exploit_type": ExploitType.RCE,
            "cve": "CVE-2021-42013",
            "severity": "critical",
            "success_rate": 0.93,
            "difficulty": ExploitDifficulty.EASY,
            "description": "Path traversal and RCE in Apache 2.4.50",
            "metasploit_module": "exploit/multi/http/apache_normalize_path_rce",
            "public_exploit": True,
            "requirements": [],
        },
        "Apache 2.4": {
            "exploit_name": "apache_generic_enum",
            "exploit_type": ExploitType.INFO_DISCLOSURE,
            "cve": None,
            "severity": "low",
            "success_rate": 0.70,
            "difficulty": ExploitDifficulty.TRIVIAL,
            "description": "Apache enumeration and info gathering",
            "metasploit_module": None,
            "public_exploit": True,
            "requirements": [],
        },
    },
    # SSH Exploits
    "ssh": {
        "OpenSSH 7.6": {
            "exploit_name": "openssh_username_enum_cve_2018_15473",
            "exploit_type": ExploitType.INFO_DISCLOSURE,
            "cve": "CVE-2018-15473",
            "severity": "medium",
            "success_rate": 0.85,
            "difficulty": ExploitDifficulty.EASY,
            "description": "Username enumeration in OpenSSH",
            "metasploit_module": "auxiliary/scanner/ssh/ssh_enumusers",
            "public_exploit": True,
            "requirements": [],
        },
        "OpenSSH": {
            "exploit_name": "ssh_bruteforce",
            "exploit_type": ExploitType.AUTH_BYPASS,
            "cve": None,
            "severity": "medium",
            "success_rate": 0.40,
            "difficulty": ExploitDifficulty.MEDIUM,
            "description": "SSH credential brute force",
            "metasploit_module": "auxiliary/scanner/ssh/ssh_login",
            "public_exploit": True,
            "requirements": ["wordlist"],
        },
    },
    # Database Exploits
    "mysql": {
        "MySQL 5.7": {
            "exploit_name": "mysql_default_creds",
            "exploit_type": ExploitType.AUTH_BYPASS,
            "cve": None,
            "severity": "high",
            "success_rate": 0.60,
            "difficulty": ExploitDifficulty.TRIVIAL,
            "description": "Try default MySQL credentials",
            "metasploit_module": "auxiliary/scanner/mysql/mysql_login",
            "public_exploit": True,
            "requirements": [],
        },
        "MySQL": {
            "exploit_name": "mysql_udf_privesc",
            "exploit_type": ExploitType.PRIVESC,
            "cve": None,
            "severity": "high",
            "success_rate": 0.50,
            "difficulty": ExploitDifficulty.HARD,
            "description": "MySQL UDF privilege escalation",
            "metasploit_module": "exploit/multi/mysql/mysql_udf_payload",
            "public_exploit": True,
            "requirements": ["mysql_access"],
        },
    },
    "postgresql": {
        "PostgreSQL": {
            "exploit_name": "postgresql_default_creds",
            "exploit_type": ExploitType.AUTH_BYPASS,
            "cve": None,
            "severity": "high",
            "success_rate": 0.55,
            "difficulty": ExploitDifficulty.TRIVIAL,
            "description": "Try default PostgreSQL credentials",
            "metasploit_module": None,
            "public_exploit": True,
            "requirements": [],
        }
    },
    # SMB/Windows Exploits
    "smb": {
        "SMBv1": {
            "exploit_name": "eternalblue_ms17_010",
            "exploit_type": ExploitType.RCE,
            "cve": "MS17-010",
            "severity": "critical",
            "success_rate": 0.90,
            "difficulty": ExploitDifficulty.EASY,
            "description": "EternalBlue SMBv1 RCE",
            "metasploit_module": "exploit/windows/smb/ms17_010_eternalblue",
            "public_exploit": True,
            "requirements": [],
        },
        "SMB": {
            "exploit_name": "smb_enum_shares",
            "exploit_type": ExploitType.INFO_DISCLOSURE,
            "cve": None,
            "severity": "low",
            "success_rate": 0.80,
            "difficulty": ExploitDifficulty.TRIVIAL,
            "description": "Enumerate SMB shares",
            "metasploit_module": "auxiliary/scanner/smb/smb_enumshares",
            "public_exploit": True,
            "requirements": [],
        },
    },
    # Web Application Exploits
    "http": {
        "nginx 1.18": {
            "exploit_name": "nginx_off_by_one",
            "exploit_type": ExploitType.INFO_DISCLOSURE,
            "cve": "CVE-2017-7529",
            "severity": "high",
            "success_rate": 0.75,
            "difficulty": ExploitDifficulty.MEDIUM,
            "description": "Nginx off-by-one heap overflow",
            "metasploit_module": None,
            "public_exploit": True,
            "requirements": [],
        },
        "WordPress": {
            "exploit_name": "wordpress_xmlrpc_bruteforce",
            "exploit_type": ExploitType.AUTH_BYPASS,
            "cve": None,
            "severity": "medium",
            "success_rate": 0.45,
            "difficulty": ExploitDifficulty.MEDIUM,
            "description": "WordPress XML-RPC brute force",
            "metasploit_module": "auxiliary/scanner/http/wordpress_xmlrpc_login",
            "public_exploit": True,
            "requirements": ["wordlist"],
        },
    },
    # RDP Exploits
    "rdp": {
        "RDP 10.0": {
            "exploit_name": "bluekeep_cve_2019_0708",
            "exploit_type": ExploitType.RCE,
            "cve": "CVE-2019-0708",
            "severity": "critical",
            "success_rate": 0.70,
            "difficulty": ExploitDifficulty.HARD,
            "description": "BlueKeep RDP RCE",
            "metasploit_module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
            "public_exploit": True,
            "requirements": [],
        },
        "RDP": {
            "exploit_name": "rdp_bruteforce",
            "exploit_type": ExploitType.AUTH_BYPASS,
            "cve": None,
            "severity": "medium",
            "success_rate": 0.35,
            "difficulty": ExploitDifficulty.MEDIUM,
            "description": "RDP credential brute force",
            "metasploit_module": "auxiliary/scanner/rdp/rdp_scanner",
            "public_exploit": True,
            "requirements": ["wordlist"],
        },
    },
    # FTP Exploits
    "ftp": {
        "ProFTPD 1.3.5": {
            "exploit_name": "proftpd_modcopy_exec",
            "exploit_type": ExploitType.RCE,
            "cve": "CVE-2015-3306",
            "severity": "critical",
            "success_rate": 0.85,
            "difficulty": ExploitDifficulty.MEDIUM,
            "description": "ProFTPD mod_copy RCE",
            "metasploit_module": "exploit/unix/ftp/proftpd_modcopy_exec",
            "public_exploit": True,
            "requirements": [],
        },
        "FTP": {
            "exploit_name": "ftp_anonymous_login",
            "exploit_type": ExploitType.AUTH_BYPASS,
            "cve": None,
            "severity": "medium",
            "success_rate": 0.50,
            "difficulty": ExploitDifficulty.TRIVIAL,
            "description": "Try anonymous FTP login",
            "metasploit_module": "auxiliary/scanner/ftp/anonymous",
            "public_exploit": True,
            "requirements": [],
        },
    },
}


def select_best_exploit(
    service_name: str,
    service_version: str = "",
    target_os: str = "auto",
    difficulty: str = "medium",
) -> dict[str, Any]:
    """
    Select the best exploit for a given service.

    This function analyzes the service and version to recommend the most
    appropriate exploit based on success probability, difficulty, and severity.

    Args:
        service_name: Name of the service (e.g., "http", "ssh", "mysql")
        service_version: Version string (e.g., "Apache 2.4.49", "OpenSSH 7.6")
        target_os: Operating system ("linux", "windows", "auto")
        difficulty: Challenge difficulty ("easy", "medium", "hard")

    Returns:
        Dictionary containing:
        - exploit_recommended: Whether an exploit was found
        - exploit_name: Name of the recommended exploit
        - exploit_type: Type of exploit (RCE, SQLi, etc.)
        - success_probability: Estimated success probability (0.0-1.0)
        - severity: Vulnerability severity
        - difficulty_level: Exploit difficulty
        - metasploit_module: Metasploit module name (if available)
        - description: Exploit description
        - requirements: List of requirements for the exploit

    Example:
        >>> result = select_best_exploit(
        ...     service_name="http",
        ...     service_version="Apache 2.4.49",
        ...     difficulty="medium"
        ... )
        >>> print(f"Recommended: {result['exploit_name']}")
        >>> print(f"Success rate: {result['success_probability']:.1%}")
    """
    # Normalize service name
    service_name = service_name.lower().strip()

    # Get exploit candidates for this service
    candidates = []

    if service_name in EXPLOIT_DATABASE:
        service_exploits = EXPLOIT_DATABASE[service_name]

        # First, try to find exact version match
        for version_key, exploit_info in service_exploits.items():
            if version_key.lower() in service_version.lower():
                candidates.append({**exploit_info, "version_match": "exact", "match_score": 1.0})

        # If no exact match, add generic exploits for this service
        if not candidates:
            for version_key, exploit_info in service_exploits.items():
                # Generic exploits have no specific version or are service name only
                if version_key == service_name.title() or version_key == service_name.upper():
                    candidates.append({**exploit_info, "version_match": "generic", "match_score": 0.6})

    # If no candidates found, return no recommendation
    if not candidates:
        return {
            "exploit_recommended": False,
            "exploit_name": None,
            "exploit_type": None,
            "success_probability": 0.0,
            "severity": None,
            "difficulty_level": None,
            "metasploit_module": None,
            "description": f"No known exploits for {service_name}",
            "requirements": [],
        }

    # Score and rank candidates
    ranked_candidates = _rank_exploits(candidates, difficulty, target_os)

    # Select best exploit
    best_exploit = ranked_candidates[0]

    return {
        "exploit_recommended": True,
        "exploit_name": best_exploit["exploit_name"],
        "exploit_type": best_exploit["exploit_type"].value,
        "success_probability": best_exploit["final_score"],
        "severity": best_exploit["severity"],
        "difficulty_level": best_exploit["difficulty"].name,
        "metasploit_module": best_exploit.get("metasploit_module"),
        "description": best_exploit["description"],
        "requirements": best_exploit.get("requirements", []),
        "cve": best_exploit.get("cve"),
    }


def _rank_exploits(exploits: list[dict[str, Any]], difficulty: str, target_os: str) -> list[dict[str, Any]]:
    """
    Rank exploits by composite score.

    Scoring factors:
    - Base success rate (from exploit database)
    - Version match quality (exact vs generic)
    - Severity (critical > high > medium > low)
    - Difficulty alignment (easier exploits for easy challenges)
    - Public exploit availability
    """
    difficulty_map = {"easy": 1, "medium": 2, "hard": 3, "expert": 4}

    severity_scores = {"critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4, "info": 0.2}

    target_difficulty = difficulty_map.get(difficulty.lower(), 2)

    for exploit in exploits:
        # Base score from success rate
        base_score = exploit.get("success_rate", 0.5)

        # Version match bonus
        match_score = exploit.get("match_score", 0.5)

        # Severity bonus
        severity_score = severity_scores.get(exploit.get("severity", "medium"), 0.6)

        # Difficulty alignment
        exploit_diff = exploit["difficulty"].value
        diff_delta = abs(exploit_diff - target_difficulty)
        difficulty_score = max(0.3, 1.0 - (diff_delta * 0.2))

        # Public exploit bonus
        public_bonus = 0.1 if exploit.get("public_exploit") else 0.0

        # Composite score
        final_score = (
            base_score * 0.40  # Base success rate (40%)
            + match_score * 0.25  # Version match (25%)
            + severity_score * 0.20  # Severity (20%)
            + difficulty_score * 0.15  # Difficulty alignment (15%)
        ) + public_bonus

        exploit["final_score"] = min(1.0, final_score)

    # Sort by final score (descending)
    ranked = sorted(exploits, key=lambda x: x["final_score"], reverse=True)

    return ranked


def get_all_exploits_for_service(service_name: str) -> list[dict[str, Any]]:
    """
    Get all known exploits for a service.

    Args:
        service_name: Service name (e.g., "http", "ssh")

    Returns:
        List of all exploits for the service
    """
    service_name = service_name.lower().strip()

    if service_name not in EXPLOIT_DATABASE:
        return []

    all_exploits = []
    for version_key, exploit_info in EXPLOIT_DATABASE[service_name].items():
        all_exploits.append({**exploit_info, "service_version": version_key})

    return all_exploits


def add_custom_exploit(service_name: str, version: str, exploit_info: dict[str, Any]) -> bool:
    """
    Add a custom exploit to the database.

    Args:
        service_name: Service name
        version: Service version
        exploit_info: Exploit information dictionary

    Returns:
        True if added successfully
    """
    service_name = service_name.lower().strip()

    if service_name not in EXPLOIT_DATABASE:
        EXPLOIT_DATABASE[service_name] = {}

    EXPLOIT_DATABASE[service_name][version] = exploit_info

    return True


def search_exploits_by_cve(cve_id: str) -> list[dict[str, Any]]:
    """
    Search for exploits by CVE ID.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-41773")

    Returns:
        List of matching exploits
    """
    matches = []

    for service_name, service_exploits in EXPLOIT_DATABASE.items():
        for version, exploit_info in service_exploits.items():
            if exploit_info.get("cve") == cve_id:
                matches.append({**exploit_info, "service": service_name, "version": version})

    return matches
