"""
KRYON Context Analyzer - NLP-Based Intelligence Extraction
===========================================================

Advanced context analysis system using NLP to extract valuable information
from text, logs, code comments, documentation, and command outputs.

Clearance Level: Omega-Intelligence (Intelligence Analysis Authority)
Classification: RESTRICTED
Mission: Extract maximum intelligence from all available data sources

Features:
- Credential extraction from 20+ formats
- Named Entity Recognition (usernames, IPs, emails, passwords)
- Hint following from comments and TODOs
- Attack surface extraction from documentation
- Pattern-based secret detection
- Automatic information correlation
"""

import json
import re
from collections import defaultdict
from datetime import datetime
from typing import Any


class ContextAnalyzer:
    """
    Advanced context analysis engine using NLP techniques.

    Extracts intelligence from:
    - Source code comments
    - Configuration files
    - Log files
    - Error messages
    - Documentation
    - Command outputs
    """

    def __init__(self):
        """Initialize context analyzer with pattern databases."""
        self.credential_patterns = self._build_credential_patterns()
        self.secret_patterns = self._build_secret_patterns()
        self.hint_patterns = self._build_hint_patterns()
        self.entity_patterns = self._build_entity_patterns()

    def _build_credential_patterns(self) -> dict[str, re.Pattern]:
        """Build regex patterns for credential detection."""
        return {
            # Password patterns
            "password_assignment": re.compile(
                r'(?:password|passwd|pwd|pass)\s*[=:]\s*["\']?([^"\'\s;,]+)["\']?', re.IGNORECASE
            ),
            "password_var": re.compile(r'(?:PASSWORD|PASSWD|PWD)\s*=\s*["\']?([^"\'\s;,]+)["\']?'),
            # API Key patterns
            "api_key": re.compile(
                r'(?:api[_-]?key|apikey|api[_-]?token)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,64})["\']?',
                re.IGNORECASE,
            ),
            # Database connection strings
            "mysql_connection": re.compile(r"mysql://([^:]+):([^@]+)@([^/]+)/(\w+)", re.IGNORECASE),
            "postgresql_connection": re.compile(r"postgres(?:ql)?://([^:]+):([^@]+)@([^/]+)/(\w+)", re.IGNORECASE),
            # SSH/Private keys
            "ssh_private_key": re.compile(r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----", re.IGNORECASE),
            # JWT tokens
            "jwt_token": re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
            # AWS credentials
            "aws_access_key": re.compile(r"(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
            "aws_secret_key": re.compile(
                r'(?:aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?',
                re.IGNORECASE,
            ),
            # Generic secrets
            "generic_secret": re.compile(
                r'(?:secret|token|key)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', re.IGNORECASE
            ),
            # Basic auth
            "basic_auth": re.compile(
                r'(?:username|user)\s*[=:]\s*["\']?([^"\'\s;,]+)["\']?.*?(?:password|pass)\s*[=:]\s*["\']?([^"\'\s;,]+)["\']?',
                re.IGNORECASE | re.DOTALL,
            ),
        }

    def _build_secret_patterns(self) -> dict[str, re.Pattern]:
        """Build patterns for detecting secrets and sensitive data."""
        return {
            "credit_card": re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
            "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
            "ipv4": re.compile(
                r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            ),
            "url": re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
            "hash_md5": re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE),
            "hash_sha1": re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE),
            "hash_sha256": re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE),
        }

    def _build_hint_patterns(self) -> dict[str, re.Pattern]:
        """Build patterns for detecting hints in comments."""
        return {
            "todo": re.compile(r"(?:TODO|FIXME|XXX|HACK|BUG):\s*(.+)", re.IGNORECASE),
            "vulnerability_hint": re.compile(
                r"(?:vulnerable|vuln|exploit|bug|flaw|weakness|injection|xss|sqli|rce)\s+(?:in|at|on)\s+(\S+)",
                re.IGNORECASE,
            ),
            "credential_hint": re.compile(
                r'(?:default|backup|temp(?:orary)?|test)\s+(?:password|pass|pwd|credential|login)(?:\s+is|\s*[=:])\s*["\']?(\S+)',
                re.IGNORECASE,
            ),
            "access_hint": re.compile(
                r"(?:admin|debug|dev|developer)\s+(?:panel|page|console|interface|mode)\s+(?:at|on|:)\s*(\S+)",
                re.IGNORECASE,
            ),
            "port_hint": re.compile(r"(?:port|service)\s+(\d{1,5})\s+(?:is|runs?|listening|open)", re.IGNORECASE),
            "path_hint": re.compile(
                r"(?:backup|old|deprecated|legacy)\s+(?:at|in|location)\s+([/\\]\S+)", re.IGNORECASE
            ),
        }

    def _build_entity_patterns(self) -> dict[str, re.Pattern]:
        """Build patterns for Named Entity Recognition."""
        return {
            "username": re.compile(
                r'(?:user(?:name)?|login|account)\s*[=:]\s*["\']?([a-zA-Z0-9_.-]+)["\']?',
                re.IGNORECASE,
            ),
            "hostname": re.compile(r'(?:host(?:name)?|server)\s*[=:]\s*["\']?([a-zA-Z0-9_.-]+)["\']?', re.IGNORECASE),
            "database": re.compile(r'(?:database|db|schema)\s*[=:]\s*["\']?([a-zA-Z0-9_.-]+)["\']?', re.IGNORECASE),
            "table": re.compile(r'(?:table|collection)\s*[=:]\s*["\']?([a-zA-Z0-9_.-]+)["\']?', re.IGNORECASE),
            "version": re.compile(r'(?:version|ver|v)\s*[=:]\s*["\']?([\d.]+)["\']?', re.IGNORECASE),
        }

    def autonomous_context_analysis(
        self, target_data: dict[str, Any], operation_objective: str = "general"
    ) -> dict[str, Any]:
        """
        Perform comprehensive context analysis on target data.

        Args:
            target_data: Data to analyze (files, outputs, web pages, etc.)
            operation_objective: Current operation objective

        Returns:
            Dictionary with extracted intelligence
        """
        results = {
            "credentials_found": [],
            "secrets_found": [],
            "hints_discovered": [],
            "entities_extracted": defaultdict(list),
            "attack_surface": [],
            "recommendations": [],
            "confidence_score": 0.0,
            "analysis_metadata": {
                "analyzed_at": datetime.now().isoformat(),
                "data_sources": list(target_data.keys()),
                "objective": operation_objective,
            },
        }

        total_confidence = 0.0
        analyzed_sources = 0

        # Analyze each data source
        for source_type, source_data in target_data.items():
            if isinstance(source_data, str):
                text = source_data
            elif isinstance(source_data, list):
                text = "\n".join(str(item) for item in source_data)
            elif isinstance(source_data, dict):
                text = json.dumps(source_data, indent=2)
            else:
                text = str(source_data)

            # Extract credentials
            creds = self.extract_credentials_from_text(text, source_type)
            results["credentials_found"].extend(creds)

            # Extract secrets
            secrets = self._extract_secrets(text)
            results["secrets_found"].extend(secrets)

            # Extract hints
            hints = self._extract_hints(text)
            results["hints_discovered"].extend(hints)

            # Extract entities
            entities = self._extract_entities(text)
            for entity_type, entity_values in entities.items():
                results["entities_extracted"][entity_type].extend(entity_values)

            # Update confidence
            if creds or secrets or hints:
                total_confidence += 0.8
            else:
                total_confidence += 0.3

            analyzed_sources += 1

        # Calculate overall confidence
        if analyzed_sources > 0:
            results["confidence_score"] = min(1.0, total_confidence / analyzed_sources)

        # Deduplicate findings
        results["credentials_found"] = self._deduplicate_credentials(results["credentials_found"])
        results["secrets_found"] = list({tuple(s.items()) for s in results["secrets_found"]})
        results["secrets_found"] = [dict(s) for s in results["secrets_found"]]

        # Convert defaultdict to regular dict
        results["entities_extracted"] = dict(results["entities_extracted"])

        # Generate recommendations
        results["recommendations"] = self._generate_recommendations(results, operation_objective)

        # Extract attack surface
        if "documentation" in target_data or "web_content" in target_data:
            results["attack_surface"] = self.extract_attack_surface_from_docs(
                target_data.get("documentation", "") + target_data.get("web_content", "")
            )

        return results

    def extract_credentials_from_text(self, text: str, context: str = "general") -> list[dict[str, Any]]:
        """
        Extract credentials from any text using pattern matching.

        Args:
            text: Text to analyze
            context: Context of the text (source_code, config, log, etc.)

        Returns:
            List of found credentials
        """
        credentials = []

        for pattern_name, pattern in self.credential_patterns.items():
            matches = pattern.finditer(text)

            for match in matches:
                if pattern_name == "mysql_connection":
                    cred = {
                        "type": "mysql_connection",
                        "username": match.group(1),
                        "password": match.group(2),
                        "host": match.group(3),
                        "database": match.group(4),
                        "context": context,
                        "confidence": 0.95,
                    }
                elif pattern_name == "postgresql_connection":
                    cred = {
                        "type": "postgresql_connection",
                        "username": match.group(1),
                        "password": match.group(2),
                        "host": match.group(3),
                        "database": match.group(4),
                        "context": context,
                        "confidence": 0.95,
                    }
                elif pattern_name == "basic_auth":
                    cred = {
                        "type": "username_password",
                        "username": match.group(1),
                        "password": match.group(2),
                        "context": context,
                        "confidence": 0.90,
                    }
                elif pattern_name == "ssh_private_key":
                    # Extract full key
                    key_start = match.start()
                    key_end = text.find("-----END", key_start)
                    if key_end != -1:
                        full_key = text[key_start : key_end + 50]
                        cred = {
                            "type": "ssh_private_key",
                            "key": full_key,
                            "context": context,
                            "confidence": 1.0,
                        }
                    else:
                        continue
                else:
                    # Single value patterns
                    cred = {
                        "type": pattern_name,
                        "value": match.group(1) if match.groups() else match.group(0),
                        "context": context,
                        "confidence": 0.85 if "generic" in pattern_name else 0.90,
                    }

                credentials.append(cred)

        return credentials

    def _extract_secrets(self, text: str) -> list[dict[str, Any]]:
        """Extract secrets and sensitive data."""
        secrets = []

        for secret_type, pattern in self.secret_patterns.items():
            matches = pattern.finditer(text)

            for match in matches:
                secret = {
                    "type": secret_type,
                    "value": match.group(0),
                    "position": match.start(),
                    "confidence": 0.80,
                }

                # Higher confidence for certain types
                if secret_type in ["email", "ipv4", "url"]:
                    secret["confidence"] = 0.95

                secrets.append(secret)

        return secrets

    def _extract_hints(self, text: str) -> list[dict[str, Any]]:
        """Extract hints from comments and text."""
        hints = []

        for hint_type, pattern in self.hint_patterns.items():
            matches = pattern.finditer(text)

            for match in matches:
                hint = {
                    "type": hint_type,
                    "content": match.group(1) if match.groups() else match.group(0),
                    "full_match": match.group(0),
                    "actionable": True,
                    "priority": "medium",
                }

                # Prioritize certain hints
                if hint_type in ["vulnerability_hint", "credential_hint"]:
                    hint["priority"] = "high"

                hints.append(hint)

        return hints

    def _extract_entities(self, text: str) -> dict[str, list[str]]:
        """Extract named entities."""
        entities = defaultdict(list)

        for entity_type, pattern in self.entity_patterns.items():
            matches = pattern.finditer(text)

            for match in matches:
                value = match.group(1) if match.groups() else match.group(0)
                entities[entity_type].append(value)

        # Deduplicate
        for entity_type in entities:
            entities[entity_type] = list(set(entities[entity_type]))

        return entities

    def autonomous_hint_following(
        self, hints: list[dict[str, Any]], current_access: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Generate actionable tasks from discovered hints.

        Args:
            hints: List of hints discovered
            current_access: Current access level and capabilities

        Returns:
            List of actionable tasks
        """
        tasks = []

        for hint in hints:
            hint_type = hint.get("type")
            content = hint.get("content", "")

            if hint_type == "todo":
                # Parse TODO for vulnerability hints
                if any(keyword in content.lower() for keyword in ["sql", "injection", "xss", "vuln"]):
                    tasks.append(
                        {
                            "action": "test_vulnerability",
                            "target": self._extract_target_from_hint(content),
                            "vulnerability_type": self._extract_vuln_type(content),
                            "priority": "high",
                            "source": "TODO comment",
                        }
                    )

            elif hint_type == "vulnerability_hint":
                tasks.append(
                    {
                        "action": "exploit_vulnerability",
                        "target": content,
                        "priority": "high",
                        "source": "vulnerability hint",
                    }
                )

            elif hint_type == "credential_hint":
                tasks.append(
                    {
                        "action": "try_credentials",
                        "credentials": content,
                        "services": ["ssh", "ftp", "mysql", "web_login"],
                        "priority": "high",
                        "source": "credential hint",
                    }
                )

            elif hint_type == "access_hint":
                tasks.append(
                    {
                        "action": "access_endpoint",
                        "endpoint": content,
                        "priority": "medium",
                        "source": "access hint",
                    }
                )

            elif hint_type == "port_hint":
                port = re.search(r"\d+", content)
                if port:
                    tasks.append(
                        {
                            "action": "scan_port",
                            "port": int(port.group(0)),
                            "priority": "medium",
                            "source": "port hint",
                        }
                    )

            elif hint_type == "path_hint":
                tasks.append(
                    {
                        "action": "check_path",
                        "path": content,
                        "priority": "medium",
                        "source": "path hint",
                    }
                )

        return tasks

    def extract_attack_surface_from_docs(self, documentation: str) -> dict[str, Any]:
        """
        Extract attack surface information from documentation.

        Args:
            documentation: Documentation text

        Returns:
            Dictionary with attack surface information
        """
        attack_surface = {
            "endpoints_discovered": [],
            "technologies_identified": [],
            "potential_vulnerabilities": [],
            "user_roles": [],
            "interesting_functions": [],
        }

        # Extract endpoints (URLs, API paths)
        url_pattern = re.compile(r"(?:GET|POST|PUT|DELETE|PATCH)\s+([/\w\-{}]+)", re.IGNORECASE)
        endpoints = url_pattern.findall(documentation)
        attack_surface["endpoints_discovered"] = list(set(endpoints))

        # Extract technologies
        tech_patterns = {
            "php": r"\b(?:PHP|php|\.php)\b",
            "python": r"\b(?:Python|Django|Flask|python)\b",
            "javascript": r"\b(?:JavaScript|Node\.js|React|Vue|Angular|js)\b",
            "java": r"\b(?:Java|Spring|Tomcat|JSP)\b",
            "ruby": r"\b(?:Ruby|Rails|ruby)\b",
            "database": r"\b(?:MySQL|PostgreSQL|MongoDB|Redis|SQLite|Oracle)\b",
        }

        for tech, pattern in tech_patterns.items():
            if re.search(pattern, documentation, re.IGNORECASE):
                attack_surface["technologies_identified"].append(tech)

        # Extract potential vulnerabilities based on functions
        vuln_keywords = {
            "file_upload": r"(?:upload|file upload|uploadFile)",
            "authentication": r"(?:login|signin|authenticate|auth)",
            "export": r"(?:export|download|generate report)",
            "import": r"(?:import|batch upload)",
            "debug": r"(?:debug mode|debugging|debug endpoint)",
            "admin": r"(?:admin panel|administration|admin access)",
        }

        for vuln_type, pattern in vuln_keywords.items():
            if re.search(pattern, documentation, re.IGNORECASE):
                attack_surface["potential_vulnerabilities"].append(vuln_type)

        # Extract user roles
        role_pattern = re.compile(r"(?:role|permission|privilege)\s*:\s*(\w+)", re.IGNORECASE)
        roles = role_pattern.findall(documentation)
        attack_surface["user_roles"] = list(set(roles))

        # Interesting functions
        function_pattern = re.compile(r"(?:function|def|public|private)\s+(\w+)", re.IGNORECASE)
        functions = function_pattern.findall(documentation)
        # Filter for interesting names
        interesting = [
            f
            for f in functions
            if any(
                keyword in f.lower()
                for keyword in [
                    "admin",
                    "debug",
                    "test",
                    "upload",
                    "download",
                    "execute",
                    "eval",
                    "system",
                ]
            )
        ]
        attack_surface["interesting_functions"] = list(set(interesting))[:20]  # Top 20

        return attack_surface

    def _deduplicate_credentials(self, credentials: list[dict]) -> list[dict]:
        """Remove duplicate credentials."""
        seen = set()
        unique = []

        for cred in credentials:
            # Create identifier based on type and value
            if cred["type"] in ["mysql_connection", "postgresql_connection"]:
                identifier = (cred["type"], cred.get("username"), cred.get("host"))
            elif cred["type"] == "username_password":
                identifier = (cred["type"], cred.get("username"))
            else:
                identifier = (cred["type"], cred.get("value", "")[:50])

            if identifier not in seen:
                seen.add(identifier)
                unique.append(cred)

        return unique

    def _generate_recommendations(self, analysis_results: dict[str, Any], objective: str) -> list[str]:
        """Generate actionable recommendations from analysis."""
        recommendations = []

        # Credential recommendations
        creds_count = len(analysis_results["credentials_found"])
        if creds_count > 0:
            recommendations.append(f"Try {creds_count} discovered credential(s) on all accessible services")

        # Hint recommendations
        high_priority_hints = [h for h in analysis_results["hints_discovered"] if h.get("priority") == "high"]
        if high_priority_hints:
            recommendations.append(f"Investigate {len(high_priority_hints)} high-priority hint(s) immediately")

        # Entity recommendations
        usernames = analysis_results["entities_extracted"].get("username", [])
        if usernames:
            recommendations.append(f"Attempt password spray/bruteforce with {len(usernames)} discovered username(s)")

        # Secret recommendations
        if analysis_results["secrets_found"]:
            recommendations.append("Review discovered secrets for API keys or tokens that may grant access")

        return recommendations

    def _extract_target_from_hint(self, hint_text: str) -> str:
        """Extract target from hint text."""
        # Try to find paths, URLs, or endpoints
        path_match = re.search(r"[/\w\-\.]+", hint_text)
        return path_match.group(0) if path_match else "unknown"

    def _extract_vuln_type(self, hint_text: str) -> str:
        """Extract vulnerability type from hint text."""
        hint_lower = hint_text.lower()

        if "sql" in hint_lower or "injection" in hint_lower:
            return "sqli"
        elif "xss" in hint_lower:
            return "xss"
        elif "rce" in hint_lower or "remote code" in hint_lower:
            return "rce"
        elif "lfi" in hint_lower or "local file" in hint_lower:
            return "lfi"
        elif "rfi" in hint_lower or "remote file" in hint_lower:
            return "rfi"
        else:
            return "unknown"


# Convenience functions
def analyze_context(target_data: dict[str, Any], operation_objective: str = "general") -> dict[str, Any]:
    """
    Analyze context and extract intelligence.

    Args:
        target_data: Data to analyze
        operation_objective: Current objective

    Returns:
        Analysis results
    """
    analyzer = ContextAnalyzer()
    return analyzer.autonomous_context_analysis(target_data, operation_objective)


def extract_credentials(text: str, context: str = "general") -> list[dict[str, Any]]:
    """
    Extract credentials from text.

    Args:
        text: Text to analyze
        context: Context of text

    Returns:
        List of credentials found
    """
    analyzer = ContextAnalyzer()
    return analyzer.extract_credentials_from_text(text, context)


def follow_hints(hints: list[dict[str, Any]], current_access: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Generate tasks from hints.

    Args:
        hints: Discovered hints
        current_access: Current access level

    Returns:
        List of actionable tasks
    """
    analyzer = ContextAnalyzer()
    return analyzer.autonomous_hint_following(hints, current_access)


def extract_attack_surface(documentation: str) -> dict[str, Any]:
    """
    Extract attack surface from documentation.

    Args:
        documentation: Documentation text

    Returns:
        Attack surface information
    """
    analyzer = ContextAnalyzer()
    return analyzer.extract_attack_surface_from_docs(documentation)
