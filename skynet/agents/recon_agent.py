"""
Reconnaissance Agent for Skynet framework.
Specialized in information gathering, port scanning, and initial enumeration.
"""
from typing import List, Dict, Any
from .base_agent import BaseAgent


class ReconAgent(BaseAgent):
    """
    Agent specialized in reconnaissance and information gathering.
    Uses tools like nmap, dig, whois, etc.
    """

    def __init__(self, name: str = "ReconAgent"):
        super().__init__(
            name=name,
            agent_type="recon",
            description="Reconnaissance agent specialized in information gathering and enumeration"
        )

    def _default_system_prompt(self) -> str:
        return """You are a reconnaissance specialist in cybersecurity CTF challenges.
Your role is to gather information about targets, enumerate services, and identify potential attack vectors.

You have access to these tools:
- execute_command: Run system commands (nmap, dig, whois, curl, etc.)
- search_knowledge: Search for reconnaissance techniques and methods
- read_file: Read files from the filesystem
- write_file: Write results to files

Follow the ReAct pattern:
1. THOUGHT: Analyze what information you need
2. ACTION: Use a tool to gather that information
3. OBSERVATION: Analyze the results
4. Repeat until you have a complete picture

Be thorough, methodical, and document your findings."""

    def _get_available_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "execute_command",
                "description": "Execute reconnaissance commands (nmap, dig, whois, curl, etc.)",
                "parameters": {"command": "string"}
            },
            {
                "name": "search_knowledge",
                "description": "Search for reconnaissance techniques",
                "parameters": {"query": "string"}
            },
            {
                "name": "scan_ports",
                "description": "Scan ports on a target",
                "parameters": {"target": "string", "ports": "string"}
            },
            {
                "name": "enumerate_web",
                "description": "Enumerate web application",
                "parameters": {"url": "string"}
            }
        ]

    def _tool_scan_ports(self, action: str) -> str:
        """
        Tool for port scanning using nmap.

        Args:
            action: Target in format "host:ports" (e.g., "192.168.1.1:1-1000")

        Returns:
            Scan results
        """
        parts = action.split(":")
        if len(parts) != 2:
            return "Invalid format. Use: host:ports (e.g., 192.168.1.1:1-1000)"

        host, ports = parts

        # Use nmap for scanning
        command = f"nmap -p {ports} -sV -sC {host}"
        result = self.executor.execute(command, timeout=300)

        if result.success:
            return f"Port scan results:\n{result.stdout}"
        else:
            return f"Scan failed: {result.stderr}"

    def _tool_enumerate_web(self, action: str) -> str:
        """
        Tool for web application enumeration.

        Args:
            action: URL to enumerate

        Returns:
            Enumeration results
        """
        results = []

        # Basic HTTP request
        curl_result = self.executor.execute(f"curl -I {action}", timeout=30)
        if curl_result.success:
            results.append(f"HTTP Headers:\n{curl_result.stdout}")

        # Check robots.txt
        robots_result = self.executor.execute(f"curl -s {action}/robots.txt", timeout=10)
        if robots_result.success and "404" not in robots_result.stdout:
            results.append(f"robots.txt:\n{robots_result.stdout}")

        return "\n\n".join(results) if results else "No useful information gathered"

    def _solve(self, task: str, context: Dict[str, Any]) -> str:
        """
        Solve reconnaissance task using ReAct pattern.

        Args:
            task: Task description
            context: Additional context

        Returns:
            Reconnaissance findings
        """
        findings = []

        # Extract target from task (simple heuristic)
        target = context.get("target", self._extract_target(task))

        # Step 1: Initial information gathering
        self._think(f"Starting reconnaissance on target: {target}")

        # Step 2: DNS enumeration
        if target:
            self._think("Performing DNS enumeration")
            dns_result = self._act(f"dig {target}", "execute_command")
            findings.append(f"DNS Information:\n{dns_result}")

        # Step 3: Port scanning
        self._think("Scanning common ports")
        if target:
            scan_result = self._act(f"{target}:1-1000", "scan_ports")
            findings.append(f"Port Scan:\n{scan_result}")

        # Step 4: Web enumeration if HTTP/HTTPS ports are found
        if "80/tcp" in scan_result or "443/tcp" in scan_result:
            self._think("HTTP service detected, enumerating web application")
            protocol = "https" if "443/tcp" in scan_result else "http"
            web_result = self._act(f"{protocol}://{target}", "enumerate_web")
            findings.append(f"Web Enumeration:\n{web_result}")

        # Step 5: Search for related techniques
        self._think("Searching for additional reconnaissance techniques")
        knowledge = self._act(f"reconnaissance techniques for {task[:50]}", "search_knowledge")

        # Compile final report
        report = f"""
# Reconnaissance Report

## Target: {target}

## Findings:
{chr(10).join(findings)}

## Relevant Techniques:
{knowledge}

## Recommendations:
- Review open ports for potential vulnerabilities
- Enumerate discovered services further
- Check for common misconfigurations
"""

        return report.strip()

    def _extract_target(self, task: str) -> str:
        """
        Extract target (IP or domain) from task description.

        Args:
            task: Task description

        Returns:
            Extracted target or empty string
        """
        import re

        # Look for IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_match = re.search(ip_pattern, task)
        if ip_match:
            return ip_match.group(0)

        # Look for domain names
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        domain_match = re.search(domain_pattern, task)
        if domain_match:
            return domain_match.group(0)

        return ""
