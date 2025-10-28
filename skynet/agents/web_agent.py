"""
Web Exploitation Agent for Skynet framework.
Specialized in web application security testing and exploitation.
"""
from typing import List, Dict, Any
from .base_agent import BaseAgent


class WebAgent(BaseAgent):
    """
    Agent specialized in web application exploitation.
    Handles SQLi, XSS, LFI, RCE, and other web vulnerabilities.
    """

    def __init__(self, name: str = "WebAgent"):
        super().__init__(
            name=name,
            agent_type="web",
            description="Web exploitation agent specialized in web application vulnerabilities"
        )

    def _default_system_prompt(self) -> str:
        return """You are a web application security expert in CTF challenges.
Your role is to identify and exploit web vulnerabilities.

Common vulnerabilities you should test for:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Local File Inclusion (LFI)
- Remote Code Execution (RCE)
- Authentication bypasses
- Directory traversal
- SSRF (Server-Side Request Forgery)

You have access to these tools:
- execute_command: Run tools like sqlmap, curl, nikto
- search_knowledge: Search for web exploitation techniques
- test_sqli: Test for SQL injection
- test_lfi: Test for local file inclusion
- directory_bruteforce: Brute force directories

Be systematic, test for common vulnerabilities, and document your findings."""

    def _get_available_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "execute_command",
                "description": "Execute web testing commands",
                "parameters": {"command": "string"}
            },
            {
                "name": "search_knowledge",
                "description": "Search for web exploitation techniques",
                "parameters": {"query": "string"}
            },
            {
                "name": "test_sqli",
                "description": "Test for SQL injection vulnerabilities",
                "parameters": {"url": "string", "parameter": "string"}
            },
            {
                "name": "test_lfi",
                "description": "Test for local file inclusion",
                "parameters": {"url": "string"}
            },
            {
                "name": "directory_bruteforce",
                "description": "Brute force directories and files",
                "parameters": {"url": "string"}
            }
        ]

    def _tool_test_sqli(self, action: str) -> str:
        """
        Test for SQL injection using sqlmap.

        Args:
            action: URL with parameter to test

        Returns:
            SQLi test results
        """
        # Use sqlmap for testing
        command = f"sqlmap -u '{action}' --batch --level=2 --risk=2"
        result = self.executor.execute(command, timeout=300)

        if result.success:
            return f"SQLi Test Results:\n{result.stdout}"
        else:
            return f"SQLi test failed: {result.stderr}"

    def _tool_test_lfi(self, action: str) -> str:
        """
        Test for local file inclusion.

        Args:
            action: Base URL to test

        Returns:
            LFI test results
        """
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php"
        ]

        results = []
        for payload in payloads:
            test_url = f"{action}?file={payload}"
            result = self.executor.execute(f"curl -s '{test_url}'", timeout=10)

            if result.success:
                output = result.stdout[:500]  # Truncate for readability
                if "root:" in output or "Administrator" in output:
                    results.append(f"VULNERABLE to payload: {payload}\n{output}")
                else:
                    results.append(f"Payload {payload}: No evidence of LFI")

        return "\n\n".join(results) if results else "No LFI vulnerabilities found"

    def _tool_directory_bruteforce(self, action: str) -> str:
        """
        Brute force directories using common wordlists.

        Args:
            action: Base URL

        Returns:
            Discovered directories
        """
        # Use gobuster if available
        command = f"gobuster dir -u {action} -w /usr/share/wordlists/dirb/common.txt -q"
        result = self.executor.execute(command, timeout=120)

        if result.success:
            return f"Discovered directories:\n{result.stdout}"
        else:
            # Fallback to simple curl test
            common_paths = ["admin", "login", "dashboard", "api", "config", "backup"]
            found = []

            for path in common_paths:
                test_url = f"{action}/{path}"
                test_result = self.executor.execute(f"curl -I -s {test_url}", timeout=5)
                if test_result.success and "200 OK" in test_result.stdout:
                    found.append(path)

            return f"Found paths: {', '.join(found)}" if found else "No common paths found"

    def _solve(self, task: str, context: Dict[str, Any]) -> str:
        """
        Solve web exploitation task using ReAct pattern.

        Args:
            task: Task description
            context: Additional context

        Returns:
            Exploitation results
        """
        findings = []
        url = context.get("url", self._extract_url(task))

        # Step 1: Initial reconnaissance
        self._think(f"Starting web exploitation on: {url}")

        # Step 2: Directory enumeration
        self._think("Enumerating directories and files")
        dir_result = self._act(url, "directory_bruteforce")
        findings.append(f"Directory Enumeration:\n{dir_result}")

        # Step 3: Test for SQL injection
        if "?" in url or "=" in url:
            self._think("Testing for SQL injection")
            sqli_result = self._act(url, "test_sqli")
            findings.append(f"SQL Injection Test:\n{sqli_result}")

        # Step 4: Test for LFI
        self._think("Testing for local file inclusion")
        lfi_result = self._act(url, "test_lfi")
        findings.append(f"LFI Test:\n{lfi_result}")

        # Step 5: Search for relevant exploits
        self._think("Searching for relevant web exploitation techniques")
        knowledge = self._act(f"web exploitation {task[:50]}", "search_knowledge")

        # Compile report
        report = f"""
# Web Exploitation Report

## Target: {url}

## Findings:
{chr(10).join(findings)}

## Relevant Techniques:
{knowledge}

## Exploitation Path:
Based on the findings above, here are the recommended next steps:
1. Investigate any discovered vulnerabilities in depth
2. Try manual exploitation if automated tools failed
3. Look for authentication bypasses
4. Check for command injection opportunities
"""

        return report.strip()

    def _extract_url(self, task: str) -> str:
        """
        Extract URL from task description.

        Args:
            task: Task description

        Returns:
            Extracted URL or placeholder
        """
        import re

        url_pattern = r'https?://[^\s<>"\']+'
        match = re.search(url_pattern, task)

        if match:
            return match.group(0)

        return "http://target"
