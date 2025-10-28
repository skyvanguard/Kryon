"""
Web exploitation tools wrapper for Skynet framework.
Provides convenient interfaces to web security tools.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path
from ..core.executor import CommandExecutor, ExecutionResult


@dataclass
class DirectoryBruteforceResult:
    """Result of directory bruteforce."""
    url: str
    found_paths: List[str]
    status_codes: Dict[str, int]
    success: bool


@dataclass
class SQLiTestResult:
    """Result of SQL injection test."""
    url: str
    vulnerable: bool
    injection_type: Optional[str]
    details: str
    success: bool


class WebTools:
    """Wrapper for web exploitation and analysis tools."""

    def __init__(self):
        self.executor = CommandExecutor()

    def curl_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[str] = None,
        follow_redirects: bool = True,
        timeout: int = 30
    ) -> ExecutionResult:
        """
        Perform HTTP request using curl.

        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            headers: Optional headers
            data: Optional request data
            follow_redirects: Follow HTTP redirects
            timeout: Request timeout

        Returns:
            ExecutionResult with response
        """
        command_parts = ["curl", "-X", method]

        if follow_redirects:
            command_parts.append("-L")

        if headers:
            for key, value in headers.items():
                command_parts.extend(["-H", f"{key}: {value}"])

        if data:
            command_parts.extend(["-d", data])

        command_parts.append(url)
        command = " ".join(f"'{part}'" if ' ' in str(part) else str(part) for part in command_parts)

        return self.executor.execute(command, timeout=timeout)

    def get_headers(self, url: str) -> Dict[str, str]:
        """
        Get HTTP headers for a URL.

        Args:
            url: Target URL

        Returns:
            Dictionary of headers
        """
        result = self.executor.execute(f"curl -I -s {url}", timeout=30)
        headers = {}

        if result.success:
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

        return headers

    def directory_bruteforce(
        self,
        url: str,
        wordlist: Optional[Path] = None,
        extensions: Optional[List[str]] = None,
        timeout: int = 300
    ) -> DirectoryBruteforceResult:
        """
        Brute force directories and files.

        Args:
            url: Base URL
            wordlist: Path to wordlist (uses common.txt by default)
            extensions: File extensions to try
            timeout: Scan timeout

        Returns:
            DirectoryBruteforceResult with found paths
        """
        if wordlist is None:
            wordlist = Path("/usr/share/wordlists/dirb/common.txt")

        command = f"gobuster dir -u {url} -w {wordlist} -q"

        if extensions:
            ext_string = ",".join(extensions)
            command += f" -x {ext_string}"

        result = self.executor.execute(command, timeout=timeout)

        found_paths = []
        status_codes = {}

        if result.success:
            for line in result.stdout.split('\n'):
                if line.strip() and not line.startswith('='):
                    # Parse gobuster output
                    parts = line.split()
                    if len(parts) >= 2:
                        path = parts[0]
                        status = parts[1].strip('()')
                        found_paths.append(path)
                        status_codes[path] = int(status) if status.isdigit() else 0

        return DirectoryBruteforceResult(
            url=url,
            found_paths=found_paths,
            status_codes=status_codes,
            success=result.success
        )

    def nikto_scan(self, url: str, timeout: int = 300) -> ExecutionResult:
        """
        Scan web application with Nikto.

        Args:
            url: Target URL
            timeout: Scan timeout

        Returns:
            ExecutionResult with Nikto findings
        """
        command = f"nikto -h {url} -C all"
        return self.executor.execute(command, timeout=timeout)

    def sqlmap_test(
        self,
        url: str,
        param: Optional[str] = None,
        level: int = 1,
        risk: int = 1,
        timeout: int = 300
    ) -> SQLiTestResult:
        """
        Test for SQL injection using sqlmap.

        Args:
            url: Target URL with parameters
            param: Specific parameter to test
            level: Detection level (1-5)
            risk: Risk level (1-3)
            timeout: Test timeout

        Returns:
            SQLiTestResult with findings
        """
        command = f"sqlmap -u '{url}' --batch --level={level} --risk={risk}"

        if param:
            command += f" -p {param}"

        result = self.executor.execute(command, timeout=timeout)

        vulnerable = False
        injection_type = None

        if result.success:
            output = result.stdout.lower()
            if 'is vulnerable' in output or 'parameter' in output and 'injectable' in output:
                vulnerable = True

                # Try to identify injection type
                if 'boolean' in output:
                    injection_type = "Boolean-based blind"
                elif 'time' in output:
                    injection_type = "Time-based blind"
                elif 'union' in output:
                    injection_type = "UNION query"
                elif 'error' in output:
                    injection_type = "Error-based"

        return SQLiTestResult(
            url=url,
            vulnerable=vulnerable,
            injection_type=injection_type,
            details=result.stdout,
            success=result.success
        )

    def xss_test(self, url: str, payloads: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Test for XSS vulnerabilities.

        Args:
            url: Target URL with parameter placeholder (e.g., http://site/search?q=FUZZ)
            payloads: Custom XSS payloads

        Returns:
            List of successful XSS vectors
        """
        if payloads is None:
            payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "'-alert(1)-'",
                "\"><script>alert(1)</script>",
                "javascript:alert(1)"
            ]

        results = []

        for payload in payloads:
            test_url = url.replace("FUZZ", payload)
            result = self.executor.execute(f"curl -s '{test_url}'", timeout=10)

            if result.success and payload in result.stdout:
                results.append({
                    "payload": payload,
                    "reflected": True,
                    "url": test_url
                })

        return results

    def lfi_test(self, url: str) -> List[Dict[str, Any]]:
        """
        Test for Local File Inclusion.

        Args:
            url: Base URL (should have a file parameter placeholder: FUZZ)

        Returns:
            List of successful LFI payloads
        """
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "/etc/passwd%00",
            "....//....//....//....//etc/passwd"
        ]

        results = []

        for payload in payloads:
            test_url = url.replace("FUZZ", payload)
            result = self.executor.execute(f"curl -s '{test_url}'", timeout=10)

            if result.success:
                # Check for signs of successful LFI
                indicators = ["root:", "Administrator", "<?php", "bin/bash"]
                for indicator in indicators:
                    if indicator in result.stdout:
                        results.append({
                            "payload": payload,
                            "vulnerable": True,
                            "indicator": indicator,
                            "url": test_url
                        })
                        break

        return results

    def waf_detect(self, url: str) -> Dict[str, Any]:
        """
        Detect Web Application Firewall.

        Args:
            url: Target URL

        Returns:
            WAF detection results
        """
        # Use wafw00f if available
        result = self.executor.execute(f"wafw00f {url}", timeout=60)

        waf_detected = False
        waf_name = None

        if result.success:
            output = result.stdout.lower()
            if "behind" in output or "protected" in output:
                waf_detected = True

                # Try to extract WAF name
                for line in result.stdout.split('\n'):
                    if "behind" in line.lower():
                        waf_name = line.split()[-1] if line.split() else None
                        break

        return {
            "url": url,
            "waf_detected": waf_detected,
            "waf_name": waf_name,
            "details": result.stdout
        }

    def subdomain_enum(self, domain: str, timeout: int = 300) -> List[str]:
        """
        Enumerate subdomains.

        Args:
            domain: Target domain
            timeout: Enumeration timeout

        Returns:
            List of discovered subdomains
        """
        # Try subfinder if available
        result = self.executor.execute(f"subfinder -d {domain} -silent", timeout=timeout)

        subdomains = []
        if result.success:
            subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]

        return subdomains

    def screenshot_url(self, url: str, output_path: Path) -> bool:
        """
        Take screenshot of a web page.

        Args:
            url: Target URL
            output_path: Path to save screenshot

        Returns:
            Success status
        """
        command = f"cutycapt --url={url} --out={output_path}"
        result = self.executor.execute(command, timeout=60)

        return result.success and output_path.exists()


# Convenience function
def get_web_tools() -> WebTools:
    """Get WebTools instance."""
    return WebTools()
