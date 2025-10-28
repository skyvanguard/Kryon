"""
Network tools wrapper for Skynet framework.
Provides convenient interfaces to network security tools.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from ..core.executor import CommandExecutor, ExecutionResult


@dataclass
class PortScanResult:
    """Result of a port scan."""
    target: str
    open_ports: List[Dict[str, Any]]
    scan_output: str
    success: bool


@dataclass
class DNSResult:
    """Result of DNS query."""
    domain: str
    records: Dict[str, List[str]]
    raw_output: str
    success: bool


class NetworkTools:
    """Wrapper for network reconnaissance and analysis tools."""

    def __init__(self):
        self.executor = CommandExecutor()

    def nmap_scan(
        self,
        target: str,
        ports: str = "1-1000",
        scan_type: str = "sV",
        timeout: int = 300
    ) -> PortScanResult:
        """
        Perform nmap port scan.

        Args:
            target: Target IP or hostname
            ports: Port range (e.g., "1-1000", "80,443", "all")
            scan_type: Nmap scan type (sV=version, sC=scripts, sS=syn, etc.)
            timeout: Scan timeout in seconds

        Returns:
            PortScanResult with scan details
        """
        if ports.lower() == "all":
            ports = "1-65535"

        command = f"nmap -p {ports} -{scan_type} {target}"
        result = self.executor.execute(command, timeout=timeout)

        open_ports = []
        if result.success:
            # Parse open ports from output
            for line in result.stdout.split('\n'):
                if '/tcp' in line or '/udp' in line:
                    parts = line.split()
                    if len(parts) >= 3 and 'open' in line:
                        port_info = {
                            'port': parts[0],
                            'state': parts[1],
                            'service': parts[2] if len(parts) > 2 else 'unknown'
                        }
                        open_ports.append(port_info)

        return PortScanResult(
            target=target,
            open_ports=open_ports,
            scan_output=result.stdout,
            success=result.success
        )

    def quick_scan(self, target: str) -> PortScanResult:
        """Perform a quick scan of common ports."""
        return self.nmap_scan(target, ports="21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080,8443")

    def dns_lookup(self, domain: str, record_type: str = "A") -> DNSResult:
        """
        Perform DNS lookup.

        Args:
            domain: Domain to query
            record_type: DNS record type (A, AAAA, MX, TXT, etc.)

        Returns:
            DNSResult with records
        """
        command = f"dig {domain} {record_type} +short"
        result = self.executor.execute(command, timeout=30)

        records = {record_type: []}
        if result.success:
            records[record_type] = [
                line.strip() for line in result.stdout.split('\n')
                if line.strip()
            ]

        return DNSResult(
            domain=domain,
            records=records,
            raw_output=result.stdout,
            success=result.success
        )

    def dns_enumerate(self, domain: str) -> DNSResult:
        """Enumerate all common DNS records for a domain."""
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA"]
        all_records = {}

        for rtype in record_types:
            result = self.dns_lookup(domain, rtype)
            if result.success:
                all_records[rtype] = result.records[rtype]

        return DNSResult(
            domain=domain,
            records=all_records,
            raw_output=str(all_records),
            success=True
        )

    def netcat_connect(
        self,
        host: str,
        port: int,
        data: Optional[str] = None,
        timeout: int = 10
    ) -> ExecutionResult:
        """
        Connect to a host using netcat.

        Args:
            host: Target host
            port: Target port
            data: Optional data to send
            timeout: Connection timeout

        Returns:
            ExecutionResult with response
        """
        if data:
            command = f"echo '{data}' | nc {host} {port}"
        else:
            command = f"nc -w {timeout} {host} {port}"

        return self.executor.execute(command, timeout=timeout + 5)

    def ping(self, host: str, count: int = 4) -> ExecutionResult:
        """
        Ping a host.

        Args:
            host: Target host
            count: Number of pings

        Returns:
            ExecutionResult with ping statistics
        """
        command = f"ping -c {count} {host}"
        return self.executor.execute(command, timeout=count + 10)

    def traceroute(self, host: str) -> ExecutionResult:
        """
        Trace route to a host.

        Args:
            host: Target host

        Returns:
            ExecutionResult with route
        """
        command = f"traceroute {host}"
        return self.executor.execute(command, timeout=60)

    def whois_lookup(self, target: str) -> ExecutionResult:
        """
        Perform WHOIS lookup.

        Args:
            target: Domain or IP to query

        Returns:
            ExecutionResult with WHOIS information
        """
        command = f"whois {target}"
        return self.executor.execute(command, timeout=30)

    def subnet_scan(self, subnet: str) -> List[str]:
        """
        Scan a subnet for live hosts.

        Args:
            subnet: Subnet in CIDR notation (e.g., "192.168.1.0/24")

        Returns:
            List of live host IPs
        """
        command = f"nmap -sn {subnet}"
        result = self.executor.execute(command, timeout=300)

        live_hosts = []
        if result.success:
            for line in result.stdout.split('\n'):
                if 'Nmap scan report for' in line:
                    # Extract IP address
                    parts = line.split()
                    if len(parts) >= 5:
                        ip = parts[-1].strip('()')
                        live_hosts.append(ip)

        return live_hosts


# Convenience function
def get_network_tools() -> NetworkTools:
    """Get NetworkTools instance."""
    return NetworkTools()
