"""Enterprise Autonomous Pentesting Orchestrator.

Adapts the CTF-focused orchestrator pattern for enterprise vulnerability
assessments.  Supports CIDR scopes, rate-limited LLM calls (Groq free tier),
configurable stealth levels, and produces HTML/PDF reports via the Reporting
pillar.

Usage (CLI):
    kryon auto-scan 192.168.1.0/24 --profile standard --client "ACME Corp"

Usage (API):
    POST /api/scans/auto  { "targets": [...], "profile": "standard" }
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ScanProgress:
    """Tracks the state of a running enterprise scan."""

    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    status: str = "initializing"  # initializing|recon|vuln_scan|exploitation|reporting|completed|failed
    phase_progress: float = 0.0  # 0.0-1.0
    hosts_discovered: int = 0
    hosts_scanned: int = 0
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    start_time: float = field(default_factory=time.time)
    elapsed_seconds: float = 0.0
    log_messages: list[str] = field(default_factory=list)
    report_path: str | None = None
    error: str | None = None

    def log(self, message: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        entry = f"[{ts}] {message}"
        self.log_messages.append(entry)
        logger.info(entry)

    def to_dict(self) -> dict[str, Any]:
        self.elapsed_seconds = time.time() - self.start_time
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "phase_progress": round(self.phase_progress, 2),
            "hosts_discovered": self.hosts_discovered,
            "hosts_scanned": self.hosts_scanned,
            "findings_count": self.findings_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "log_messages": self.log_messages[-50:],  # keep last 50
            "report_path": self.report_path,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Scope helpers
# ---------------------------------------------------------------------------


def parse_scope(raw: str | list[str]) -> list[str]:
    """Parse scope into a list of individual IP addresses.

    Accepts: CIDR notation, single IPs, comma-separated values, or a list.
    """
    if isinstance(raw, str):
        raw = [s.strip() for s in raw.split(",") if s.strip()]

    ips: list[str] = []
    for entry in raw:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            if net.num_addresses <= 256:
                ips.extend(str(h) for h in net.hosts())
            else:
                # For large ranges, only take first 256
                for i, h in enumerate(net.hosts()):
                    if i >= 256:
                        break
                    ips.append(str(h))
        except ValueError:
            # Treat as hostname
            ips.append(entry)

    return ips


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class EnterpriseOrchestrator:
    """Orchestrates a multi-phase autonomous penetration test."""

    def __init__(
        self,
        scope: str | list[str],
        client_id: str = "",
        client_name: str = "",
        profile: str = "standard",
        max_time_hours: float = 4.0,
        stealth_level: str = "normal",
        rate_limiter: Any | None = None,
        progress_callback: Callable[[ScanProgress], None] | None = None,
        output_format: str = "html",
        output_path: str | None = None,
        compliance_frameworks: list[str] | None = None,
    ):
        self.targets = parse_scope(scope)
        self.client_id = client_id
        self.client_name = client_name or client_id
        self.profile = profile
        self.max_time_seconds = max_time_hours * 3600
        self.stealth_level = stealth_level
        self.rate_limiter = rate_limiter
        self._progress_cb = progress_callback
        self.output_format = output_format
        self.output_path = output_path
        self.compliance_frameworks = compliance_frameworks or []

        self.progress = ScanProgress()
        self._findings: list[Any] = []  # list[Finding]
        self._recon_results: dict[str, dict] = {}

    @property
    def findings(self) -> list:
        return self._findings

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    async def run(self) -> dict[str, Any]:
        """Execute the full enterprise pentest pipeline.

        Returns a dict with scan_id, findings, report_path, progress.
        """
        self.progress.log(f"Starting enterprise scan — {len(self.targets)} target(s), profile={self.profile}")
        self._notify()

        try:
            # Phase 1: Reconnaissance
            await self._phase_recon()

            # Phase 2: Vulnerability Assessment
            await self._phase_vuln_scan()

            # Phase 3: Exploitation (deep/enterprise_deep only)
            if self.profile in ("deep", "enterprise_deep"):
                await self._phase_exploitation()

            # Phase 4: Reporting
            await self._phase_reporting()

            self.progress.status = "completed"
            self.progress.phase_progress = 1.0
            self.progress.log(
                f"Scan completed — {self.progress.findings_count} findings "
                f"({self.progress.critical_count} critical, {self.progress.high_count} high)"
            )

        except asyncio.CancelledError:
            self.progress.status = "failed"
            self.progress.error = "Scan cancelled by user"
            self.progress.log("Scan cancelled")
        except Exception as exc:
            self.progress.status = "failed"
            self.progress.error = str(exc)
            self.progress.log(f"Scan failed: {exc}")
            logger.exception("Enterprise scan failed")

        self._notify()
        return {
            "scan_id": self.progress.scan_id,
            "status": self.progress.status,
            "findings_count": self.progress.findings_count,
            "critical_count": self.progress.critical_count,
            "high_count": self.progress.high_count,
            "report_path": self.progress.report_path,
            "elapsed_seconds": time.time() - self.progress.start_time,
            "error": self.progress.error,
        }

    # ------------------------------------------------------------------
    # Phase 1: Reconnaissance
    # ------------------------------------------------------------------

    async def _phase_recon(self) -> None:
        self.progress.status = "recon"
        self.progress.phase_progress = 0.0
        self.progress.log(f"Phase 1/4: Reconnaissance — scanning {len(self.targets)} target(s)")
        self._notify()

        for idx, target in enumerate(self.targets):
            if self._time_exceeded():
                self.progress.log("Time limit reached during recon phase")
                break

            self.progress.log(f"Scanning {target} ({idx + 1}/{len(self.targets)})")

            try:
                from kryon.tools.autonomous.auto_recon import full_auto_enumeration

                deep = self.profile in ("deep", "enterprise_deep")
                timeout_per_host = min(
                    300,  # 5 min max per host in recon
                    int(self.max_time_seconds * 0.25 / max(len(self.targets), 1)),
                )

                recon = await asyncio.to_thread(
                    full_auto_enumeration,
                    target_ip=target,
                    deep_scan=deep,
                    timeout=timeout_per_host,
                )

                if recon.get("success") and recon.get("open_ports"):
                    self._recon_results[target] = recon
                    self.progress.hosts_discovered += 1
                    ports_str = ", ".join(str(p["port"]) for p in recon["open_ports"][:5])
                    self.progress.log(f"  {target}: {len(recon['open_ports'])} ports ({ports_str})")
                else:
                    self.progress.log(f"  {target}: no open ports or scan failed")

            except Exception as exc:
                self.progress.log(f"  {target}: recon error — {exc}")

            self.progress.phase_progress = (idx + 1) / len(self.targets)
            self.progress.hosts_scanned = idx + 1
            self._notify()

        self.progress.log(f"Recon complete — {self.progress.hosts_discovered} live hosts discovered")

    # ------------------------------------------------------------------
    # Phase 2: Vulnerability Assessment (LLM-driven)
    # ------------------------------------------------------------------

    async def _phase_vuln_scan(self) -> None:
        self.progress.status = "vuln_scan"
        self.progress.phase_progress = 0.0
        self.progress.log(f"Phase 2/4: Vulnerability assessment — {len(self._recon_results)} host(s)")
        self._notify()

        if not self._recon_results:
            self.progress.log("No live hosts to assess — skipping")
            return

        hosts = list(self._recon_results.items())
        for idx, (target, recon) in enumerate(hosts):
            if self._time_exceeded():
                self.progress.log("Time limit reached during vuln scan")
                break

            self.progress.log(f"Assessing {target}")

            if self.rate_limiter:
                waited = await self.rate_limiter.acquire(estimated_tokens=1500)
                if waited > 0:
                    self.progress.log(f"  Rate limited — waited {waited:.1f}s")

            try:
                findings = await self._assess_host_vulns(target, recon)
                self._findings.extend(findings)
                self.progress.findings_count = len(self._findings)
                self.progress.critical_count = sum(
                    1 for f in self._findings if f.severity.value == "critical"
                )
                self.progress.high_count = sum(
                    1 for f in self._findings if f.severity.value == "high"
                )
                self.progress.log(f"  {target}: {len(findings)} findings")
            except Exception as exc:
                self.progress.log(f"  {target}: assessment error — {exc}")

            self.progress.phase_progress = (idx + 1) / len(hosts)
            self._notify()

    async def _assess_host_vulns(self, target: str, recon: dict) -> list:
        """Use LLM agent to assess vulnerabilities for a host."""
        from kryon.intelligence.models import Finding, Severity

        findings: list[Finding] = []

        # Convert recon vulnerabilities directly to findings
        for vuln in recon.get("vulnerabilities", []):
            sev_str = vuln.get("severity", "medium").lower()
            sev_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            severity = sev_map.get(sev_str, Severity.MEDIUM)

            finding = Finding(
                title=vuln.get("cve", vuln.get("name", "Vulnerability detected")),
                description=vuln.get("description", f"Vulnerability found on {target}"),
                severity=severity,
                cvss_score=vuln.get("cvss", None),
                affected_asset=target,
                tool_source="nmap/auto_recon",
                evidence=json.dumps(vuln, default=str),
            )
            findings.append(finding)

        # Generate findings from detected services (potential vulns)
        for service in recon.get("services_detected", []):
            svc_name = service.get("name", "unknown")
            svc_version = service.get("version", "")
            svc_port = service.get("port", 0)

            # Check for known vulnerable patterns
            vuln_findings = self._check_known_vulns(target, svc_name, svc_version, svc_port)
            findings.extend(vuln_findings)

        # Try LLM-based assessment if Runner is available
        try:
            findings.extend(await self._llm_vuln_assessment(target, recon))
        except Exception as exc:
            self.progress.log(f"  LLM assessment unavailable: {exc}")

        return findings

    def _check_known_vulns(self, target: str, service: str, version: str, port: int) -> list:
        """Check for well-known vulnerabilities based on service/version."""
        from kryon.intelligence.models import Finding, Severity

        findings: list[Finding] = []
        sv = f"{service} {version}".lower()

        # Apache path traversal (CVE-2021-41773 / CVE-2021-42013)
        if "apache" in sv and any(v in sv for v in ["2.4.49", "2.4.50"]):
            findings.append(
                Finding(
                    title="CVE-2021-41773 - Apache HTTP Server Path Traversal",
                    description="Apache HTTP Server 2.4.49/2.4.50 is vulnerable to path traversal and remote code execution.",
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    affected_asset=f"{target}:{port}",
                    tool_source="enterprise_orchestrator",
                    remediation="Upgrade Apache to version 2.4.51 or later.",
                )
            )

        # OpenSSH before 8.5 (various CVEs)
        if "openssh" in sv:
            try:
                ver_parts = version.split(".")
                major = int(ver_parts[0].replace("OpenSSH_", "").replace("openssh", ""))
                minor = int(ver_parts[1].split("p")[0]) if len(ver_parts) > 1 else 0
                if major < 8 or (major == 8 and minor < 5):
                    findings.append(
                        Finding(
                            title=f"Outdated OpenSSH ({version})",
                            description=f"OpenSSH {version} may be vulnerable to known CVEs. Consider upgrading.",
                            severity=Severity.MEDIUM,
                            affected_asset=f"{target}:{port}",
                            tool_source="enterprise_orchestrator",
                            remediation="Upgrade OpenSSH to the latest stable release.",
                        )
                    )
            except (ValueError, IndexError):
                pass

        # SSL/TLS on non-standard or known weak configs
        if service in ("https", "ssl") or port == 443:
            findings.append(
                Finding(
                    title=f"TLS Service Detected on {target}:{port}",
                    description="TLS service detected. Verify certificate validity, cipher suites, and protocol versions.",
                    severity=Severity.INFO,
                    affected_asset=f"{target}:{port}",
                    tool_source="enterprise_orchestrator",
                    remediation="Ensure TLS 1.2+ with strong cipher suites. Disable SSLv3, TLS 1.0, TLS 1.1.",
                )
            )

        return findings

    async def _llm_vuln_assessment(self, target: str, recon: dict) -> list:
        """Use the vuln_hunter agent via Runner for LLM-driven assessment."""
        from kryon.intelligence.models import Finding, Severity

        findings: list[Finding] = []

        try:
            from kryon.agents import get_agent_by_name
            from kryon.sdk.agents import Runner

            agent = get_agent_by_name("vuln_hunter")

            # Build a focused prompt from recon data
            services_summary = "\n".join(
                f"- Port {s['port']}: {s['name']} {s.get('version', '')}"
                for s in recon.get("services_detected", [])
            )
            prompt = (
                f"Analyze the following target for vulnerabilities.\n"
                f"Target: {target}\n"
                f"Services:\n{services_summary}\n\n"
                f"Identify potential security issues and recommend remediation."
            )

            if self.rate_limiter:
                await self.rate_limiter.acquire(estimated_tokens=2000)

            result = await Runner.run(agent, input=prompt, max_turns=3)
            output = result.final_output or ""

            if output:
                # Parse LLM output into a generic finding
                findings.append(
                    Finding(
                        title=f"LLM Vulnerability Assessment — {target}",
                        description=output[:2000],
                        severity=Severity.INFO,
                        affected_asset=target,
                        tool_source="vuln_hunter",
                        evidence=f"Agent output (max_turns=3): {len(output)} chars",
                    )
                )
        except Exception:
            pass  # LLM assessment is best-effort

        return findings

    # ------------------------------------------------------------------
    # Phase 3: Exploitation (deep profiles only)
    # ------------------------------------------------------------------

    async def _phase_exploitation(self) -> None:
        self.progress.status = "exploitation"
        self.progress.phase_progress = 0.0
        self.progress.log("Phase 3/4: Exploitation (deep profile)")
        self._notify()

        exploitable = [f for f in self._findings if f.severity.value in ("critical", "high")]
        if not exploitable:
            self.progress.log("No critical/high findings to exploit — skipping")
            return

        for idx, finding in enumerate(exploitable[:5]):  # limit to top 5
            if self._time_exceeded():
                self.progress.log("Time limit reached during exploitation")
                break

            self.progress.log(f"Attempting exploitation: {finding.title}")

            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire(estimated_tokens=2000)

                from kryon.agents import get_agent_by_name
                from kryon.sdk.agents import Runner

                agent = get_agent_by_name("pentest_agent")
                prompt = (
                    f"Attempt to exploit the following vulnerability on an authorized target.\n"
                    f"Target: {finding.affected_asset}\n"
                    f"Vulnerability: {finding.title}\n"
                    f"Description: {finding.description}\n"
                    f"Stealth level: {self.stealth_level}\n"
                    f"Report your findings."
                )

                result = await Runner.run(agent, input=prompt, max_turns=5)
                output = result.final_output or ""

                if output:
                    from kryon.intelligence.models import Finding, Severity

                    self._findings.append(
                        Finding(
                            title=f"Exploitation Result — {finding.affected_asset}",
                            description=output[:2000],
                            severity=Severity.HIGH,
                            affected_asset=finding.affected_asset,
                            tool_source="pentest_agent",
                            evidence="Automated exploitation attempt",
                        )
                    )
                    self.progress.findings_count = len(self._findings)
                    self.progress.log(f"  Exploitation output captured")

            except Exception as exc:
                self.progress.log(f"  Exploitation error: {exc}")

            self.progress.phase_progress = (idx + 1) / min(len(exploitable), 5)
            self._notify()

    # ------------------------------------------------------------------
    # Phase 4: Reporting
    # ------------------------------------------------------------------

    async def _phase_reporting(self) -> None:
        self.progress.status = "reporting"
        self.progress.phase_progress = 0.0
        self.progress.log(f"Phase 4/4: Generating {self.output_format.upper()} report")
        self._notify()

        try:
            from kryon.reporting.generator import ReportGenerator
            from kryon.reporting.models import ReportConfig, ReportType

            # Determine report type
            if self.profile in ("compliance", "enterprise_compliance"):
                report_type = ReportType.COMPLIANCE
            else:
                report_type = ReportType.TECHNICAL

            target_scope = ", ".join(self.targets[:10])
            if len(self.targets) > 10:
                target_scope += f" (+{len(self.targets) - 10} more)"

            config = ReportConfig(
                report_type=report_type,
                client_name=self.client_name,
                target_scope=target_scope,
                include_compliance=self.compliance_frameworks,
            )

            gen = ReportGenerator()
            html = await gen.generate(self._findings, config)

            self.progress.phase_progress = 0.5
            self._notify()

            # Save report
            from kryon.reporting.export import save_pdf, save_report

            if self.output_format == "pdf":
                try:
                    pdf_bytes = await gen.to_pdf(html)
                    path = save_pdf(pdf_bytes, self.client_name, report_type.value)
                except ImportError:
                    self.progress.log("weasyprint not installed — falling back to HTML")
                    path = save_report(html, self.client_name, report_type.value)
            else:
                path = save_report(html, self.client_name, report_type.value)

            if self.output_path:
                # Also write to the specified path
                import shutil

                shutil.copy2(str(path), self.output_path)
                path = self.output_path

            self.progress.report_path = str(path)
            self.progress.phase_progress = 0.8
            self.progress.log(f"Report saved: {path}")

            # Store in memory (SQLite)
            await self._store_results()
            self.progress.phase_progress = 1.0

        except Exception as exc:
            self.progress.log(f"Report generation error: {exc}")
            logger.exception("Report generation failed")

        self._notify()

    async def _store_results(self) -> None:
        """Persist scan results to the MemoryStore."""
        try:
            from kryon.memory.models import FindingRecord, ScanRecord
            from kryon.memory.store import MemoryStore

            store = MemoryStore()

            # Create or resolve client
            client_id = self.client_id
            if not client_id:
                client_id = "default"

            # Create scan record
            scan = ScanRecord(
                id=self.progress.scan_id,
                client_id=client_id,
                agent_key="enterprise_orchestrator",
                status=self.progress.status,
                finding_count=self.progress.findings_count,
                risk_score=self._calculate_risk_score(),
                report_id=self.progress.report_path,
            )
            store.create_scan(scan)

            # Store individual findings
            for finding in self._findings:
                record = FindingRecord(
                    scan_id=self.progress.scan_id,
                    client_id=client_id,
                    finding_json=finding.model_dump_json(),
                )
                store.save_finding(record)

            store.close()
            self.progress.log(f"Results stored in database ({self.progress.findings_count} findings)")

        except Exception as exc:
            self.progress.log(f"Storage error (non-fatal): {exc}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _time_exceeded(self) -> bool:
        return (time.time() - self.progress.start_time) > self.max_time_seconds

    def _calculate_risk_score(self) -> float:
        """Simple risk score 0-100 based on findings."""
        if not self._findings:
            return 0.0

        weights = {"critical": 10, "high": 5, "medium": 2, "low": 0.5, "info": 0.1}
        total = sum(weights.get(f.severity.value, 1) for f in self._findings)
        return min(100.0, total)

    def _notify(self) -> None:
        if self._progress_cb:
            try:
                self._progress_cb(self.progress)
            except Exception:
                pass
