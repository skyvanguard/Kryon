"""
Comm-Sec Analyzer - Communications Security Assessment Unit

Series: Protocol-Class Security Analysis System
Classification: Email Security / Mail Protocol Specialist
Clearance: Bravo-Cyan (Protocol Analysis Authority)
Operational Status: ACTIVE

═══════════════════════════════════════════════════════════════════════
UNIT DESIGNATION: Comm-Sec Analyzer
PRIMARY FUNCTION: Email Security & Mail Spoofing Assessment
SPECIALIZATION: SPF/DMARC/DKIM Analysis, Mail Configuration Security
═══════════════════════════════════════════════════════════════════════

OPERATIONAL OVERVIEW:
Comm-Sec Analyzer represents KRYON's specialized communications security unit,
designed to assess email infrastructure security and identify mail spoofing
vulnerabilities. Analyzes SPF (Sender Policy Framework), DMARC (Domain-based
Message Authentication), and DKIM (DomainKeys Identified Mail) configurations
to determine if target domains are vulnerable to email spoofing attacks and
phishing campaigns.

CORE ANALYSIS CAPABILITIES:
- SPF (Sender Policy Framework) record analysis
- DMARC (Domain-based Message Authentication) configuration assessment
- DKIM (DomainKeys Identified Mail) validation
- DNS TXT record enumeration and analysis
- Mail spoofing vulnerability identification
- Email authentication bypass detection
- MX record analysis and mail routing assessment
- Email security posture evaluation
- Phishing infrastructure assessment
- Mail server fingerprinting

MISSION OBJECTIVES:
- Identify mail spoofing vulnerabilities in target domains
- Analyze email authentication configurations
- Detect missing or misconfigured SPF/DMARC/DKIM
- Assess email infrastructure security posture
- Identify domains vulnerable to phishing campaigns
- Evaluate mail authentication bypass opportunities
- Support social engineering operations
- Document email security weaknesses

ATTACK SURFACE ANALYSIS:
- Missing SPF records (unrestricted sender validation)
- Weak SPF configurations (overly permissive policies)
- Missing DMARC records (no policy enforcement)
- Permissive DMARC policies (p=none)
- Missing DKIM signatures (no cryptographic validation)
- Multiple authentication failures
- Subdomain takeover via DNS misconfigurations

PROTOCOL ASSESSMENT:
Comm-Sec Analyzer evaluates email authentication mechanisms that prevent
domain spoofing and email impersonation attacks. Identifies weaknesses that
could be exploited for spear phishing, business email compromise (BEC), and
other social engineering attacks.

COMM-SEC DESIGNATION:
Specialized in communications security assessment - the unit that evaluates
email infrastructure for spoofing vulnerabilities and authentication weaknesses.
"""

import os

import dns.resolver  # pylint: disable=import-error
from openai import AsyncOpenAI

from skynet.sdk.agents import Agent, OpenAIChatCompletionsModel, function_tool
from skynet.tools.misc.cli_utils import execute_cli_command


def get_txt_record(domain, record_type="TXT"):
    """
    Utility function to fetch TXT records for a given domain.
    Returns a list of record strings or an empty list if none found.
    """
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [rdata.to_text().strip('"') for rdata in answers]
    except Exception:  # pylint: disable=broad-exception-caught
        return []


def check_spf(domain: str):
    """
    Checks for the presence of an SPF record in the domain's TXT records.
    Returns the SPF record string if found; otherwise, returns None.
    """
    txt_records = get_txt_record(domain, "TXT")
    for record in txt_records:
        if record.lower().startswith("v=spf1"):
            return record
    return None


def check_dmarc(domain: str):
    """
    Checks for the presence of a DMARC record.
    DMARC records are stored in the TXT record of _dmarc.<domain>.
    Returns the DMARC record string if found; otherwise, returns None.
    """
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = get_txt_record(dmarc_domain, "TXT")
    for record in txt_records:
        if record.lower().startswith("v=dmarc1"):
            return record
    return None


def check_dkim(domain: str, selector: str = "default"):
    """
    Checks for the presence of a DKIM record using the specified selector.
    DKIM records are stored in the TXT record of
    <selector>._domainkey.<domain>.
    Returns the DKIM record string if found; otherwise returns None.
    """
    dkim_domain = f"{selector}._domainkey.{domain}"
    txt_records = get_txt_record(dkim_domain, "TXT")
    if txt_records:
        return txt_records[0]
    return None


@function_tool
def check_mail_spoofing_vulnerability(domain: str, dkim_selector: str = "default") -> dict:
    """
    Checks if domain is vulnerable to mail spoofing by inspecting SPF,
    DMARC, and DKIM. Returns dict with domain, records found/missing,
    vulnerability status and issues.
    """
    results = {}
    spf_record = check_spf(domain)
    dmarc_record = check_dmarc(domain)
    dkim_record = check_dkim(domain, selector=dkim_selector)

    results["domain"] = domain
    results["spf"] = spf_record if spf_record else "Missing SPF record"
    results["dmarc"] = dmarc_record if dmarc_record else "Missing DMARC record"
    results["dkim"] = dkim_record if dkim_record else f"Missing DKIM record (selector: {dkim_selector})"

    vulnerabilities = []
    if not spf_record:
        vulnerabilities.append("SPF")
    if not dmarc_record:
        vulnerabilities.append("DMARC")
    if not dkim_record:
        vulnerabilities.append("DKIM")

    results["vulnerable"] = bool(vulnerabilities)
    results["issues"] = vulnerabilities or ["None detected. All email auth configured."]

    full_string = ""
    for key, value in results.items():
        full_string += f"{key}: {value}\n"
    return full_string


# Protocol Analysis Systems - Available email security assessment tools
protocol_systems = [check_mail_spoofing_vulnerability, execute_cli_command]

# Initialize Comm-Sec Analyzer Unit
comm_sec_analyzer = Agent(
    name="Comm-Sec Analyzer",
    description="""Specialized communications security unit from KRYON's Protocol-Class series.
Expert in email infrastructure security assessment and mail spoofing vulnerability identification.
Analyzes SPF, DMARC, and DKIM configurations to determine if target domains are vulnerable to
email spoofing attacks, phishing campaigns, and business email compromise (BEC).

Primary Mission: Email security assessment, mail spoofing detection, protocol analysis.
Operational Focus: Identify email authentication weaknesses and spoofing vulnerabilities.

Comm-Sec Analyzer Capabilities:
- SPF (Sender Policy Framework) record analysis
- DMARC (Domain-based Message Authentication) assessment
- DKIM (DomainKeys Identified Mail) validation
- DNS TXT record enumeration
- Mail spoofing vulnerability identification
- Email authentication bypass detection
- MX record analysis and mail routing assessment
- Email security posture evaluation
- Phishing infrastructure assessment
- Mail server fingerprinting
- Business email compromise (BEC) attack surface analysis

Identifies missing or misconfigured email authentication mechanisms that could enable
domain spoofing, email impersonation, and social engineering attacks.""",
    instructions=(
        "You are KRYON's Comm-Sec Analyzer - specialized in email infrastructure security "
        "assessment. Your mission is to identify mail spoofing vulnerabilities by analyzing "
        "SPF, DMARC, and DKIM configurations. Use check_mail_spoofing_vulnerability for "
        "comprehensive email authentication analysis. Use execute_cli_command for DNS "
        "queries and mail server reconnaissance. Report all missing or misconfigured "
        "authentication mechanisms that could enable spoofing attacks. "
        "FOCUS ON TOOL CALLS AND ACTIONABLE FINDINGS."
    ),
    tools=protocol_systems,
    model=OpenAIChatCompletionsModel(
        model=os.getenv("KRYON_MODEL", "gpt-4o"),
        openai_client=AsyncOpenAI(),
    ),
)

# Legacy compatibility - maintain backward compatibility with old naming
dns_smtp_agent = comm_sec_analyzer  # Alias for legacy code


def transfer_to_comm_sec_analyzer():
    """Transfer control to Comm-Sec Analyzer for email security assessment.

    Use this when you need:
    - Email spoofing vulnerability assessment
    - SPF/DMARC/DKIM configuration analysis
    - Mail authentication mechanism evaluation
    - DNS TXT record analysis for email security
    - Phishing infrastructure assessment
    - Business email compromise (BEC) attack surface
    - Mail server reconnaissance
    - Email security posture evaluation
    - Domain spoofing vulnerability detection

    Returns:
        Agent: Comm-Sec Analyzer email security assessment agent
    """
    return comm_sec_analyzer


# Legacy transfer function for backward compatibility
def transfer_to_dns_smtp_agent():
    """Legacy function - transfers to Comm-Sec Analyzer.

    This function maintained for backward compatibility.
    Use transfer_to_comm_sec_analyzer() in new code.
    """
    return transfer_to_comm_sec_analyzer()
