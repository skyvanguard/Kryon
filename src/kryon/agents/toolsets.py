"""
Shared toolsets for KRYON agents.

Provides standardized tool groupings to ensure consistent capabilities
across all agents while keeping individual tool lists focused.
"""

from kryon.tools.ai.claude_code import claude_code
from kryon.tools.knowledge import (
    findings_library_stats,
    get_exploit_techniques,
    get_security_tools,
    list_recent_experiences,
    query_knowledge_base,
    query_similar_findings,
    recall_similar_experiences,
    record_engagement_findings,
    search_vulnerabilities,
)
from kryon.tools.reconnaissance.exec_code import execute_code
from kryon.tools.reconnaissance.run_command import run_command

# Core execution tools — every agent that runs commands needs these
CORE_TOOLS = [run_command, execute_code]

# RAG knowledge base tools — basic set for most agents
# recall_similar_experiences is included here so EVERY agent that does
# recon can bias its plan toward attack chains that worked against
# similar targets before (self-improving loop — see docs/LEARNING_LOOP.md).
# F64 — query_similar_findings added so the planner pulls XBOW-style
# n-days patterns before probing a new target.
RAG_TOOLS = [
    query_knowledge_base,
    search_vulnerabilities,
    recall_similar_experiences,
    query_similar_findings,
]

# RAG full set — for agents doing deep vuln research
RAG_TOOLS_FULL = RAG_TOOLS + [
    get_exploit_techniques,
    get_security_tools,
    list_recent_experiences,
    record_engagement_findings,
    findings_library_stats,
]

# AI delegation tool
AI_TOOLS = [claude_code]

# Base toolset — standard for every agent (7 tools)
BASE_TOOLS = CORE_TOOLS + RAG_TOOLS + AI_TOOLS

# --- Domain-specific toolsets ---

# AppSec pipeline tools (SAST/DAST/SCA/API/Supply Chain)
from kryon.tools.appsec import (  # noqa: E402
    api_security_scan,
    check_typosquatting,
    dependency_tree,
    detect_dependency_confusion,
    generate_sbom,
    owasp_api_top10_check,
    scan_sbom_vulns,
    semgrep_scan,
    semgrep_scan_with_rules,
    zap_api_scan,
    zap_baseline_scan,
    zap_full_scan,
)
from kryon.tools.appsec.compliance_audit import (  # noqa: E402  (F15.2)
    generate_compliance_pdf,
    run_compliance_audit,
)
from kryon.tools.appsec.web_pentest_tool import (  # noqa: E402  (F63)
    crawl_web_target,
    run_web_pentest,
)
from kryon.tools.appsec.pentest_stack import (  # noqa: E402  (F68/F69)
    pentest_build_engagement_report,
    pentest_chain_findings,
    pentest_dispatch_experts,
    pentest_final_judge,
    pentest_waf_probe,
)
from kryon.tools.platforms.hackerone import (  # noqa: E402  (F65)
    h1_assert_in_scope,
    h1_get_program_scope,
    h1_list_my_reports,
    h1_list_programs,
    h1_submit_report,
)

# F65 HackerOne platform toolset — add to agents that handle H1 engagements.
HACKERONE_TOOLS = [
    h1_list_programs,
    h1_get_program_scope,
    h1_assert_in_scope,
    h1_list_my_reports,
    h1_submit_report,
]

APPSEC_TOOLS = [
    semgrep_scan,
    semgrep_scan_with_rules,
    zap_baseline_scan,
    zap_full_scan,
    zap_api_scan,
    generate_sbom,
    scan_sbom_vulns,
    dependency_tree,
    api_security_scan,
    owasp_api_top10_check,
    detect_dependency_confusion,
    check_typosquatting,
    # F15.2 — deterministic compliance auditor + PDF report
    run_compliance_audit,
    generate_compliance_pdf,
    # F63 — LLM-activated web pentest (F50-F62 pipeline behind @function_tool)
    run_web_pentest,
    crawl_web_target,
    # F68 — F66/F67 pentest stack exposed as @function_tools. The LLM
    # chains them: waf_probe -> dispatch_experts -> chain_findings ->
    # final_judge. Deterministic, VRAM-free, banking-oriented.
    pentest_waf_probe,
    pentest_dispatch_experts,
    pentest_chain_findings,
    pentest_final_judge,
    # F69 — orquestador end-to-end: corre los 4 anteriores y escribe
    # un JSON compatible con load_webpentest_report() para que el
    # pipeline F60 + F44 genere el PDF multi-framework.
    pentest_build_engagement_report,
    # F65 — HackerOne platform integration (scope-enforced engagements)
    h1_list_programs,
    h1_get_program_scope,
    h1_assert_in_scope,
    h1_list_my_reports,
    h1_submit_report,
]

# Offensive validation tools (BAS/Purple Team/Detection as Code)
from kryon.tools.validation import (  # noqa: E402
    calculate_mitre_coverage,
    check_siem_alert,
    generate_coverage_report,
    generate_sigma_rule,
    generate_suricata_rule,
    generate_yara_rule,
    list_attack_techniques,
    simulate_attack,
    validate_detection,
)

VALIDATION_TOOLS = [
    simulate_attack,
    list_attack_techniques,
    validate_detection,
    check_siem_alert,
    generate_sigma_rule,
    generate_yara_rule,
    generate_suricata_rule,
    calculate_mitre_coverage,
    generate_coverage_report,
]

# Credential and password tools
from kryon.tools.credentials import (  # noqa: E402
    generate_targeted_wordlist,
    identify_hash_type,
    search_credential_dataset,
)

CREDENTIAL_TOOLS = [
    search_credential_dataset,
    generate_targeted_wordlist,
    identify_hash_type,
]

# LLM security testing tools
from kryon.tools.llm_security import (  # noqa: E402
    garak_list_probes,
    garak_scan,
    generate_injection_payloads,
    test_data_extraction,
    test_prompt_injection,
)

LLM_SECURITY_TOOLS = [
    garak_scan,
    garak_list_probes,
    test_prompt_injection,
    generate_injection_payloads,
    test_data_extraction,
]

# Discovery / ASM tools
from kryon.tools.discovery import (  # noqa: E402
    aggregate_cloud_posture,
    asm_diff,
    asm_discovery_scan,
    asset_timeline,
    register_asset,
    search_assets,
)

DISCOVERY_TOOLS = [
    asm_discovery_scan,
    asm_diff,
    register_asset,
    search_assets,
    asset_timeline,
    aggregate_cloud_posture,
]

# Memory / learning tools — agents can store and recall operational knowledge
try:
    from kryon.tools.misc.rag import add_to_memory_semantic, query_memory  # noqa: E402

    MEMORY_TOOLS = [query_memory, add_to_memory_semantic]
except ImportError:
    MEMORY_TOOLS = []
