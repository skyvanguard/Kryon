"""
Tool budget manager — select which tools to register on the unified agent
based on active skills. Caps at max_tools to keep schema tokens under control.
"""

from __future__ import annotations

import logging
from typing import Any

from kryon.util.env import is_red_team

logger = logging.getLogger(__name__)

# These tools are ALWAYS included regardless of skill selection.
# RAG/memory tools (recall_similar_experiences, query_knowledge_base,
# search_vulnerabilities, add_to_memory_semantic, query_memory) fueron
# removidas: el RAG quedó apagado (corpus 94% duplicado, query_knowledge_base
# con 0 invocaciones reales, search_vulnerabilities siempre count:0). Sin RAG
# no hay dependencia de embeddings/Ollama.
ALWAYS_INCLUDE = {
    "run_command",
    "execute_code",
    "nmap",
    "cve_intel",  # F2 — live CVE intel (reemplaza el RAG estático de CVEs)
    # FASE 6 — the OPERATOR DIRECTIVE block tells the model to call
    # ``execute_planner_directive()`` as its next tool. Without this
    # entry the tool-budget selector can drop the function_tool when
    # the active skill set doesn't reference it by name, leaving the
    # model with a directive pointing at a tool that doesn't exist
    # (the agent then refuses with "tool not available"). Pin it.
    "execute_planner_directive",
}


# Exploit-confirmation tools (exploit_validator). They RUN the real exploit
# tool (sqlmap/dalfox/commix/...) against the target when called — there is NO
# dry-run gate inside the validator. Banking-safety therefore comes from only
# OFFERING them under KRYON_RED_TEAM (the active-pentest profile, which already
# requires written authorization — same contract as the hydra/fuzzing tools).
# Before this they were registered but never selected (no skill listed them in
# required_tools, not in ALWAYS_INCLUDE) → the agent never confirmed a finding
# → the report's "Verificado por exploit" section was always empty.
EXPLOIT_VALIDATION_TOOLS = {
    "validate_sqli",
    "validate_xss",
    "validate_rce",
    "validate_auth_bypass",
    "validate_finding",
}


# Post-foothold / exploitation tools — persistent interactive shell sessions
# plus SQLi data extraction (enumerate/dump). Same banca-safe contract as
# EXPLOIT_VALIDATION_TOOLS: offered ONLY under KRYON_RED_TEAM (active-pentest,
# written authorization). The compliance/banking default never sees them. The
# matching module imports are gated under the same flag in build_tool_registry.
POST_EXPLOITATION_TOOLS = {
    "shell_session_start",
    "shell_session_input",
    "shell_session_output",
    "shell_session_close",
    "shell_session_list",
    "sqlmap_dump_database",
}


def build_tool_registry() -> dict[str, Any]:
    """Import ALL tools from toolsets and index them by name.
    Returns dict[tool_name, Tool object].
    """
    registry: dict[str, Any] = {}

    # Import all toolsets
    from kryon.agents.toolsets import (
        AI_TOOLS,
        CORE_TOOLS,
        MEMORY_TOOLS,
        RAG_TOOLS_FULL,
    )

    for tool in [*CORE_TOOLS, *RAG_TOOLS_FULL, *AI_TOOLS, *MEMORY_TOOLS]:
        if hasattr(tool, "name"):
            registry[tool.name] = tool

    # Import domain-specific tools with graceful fallback
    _optional_imports = [
        ("kryon.agents.toolsets", "APPSEC_TOOLS"),
        ("kryon.agents.toolsets", "VALIDATION_TOOLS"),
        ("kryon.agents.toolsets", "CREDENTIAL_TOOLS"),
        ("kryon.agents.toolsets", "LLM_SECURITY_TOOLS"),
        ("kryon.agents.toolsets", "DISCOVERY_TOOLS"),
    ]
    for module_path, attr in _optional_imports:
        try:
            import importlib

            mod = importlib.import_module(module_path)
            tools = getattr(mod, attr, [])
            for tool in tools:
                if hasattr(tool, "name"):
                    registry[tool.name] = tool
        except Exception:
            pass

    # Import individual tools that aren't in shared toolsets
    _extra_tools = [
        "kryon.tools.reconnaissance.nmap",
        "kryon.tools.reconnaissance.whatweb",
        "kryon.tools.web.nuclei",
        "kryon.tools.web.duckduckgo_search",
        # F203.B — smart HTTP GET with HTML→markdown extraction
        "kryon.tools.web.web_fetch_smart",
        # F197 — IoT / DVR fingerprinting (Hikvision / Dahua / ONVIF)
        "kryon.tools.iot.dvr_recon",
        "kryon.tools.iot.onvif_probe",
        # F198 — Asterisk / VoIP / SIP recon
        "kryon.tools.voice.asterisk_discover",
        # F200.A — Apache Tomcat recon (version + endpoints + AJP probe)
        "kryon.tools.web.tomcat_recon",
        # Source-code tools — F1 of ZERO_DAY_ROADMAP
        "kryon.tools.code.git_tools",
        "kryon.tools.code.reader",
        "kryon.tools.code.priority",
        "kryon.tools.code.sandbox",
        # Supervisor tools — F3.1 (planner-hunter coordination)
        "kryon.skills.supervisor_tools",
        # CVE corpus RAG — F4.2 (recall_similar_code_pattern)
        "kryon.knowledge.cve_corpus",
        # Semgrep — F5.2.b (industry-standard pattern scanner)
        "kryon.tools.code.semgrep_tool",
        # Structured finding submission — F5.1.d (replaces text-block parsing)
        "kryon.skills.submit_tools",
        # F203.R — DFIR detection/exploit validation tools.
        # Banca-safe: validate_detection es analítico (no fire), exploit_validator
        # respeta el doble gate KRYON_EXPLOIT_FIRE+fire=True; bas_scenarios y
        # attack_simulator solo emiten plans/scenarios, no ejecutan. coverage_scorer
        # mapea findings vs MITRE ATT&CK (analítico). detection_generator emite
        # Sigma/YARA rules (read-only).
        "kryon.tools.validation.detection_validator",
        "kryon.tools.validation.detection_generator",
        "kryon.tools.validation.coverage_scorer",
        "kryon.tools.validation.attack_simulator",
        "kryon.tools.validation.bas_scenarios",
        "kryon.tools.validation.exploit_validator",
        # F203.BB — Burp Suite Pro REST API tools (instalado en Kali
        # container v2026.3.2). 3 @function_tool: burp_send_to_repeater,
        # burp_active_scan, burp_proxy_history. Fallback automático a
        # mitmproxy embebido (F50) cuando Burp Pro no está disponible
        # (sin license / API key). Banca-safe: read-only para
        # repeater/history; active_scan respeta scope del operator.
        "kryon.tools.appsec.burp_tools",
        # F203.BC — Kali tool wrappers (binaries installed pero antes
        # solo accesibles via run_command genérico). Wrappers @function_tool
        # con schema explicito + args canónicos para mejor LLM guidance.
        # Banca-safe: read-only enumeration / scanning. Para uso intrusivo
        # operator debe pasar args explicitos.
        "kryon.tools.reconnaissance.kali_wrappers",
        # F203.BD Group 1 — banca-safe recon/RE wrappers (no RED_TEAM gate).
        # masscan/tcpdump/dnsrecon/amass/sublist3r/radare2. Read-only.
        "kryon.tools.reconnaissance.kali_recon",
        # WIRING FIX — read-only / analytical capability branches that were
        # defined but never registered (the registry is a hardcoded allowlist, it
        # does NOT scan tools/**). All banca-safe: cloud posture audit, OSINT,
        # DFIR analysis, container/k8s scanning, threat-intel correlation. None
        # are intrusive (no exploitation, no credential access) so they need no
        # RED_TEAM gate.
        "kryon.tools.cloud.prowler",
        "kryon.tools.cloud.scoutsuite",
        "kryon.tools.cloud.pacu",
        "kryon.tools.cloud.s3scanner",
        "kryon.tools.cloud.cloudmapper",
        "kryon.tools.cloud.aws_tool",
        "kryon.tools.osint.shodan_cli",
        "kryon.tools.osint.theharvester",
        "kryon.tools.osint.threat_intel",
        "kryon.tools.osint.yara_scan",
        "kryon.tools.dfir.volatility_forensics",
        "kryon.tools.dfir.disk_forensics",
        "kryon.tools.dfir.log_analysis",
        "kryon.tools.dfir.network_forensics",
        "kryon.tools.container.trivy",
        "kryon.tools.container.kube_hunter",
        "kryon.tools.container.kube_bench",
        "kryon.tools.container.docker_bench",
        "kryon.tools.container.dockerfile_tool",
        "kryon.tools.intelligence.intel_tools",
        "kryon.tools.intelligence.vulnerability_correlator",
        "kryon.tools.intelligence.vm_importers",
        "kryon.tools.intelligence.misp_client",
        "kryon.tools.intelligence.stix_taxii",
        "kryon.tools.intelligence.decision_engine",
        # F66 unified web pipeline — was built but had zero call-sites. Static
        # analyzers ON by default (headers/cookies/CMS/JS-libs/DOM-XSS); network
        # stages opt-in. Banca-safe default.
        "kryon.tools.pipeline.pipeline_tool",
    ]

    # F203.T — red-team tools gated by KRYON_RED_TEAM=true. Banking-default
    # OFF: these tools can be intrusive (fuzzing, credential brute-force,
    # JWT cracking) and require written authorization. Operator opt-in via
    # `export KRYON_RED_TEAM=true` for authorized pentest engagements (Juice
    # Shop bench, bug bounty con autorización escrita, lab interno).
    #
    # Still NOT included even under RED_TEAM=true (destructive — separate approval):
    #   - evasion/log_cleaning, anti_forensic, timestomping (tamper/destruction)
    # The post-exploitation / lateral-movement / AD branches below ARE now offered
    # under RED_TEAM (intrusive, require existing access + written authorization)
    # — they were defined but never registered, leaving the offensive agent without
    # credential dumping, lateral movement, AD attacks, or privesc.
    if is_red_team():
        _extra_tools.extend(
            [
                # API attacks — fuzzing, credential testing, JWT analysis
                "kryon.tools.api_attacks.api_fuzzer",
                "kryon.tools.api_attacks.ffuf_api",
                "kryon.tools.api_attacks.hydra",
                "kryon.tools.api_attacks.jwt_tool",
                "kryon.tools.api_attacks.medusa",
                "kryon.tools.api_attacks.wfuzz",
                # Browser automation (Playwright) — useful for E2E auth flows
                "kryon.tools.browser.playwright_tools",
                # Payload prep (analytical, no exec): encoding + obfuscation
                "kryon.tools.evasion.payload_encoding",
                "kryon.tools.evasion.traffic_obfuscation",
                # F203.BD Group 2 — RED_TEAM-gated AD/exploit Kali tools.
                # evil-winrm, impacket-{secretsdump,psexec,GetUserSPNs},
                # responder (analyze-only default), bloodhound-python,
                # msfvenom. Todos requieren creds previas o hardware.
                "kryon.tools.lateral_movement.kali_redteam",
                # D — web exploitation: file upload (CWE-434) + Java
                # deserialization (CWE-502). The two attack classes that had no
                # native tool (commix/sqlmap/dalfox already cover RCE/SQLi/XSS).
                # Intrusive: benign-marker probe by default, aggressive run needs
                # the per-tool fire env var too.
                "kryon.tools.exploitation.web_exploit",
                # Post-foothold tools — persistent interactive shell sessions
                # (shell_session_*) + SQLi enumerate/dump (sqlmap_dump_database).
                # See POST_EXPLOITATION_TOOLS. Same written-authorization
                # contract as the rest of this block.
                "kryon.tools.common.session_tools",
                "kryon.tools.sqlmap_dump",
                # WIRING FIX — post-foothold offensive branches, defined but never
                # registered. Same written-authorization contract as the rest of
                # this block. kali_redteam (above) is imported first, so on name
                # collisions (e.g. bloodhound_collect) it wins; these add the
                # unique tools (kerberoast/asreproast/dcsync, LSASS/SAM dumping,
                # PtH/PtT, linpeas/gtfobins, credential spray, sqlmap_scan).
                "kryon.tools.post_exploitation.credential_dumping",
                "kryon.tools.post_exploitation.lateral_movement",
                "kryon.tools.lateral_movement.ad_attacks",
                "kryon.tools.lateral_movement.pth_attacks",
                "kryon.tools.privilege_escalation.linux_privesc",
                "kryon.tools.password_cracking.smart_attacks",
                "kryon.tools.web.sqlmap",
            ]
        )
    for mod_path in _extra_tools:
        try:
            import importlib

            mod = importlib.import_module(mod_path)
            for attr_name in dir(mod):
                obj = getattr(mod, attr_name)
                if hasattr(obj, "name") and hasattr(obj, "params_json_schema"):
                    if obj.name not in registry:
                        registry[obj.name] = obj
        except Exception:
            pass

    logger.debug("Tool registry: %d tools indexed", len(registry))
    return registry


def select_tools(
    registry: dict[str, Any],
    skill_tool_names: set[str],
    # Cap de tools registradas. Bajado 30→15: los schemas de tools eran ~48%
    # del prompt (~6.3K tok). Con el MoE re-procesando el prompt cada turno,
    # menos tools = menos latencia. ALWAYS_INCLUDE + 4 ambient tools se suman
    # aparte, así que el total efectivo ronda ~19.
    max_tools: int = 15,
    forbidden_tool_names: set[str] | None = None,
) -> list[Any]:
    """Select tool objects from the registry based on skill requirements.

    Always includes ALWAYS_INCLUDE tools, then adds skill-specific tools.
    If forbidden_tool_names is given, those names are REMOVED from the
    final set even if they're in ALWAYS_INCLUDE — lets individual skills
    veto ambient tools (used by the zero-day-hunter to block
    run_command/execute_code side-channels around run_sandboxed).
    """
    selected_names = set(ALWAYS_INCLUDE)
    selected_names.update(skill_tool_names)
    # Active-pentest profile: offer exploit-confirmation tools so findings can
    # be promoted ALLEGED → VERIFIED. These RUN the real exploit tool against
    # the target, so they're offered ONLY under KRYON_RED_TEAM (off in the
    # banking default; that profile already requires written authorization).
    if is_red_team():
        selected_names |= EXPLOIT_VALIDATION_TOOLS
        selected_names |= POST_EXPLOITATION_TOOLS
    if forbidden_tool_names:
        selected_names -= set(forbidden_tool_names)

    # Resolve names to tool objects
    tools: list[Any] = []
    missing: list[str] = []
    for name in sorted(selected_names):
        if name in registry:
            tools.append(registry[name])
        else:
            missing.append(name)

    if missing:
        logger.debug("Tools not found in registry: %s", missing)

    # Cap
    if len(tools) > max_tools:
        # Keep ALWAYS_INCLUDE first, then fill from skills
        always = [t for t in tools if t.name in ALWAYS_INCLUDE]
        rest = [t for t in tools if t.name not in ALWAYS_INCLUDE]
        tools = always + rest[: max_tools - len(always)]

    return tools


def select_tools_itr(
    registry: dict[str, Any],
    user_query: str,
    *,
    max_tools: int = 30,
    forbidden_tool_names: set[str] | None = None,
    embedder: Any = None,
    index: Any = None,
) -> list[Any] | None:
    """F84.7 — Per-turn ITR tool selection. Embeds the user query,
    scores every tool in the persisted index by cosine similarity,
    keeps the high-confidence hits (CAR adaptive K) plus the
    ALWAYS_INCLUDE set, caps at max_tools.

    Returns None on any of:
      - empty query
      - index not built / missing
      - embedder failure (network, model down)
      - too few hits clear the confidence threshold (ambiguous query)

    The caller is REQUIRED to handle None by falling back to
    `select_tools` so an ITR misfire never produces an empty tool
    list on a live banking engagement.

    `embedder` and `index` are dependency-injected so tests can mock
    them. Production callers pass None and we wire the Ollama
    embedder + on-disk index automatically."""
    if not user_query or not user_query.strip():
        return None
    if not registry:
        return None

    # Lazy import to avoid pulling the embedder module on the static
    # path (banca-safe default).
    from kryon.skills.itr_retriever import select_with_itr

    if embedder is None:
        from kryon.skills.itr_tool_index import OllamaEmbedder

        embedder = OllamaEmbedder()
    if index is None:
        from kryon.skills.itr_tool_index import load_index

        index = load_index()

    selected_names = select_with_itr(
        user_query,
        embedder,
        index,
        max_tools=max_tools,
        always_include=ALWAYS_INCLUDE,
    )
    if selected_names is None:
        return None

    if forbidden_tool_names:
        selected_names = [n for n in selected_names if n not in forbidden_tool_names]

    tools = [registry[n] for n in selected_names if n in registry]
    return tools or None
