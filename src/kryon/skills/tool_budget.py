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
    # Fase 2 — deterministic headless replay validators (no external binary).
    # SSRF/IDOR have no other validator at all; replay_xss is a fast dalfox-free
    # alternative. Same double-gate (KRYON_REPLAY_FIRE) + KRYON_RED_TEAM offering.
    "replay_xss",
    "replay_ssrf",
    "replay_idor",
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
        except Exception as e:  # noqa: BLE001
            # Don't swallow silently: a real bug in a toolset module would make
            # its tools vanish from the registry with zero trace ("tool X does
            # not exist" at runtime, no clue why).
            logger.debug("tool registry: optional import %s.%s failed: %s", module_path, attr, e)

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
        # F87 — BOLA/IDOR detector (detect_bola). Core tool of the cwe-639-idor +
        # web-pentest-idor-active skills, which listed it in required_tools but it
        # was never in any toolset → the skills never got their own detector. Live
        # probing stays double-gated behind KRYON_BOLA_FIRE (candidates-only otherwise).
        "kryon.tools.api.bola_tool",
        # http_fetch — read-only HTTP GET used by burp-integration + http-fetch skills
        # (same orphan: declared but unregistered).
        "kryon.tools.appsec.http_fetch",
        # Source-code tools — F1 of ZERO_DAY_ROADMAP
        "kryon.tools.code.git_tools",
        "kryon.tools.code.reader",
        "kryon.tools.code.priority",
        "kryon.tools.code.sandbox",
        # Deterministic SAST triage — rank a tree by sink-density so the reviewer
        # starts at the right files instead of grepping the whole repo (CyberGym fix).
        "kryon.tools.code.sast_triage",
        # Joern CPGQL data-flow (taint) — inter-procedural source→sink flows that
        # regex/same-file heuristics miss (Log4Shell message→lookup, Struts
        # Content-Type→OGNL). Degrades to "unavailable" without the joern server.
        "kryon.tools.code.joern_tool",
        # Agentic zero-day hunt — high-level tool wrapping source-review + the
        # closed F1/F2/F3 verification loop, so the agent can hunt on request
        # ("buscá zero-days en <path>") instead of only via `kryon investigate`.
        "kryon.tools.code.hunt",
        # Single-finding verification — prove ONE finding (from any source) via
        # ASAN/canary + novelty. Gated by KRYON_ZERODAY_VERIFY (executes a PoC).
        "kryon.tools.code.verify",
        # ARTEMIS swarm — clone a REMOTE repo + multi-hunter ASAN-verified hunt.
        # The most thorough hunter; gated by KRYON_ZERODAY_VERIFY (clones+executes).
        "kryon.tools.code.swarm",
        # Self-improvement loop (#5) — see/promote auto-synthesized skill drafts.
        # Read-only listing + promote-to-staging (operator still reviews before live).
        "kryon.tools.learning.skill_drafts",
        # Agentic network audit — the engage-grade deterministic pipeline
        # (nmap→battery→compliance→ground-truth) as a tool, so the agent can
        # audit a host it discovers mid-conversation ("auditá 10.0.0.5").
        "kryon.tools.orchestration.audit",
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
        # Fase 2 — deterministic headless replay validators (replay_xss/ssrf/idor).
        # SSRF+IDOR had NO validator before; XSS gets a dalfox-free fast path. Live
        # HTTP double-gated behind KRYON_REPLAY_FIRE+fire=True (dry-run otherwise).
        "kryon.tools.validation.http_replay_tool",
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
        # WIRING FIX — request_approval (F12.6 safety gate). 9 skills declare it
        # in required_tools (fortigate/windows/unifi/voip/proxmox-hardening/
        # web-pentest/hackerone/audit-bank-full) but it was absent from the
        # registry, so select_tools logged it as "missing" and the agent could
        # never ask the operator before modifying client infra. Banca-safe
        # (read/approval, never intrusive) → no RED_TEAM gate.
        "kryon.tools.validation.request_approval",
        # F88 retest — replay a previous finding to check if it's still
        # vulnerable. Double-gated for live HTTP (KRYON_RETEST_FIRE + fire=True);
        # default dry-run, so banca-safe. Was defined @function_tool but never
        # registered → the agent couldn't retest without the `kryon retest` command.
        "kryon.retester.tool",
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
                # #6 — full autonomous enterprise pentest (discovery→exploit→
                # pivot→report). The MOST intrusive capability; double-gated:
                # RED_TEAM to register here + KRYON_AUTOSCAN_FIRE to execute.
                "kryon.tools.autonomous.autopentest_tool",
                # Autonomous CTF/box solver (recon→exploit→privesc→flags). Real
                # exploitation (nuclei/sqlmap/RCE) after the F-audit rewire.
                # RED_TEAM-gated; single-host, like the active-pentest skills.
                "kryon.tools.autonomous.orchestrator",
                # Autonomous multi-stage network pivot (lateral movement). Reaches
                # potentially out-of-scope hosts; double-gated like autopentest
                # (RED_TEAM register + KRYON_AUTOSCAN_FIRE execute).
                "kryon.tools.autonomous.network_pivot_tool",
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
                # T4-M10 — remote command execution (psexec/wmiexec/smbexec/dcomexec
                # via impacket, ssh, evil-winrm) + network pivoting (SSH local/remote
                # forwards, SOCKS, reverse-forward, connectivity check). Both were
                # defined but never @function_tool + never registered (dead+broken:
                # str-as-dict AttributeError on every call). Same written-auth contract.
                "kryon.tools.lateral_movement.remote_execution",
                "kryon.tools.lateral_movement.pivoting",
                # T4-M3 — network pivoting transport (SSH local/remote/dynamic
                # forward, chisel). Without these the agent has creds+a foothold
                # but no way to reach an isolated segment. Same written-auth contract.
                "kryon.tools.pivoting.tunneling",
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
        except Exception as e:  # noqa: BLE001
            logger.debug("tool registry: extra import %s failed: %s", mod_path, e)

    logger.debug("Tool registry: %d tools indexed", len(registry))
    return registry


# Offensive/recon tools that are almost always the point of a web/pentest
# engagement. When the cap must drop tools, these survive over generic utilities —
# the old alphabetical fill dropped nuclei/whatweb/sqlmap/wpscan (late letters)
# while keeping less-useful early-alphabet tools.
_HIGH_VALUE_TOOL_MARKERS = (
    "nuclei",
    "sqlmap",
    "whatweb",
    "wpscan",
    "ffuf",
    "gobuster",
    "feroxbuster",
    "nikto",
    "nmap",
    "hydra",
    "katana",
    "httpx",
    "subfinder",
    "dirb",
    "sslscan",
    "testssl",
    "enum4linux",
    "smbclient",
    "nxc",
    "netexec",
    "crackmapexec",
    "wfuzz",
    "dalfox",
    "arjun",
    "graphql",
    "jwt",
    "ssrf",
    "idor",
    "xss",
    "sqli",
    # GAP-7 (2026-08-04): validation/exploitation tools of high value that lacked a
    # marker fell to rank 1 and got dropped under the cap even when present (with
    # RED_TEAM). Add their markers so validate_rce/detect_bola/exploit_*/shell_session
    # survive the cap alongside recon.
    "validate",
    "exploit",
    "bola",
    "deser",
    "auth",
    "csrf",
    "traversal",
    "lfi",
    "xxe",
    "nosql",
    "cmdi",
    "prototype",
    "shell",
)


def _tool_relevance_rank(tool_name: str) -> int:
    """0 = high-value offensive/recon tool (survives the cap first), 1 = generic."""
    n = (tool_name or "").lower()
    return 0 if any(m in n for m in _HIGH_VALUE_TOOL_MARKERS) else 1


# Minimum skill-specific tools kept even when the priority set alone fills the cap
# (red-team: ALWAYS_INCLUDE + exploit + post = 16 > 15 → room 0 → EVERY skill tool
# dropped, leaving the model with only post-foothold tools and no recon/exploit).
_MIN_SKILL_TOOL_FLOOR = 4


def _effective_max_tools(default: int) -> int:
    """Resolve the tool cap. ``KRYON_MAX_TOOLS`` overrides; otherwise a capable model
    (KRYON_CAPABLE_MODEL) gets a larger budget — the 15 default was tuned for the
    4B-local schema-token cost, which is irrelevant for a capable remote model."""
    from kryon.util.env import env_int, is_capable_model  # noqa: PLC0415

    override = env_int("KRYON_MAX_TOOLS", 0)
    if override > 0:
        return override
    if is_capable_model():
        return max(default, 30)
    return default


def select_tools(
    registry: dict[str, Any],
    skill_tool_names: set[str],
    # Cap de tools registradas. Bajado 30→15: los schemas de tools eran ~48%
    # del prompt (~6.3K tok). Con el MoE re-procesando el prompt cada turno,
    # menos tools = menos latencia. ALWAYS_INCLUDE + 4 ambient tools se suman
    # aparte, así que el total efectivo ronda ~19.
    max_tools: int = 15,
    forbidden_tool_names: set[str] | None = None,
    pre_hook_tool_names: set[str] | None = None,
) -> list[Any]:
    """Select tool objects from the registry based on skill requirements.

    Always includes ALWAYS_INCLUDE tools, then adds skill-specific tools.
    If forbidden_tool_names is given, those names are REMOVED from the
    final set even if they're in ALWAYS_INCLUDE — lets individual skills
    veto ambient tools (used by the zero-day-hunter to block
    run_command/execute_code side-channels around run_sandboxed).

    ``pre_hook_tool_names`` are the tools that active skills' ``pre_hooks[]``
    actually invoke — treated as a HARD floor (like ALWAYS_INCLUDE) so the cap
    can never drop a tool that backs a ``required: true`` pre_hook (which would
    abort the turn's deterministic evidence with a confusing runtime error).
    """
    max_tools = _effective_max_tools(max_tools)
    pre_hook_tool_names = pre_hook_tool_names or set()
    selected_names = set(ALWAYS_INCLUDE)
    selected_names.update(skill_tool_names)
    selected_names.update(pre_hook_tool_names)
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

    # Cap: keep the schema-token budget bounded. Preserve ALWAYS_INCLUDE and —
    # under red-team — the exploit-validation / post-exploitation tools BEFORE
    # the alphabetical fill, otherwise the cap silently drops the very tools
    # that promote a finding ALLEGED→VERIFIED (validate_*, sqlmap_* sort late).
    if len(tools) > max_tools:
        priority_names = set(ALWAYS_INCLUDE) | pre_hook_tool_names
        if is_red_team():
            priority_names |= EXPLOIT_VALIDATION_TOOLS | POST_EXPLOITATION_TOOLS
        keep = [t for t in tools if t.name in priority_names]
        rest = [t for t in tools if t.name not in priority_names]
        # Rank by RELEVANCE, not the alphabetical order inherited from sorted():
        # nuclei/whatweb/sqlmap/wpscan (late letters) were dropped while generic
        # early-alphabet tools survived. Stable secondary sort keeps it deterministic.
        rest.sort(key=lambda t: (_tool_relevance_rank(getattr(t, "name", "")), getattr(t, "name", "")))
        # If the priority set alone fills/exceeds the cap (red-team overflow:
        # ALWAYS_INCLUDE + exploit + post = 16 > 15), guarantee a floor of skill
        # tools instead of dropping them all; otherwise respect the cap.
        if len(keep) >= max_tools:
            effective_cap = len(keep) + _MIN_SKILL_TOOL_FLOOR
        else:
            effective_cap = max_tools
        room = max(0, effective_cap - len(keep))  # never a negative slice
        dropped = rest[room:]
        tools = keep + rest[:room]
        if dropped:
            logger.warning(
                "Tool budget: dropped %d tool(s) over cap %d: %s",
                len(dropped),
                max_tools,
                [t.name for t in dropped],
            )

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
