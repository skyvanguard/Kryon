"""Focused SAST specialist, delegated to via Agent.as_tool().

The unified Kryon agent DELEGATES a code-tree SAST review to this specialist
(NOT a handoff — the orchestrator keeps the thread). The specialist runs its own
loop in ISOLATED context with a tight, role-specific prompt + just run_command,
and returns only its distilled findings. So the specialist's grep/cat/ls
exploration (the flailing the unified agent did on the bench) stays contained
and the orchestrator's context stays clean — exactly how Claude Code's Task tool
delegates to sub-agents.
"""

from __future__ import annotations

from typing import Any

# Tight, role-specific prompt — the directive, spoiler-free SAST methodology
# validated in the cybergym bench (no-git snapshot, grep the sink → read the
# file → emit the finding → stop). Deliberately small: NOT the 106-skill
# composite the unified agent loads.
_SAST_PROMPT = (
    "Sos un auditor SAST especializado. Tu ÚNICA tarea: encontrar una "
    "vulnerabilidad concreta en el árbol de código que te indiquen y reportar "
    "`CWE-XXX en <archivo>:<línea>` con una frase de evidencia.\n\n"
    "El código es un SNAPSHOT (no hay `.git`) — NO uses `git`, perdés turnos. "
    "Metodología, sé DIRECTO (no te quedes orientándote con ls/pwd):\n"
    "1. `semgrep_scan(<path>)` — reglas CWE-labeled de la industria; te da "
    "candidatos con `archivo:línea` + CWE al toque. Es tu mejor primer paso.\n"
    "2. `joern_scan(<path>)` — DATA-FLOW (taint) INTER-PROCEDURAL: sigue el input "
    "no confiable hasta el sink CRUZANDO funciones/archivos (lo que semgrep y el "
    "grep no ven — ej. un input que llega a un `lookup()`/`eval()` a través de "
    "varias capas). Usalo cuando el sink y el origen del input están en archivos "
    "distintos. Si devuelve status != ok, NO concluyas que está limpio.\n"
    "3. `sast_triage(<path>)` — ranking determinista por densidad/taint same-file, "
    "como respaldo si semgrep/joern no están disponibles (status unavailable).\n"
    "4. `cat`/`sed -n` los archivos candidatos de los pasos anteriores para "
    "confirmar el data-flow (que el input no confiable realmente llega al sink). "
    "`grep -rn` solo como último recurso.\n"
    "5. Apenas confirmes el defecto, EMITÍ `CWE-XXX en <archivo>:<línea>` y "
    "TERMINÁ — no sigas explorando ni re-verifiques de más.\n"
    "Si no encontrás nada concreto, decílo explícitamente — no inventes.\n\n"
    "## Clasificación CWE precisa (conocimiento general, distinguí familias)\n"
    "- Resolución de nombres/objetos remotos (JNDI/LDAP/RMI lookups, readObject, "
    "unmarshalling) que instancia clases desde datos no confiables = "
    "**deserialización insegura, CWE-502** (NO es SSRF; SSRF/CWE-918 es solo "
    "hacer un request a una URL controlada, sin instanciar objetos).\n"
    "- Copias de memoria (`memcpy`/`memmove`) cuyo largo viene del input sin "
    "validar contra el buffer real = lectura/escritura fuera de límites, "
    "**CWE-125** (read) o **CWE-787** (write).\n"
    "- Evaluación de expresiones/plantillas con input (OGNL/SpEL/EL/eval) = "
    "**inyección de expresión/código, CWE-917/CWE-94**; ejecución de comandos "
    "shell con input = **CWE-78**.\n"
    "- Falta de chequeo/sanitización de input que habilita el ataque, sin un "
    "sink más específico = **validación impropia de input, CWE-20**.\n"
    "Elegí el CWE que describe el DATA-FLOW real, no el primero que se te ocurra."
)


def create_sast_specialist(registry: dict[str, Any], *, model: Any = None):
    """Build the focused SAST sub-agent: tight prompt + run_command only.

    ``registry`` is the tool registry (name -> Tool). ``model`` overrides the
    backend (defaults to the shared default model — currently gpt-oss-20b).
    """
    from kryon.agents.base import create_agent

    tools = [
        registry[name]
        for name in ("semgrep_scan", "joern_scan", "sast_triage", "run_command")
        if name in registry
    ]
    kwargs: dict[str, Any] = {}
    if model is not None:
        kwargs["model"] = model
    return create_agent(
        name="SAST-Specialist",
        instructions=_SAST_PROMPT,
        tools=tools,
        description="Focused source-code SAST reviewer (delegated to via as_tool)",
        **kwargs,
    )


def sast_review_tool(registry: dict[str, Any], *, model: Any = None):
    """Expose the SAST specialist as a delegation tool for the orchestrator.

    Returns a Tool named ``sast_review`` that runs the specialist in isolated
    context and returns its findings text.
    """
    specialist = create_sast_specialist(registry, model=model)
    return specialist.as_tool(
        tool_name="sast_review",
        tool_description=(
            "Delegá una revisión SAST de un árbol de código local a un "
            "especialista que corre en CONTEXTO AISLADO. Input: el path del "
            "código + qué auditar. Devuelve CWEs confirmados como "
            "`CWE-XXX en <archivo>:<línea>`. Usalo para auditar código fuente "
            "en vez de hacer el grep/cat vos mismo."
        ),
    )
