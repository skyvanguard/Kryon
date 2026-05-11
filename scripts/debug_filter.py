from kryon.sdk.agents.models.openai_chatcompletions import _PROSE_PLAN_PATTERNS, _is_prose_plan_contamination

samples = [
    # From call 26 of obsidian session — final prose summary
    """```
ANÁLISIS: Código revisado manualmente — no se encontraron vulnerabilidades críticas en lógica o configuración
RECOMENDACIONES:
1. Actualizar todas las dependencias inseguras reportadas por `npm audit`
2. Revisar manualmente archivos `.env`, `secrets.js`, o configuraciones de credenciales
3. Validar implementación de HTTPS en endpoints críticos
4. Implementar políticas de seguridad en `package.json` (ej: `npm audit fix --force`)
```""",
    # From replay_call 26 force=required — classic poison
    """```
ANÁLISIS: Código revisado — no se encontraron vulnerabilidades críticas con ESLint, pero se detectaron prácticas inseguras en dependencias
PLAN (ejecutando #1 ya):
1. `run_command("cd obsidian-mind && find . -name '*.js'")`
2. `duckduckgo_search(query="obsidian-mind code security", num_results=3)`
3. `run_command("cd obsidian-mind && git grep -A 3 'password|token|secret'")`
4. `query_knowledge_base(question="recomendaciones para código seguro", source_filter="github", top_k=2)`
```""",
]

for i, s in enumerate(samples):
    print(f"=== sample {i} (len={len(s)}) ===")
    print(f"flagged: {_is_prose_plan_contamination(s)}")
    for j, pat in enumerate(_PROSE_PLAN_PATTERNS):
        m = pat.search(s)
        if m:
            print(f"  pattern[{j}] HIT: {m.group()!r}")
        else:
            print(f"  pattern[{j}] miss: {pat.pattern[:60]}")
    print()
