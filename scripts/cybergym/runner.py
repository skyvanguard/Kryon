"""F86 — Single-task run orchestration for CyberGym.

The detection task: given a CVE walkthrough that points at a
vulnerable commit of a real OSS project, can Kryon identify the right
CWE in the right file/line?

We DELIBERATELY do not build the vulnerable target by default —
CyberGym's full data is 240 GB and the operator may not have it
locally. Static-only mode reads the source tree (cloned by us or
mounted in by the operator) and asks Kryon to audit it. PoC
generation + validation is the v2 mode gated by
KRYON_CYBERGYM_DOCKER=1.

Returns a `RunResult` frozen dataclass shaped like
scripts.htb_bench.runner.RunResult so the HTML reporter from F83 can
consume both — but with detection-specific fields (cwe_match,
file_match) instead of pwn-specific ones.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts.cybergym.loader import load_walkthrough

# Hard cap so a stuck Kryon turn doesn't lock the whole bench.
_DEFAULT_WALL_BUDGET_SECONDS = 600


@dataclass(frozen=True)
class RunResult:
    """Result of running Kryon vuln-hunter against one CVE task.

    Shape-compatible with scripts.htb_bench.runner.RunResult enough
    that the HTML reporter can render either — but the semantics
    differ:

    - `detected`     : did Kryon flag the *correct* CWE?
    - `file_match`   : did it point at the expected source file
                       (any line)?
    - `line_match`   : did it point within ±5 lines of the expected
                       line number?
    """

    slug: str
    cve_id: str
    detected: bool
    cwe_match: bool
    file_match: bool
    line_match: bool
    wall_time_seconds: float
    expected_cwe: str
    actual_cwes_found: tuple[str, ...] = field(default_factory=tuple)
    expected_file: str | None = None
    expected_line: int | None = None
    actual_file_hits: tuple[str, ...] = field(default_factory=tuple)
    error: str | None = None
    raw_output: str = ""


# Regex for CWE references in Kryon transcripts. Liberal — anything
# from "CWE-79", "cwe 79", "CWE_79" counts as a finding mention.
_CWE_RE = re.compile(r"\bCWE[-_\s]?(\d{1,4})\b", re.IGNORECASE)
# File references: catch absolute and relative paths with common
# source extensions. False positives are fine; we'll cross-reference
# against `expected_file` substring match.
_FILE_RE = re.compile(
    r"\b([A-Za-z0-9_\-./]+\.(?:c|cc|cpp|cxx|h|hpp|py|rs|go|js|ts|java|php|rb))\b"
)
# Line references near a file mention: "at line 142", "line: 142",
# ":142:". We grab any 1-6 digit integer in proximity.
_LINE_RE = re.compile(r"(?:line|:)[\s:]*(\d{1,6})")


def _detect_cwe(transcript: str, expected_cwe: str) -> tuple[bool, tuple[str, ...]]:
    """Returns (cwe_matched, all_cwes_seen). all_cwes_seen is useful
    for the report — it lets a reviewer spot near-misses
    ("expected CWE-79, agent said CWE-89")."""
    seen = tuple(f"CWE-{m.group(1)}" for m in _CWE_RE.finditer(transcript))
    expected_num = expected_cwe.replace("CWE-", "").strip()
    matched = any(c.split("-")[-1] == expected_num for c in seen)
    return matched, tuple(dict.fromkeys(seen))  # dedupe preserving order


def _detect_file(
    transcript: str,
    expected_file: str | None,
) -> tuple[bool, tuple[str, ...]]:
    """File match. The agent may emit:
      - full path  ("log4j-core/src/.../JndiLookup.java")
      - abbreviated ("log4j-core/.../JndiLookup.java")
      - basename   ("JndiLookup.java")
      - build path ("/build/src/proto/parser.c")
    Any of these should match the expected path "src/proto/parser.c".

    Heuristic: a hit matches when either (a) the expected basename
    equals the hit basename, OR (b) the expected path is a substring
    of the hit, OR (c) the hit is a substring of the expected path
    AND the hit is meaningful (has at least one path separator OR
    matches the basename). Lower-cased throughout.
    """
    if not expected_file:
        return False, ()
    hits = tuple(m.group(1) for m in _FILE_RE.finditer(transcript))
    expected_lower = expected_file.lower()
    expected_base = expected_lower.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]

    def _matches(hit: str) -> bool:
        h = hit.lower()
        h_base = h.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if h_base == expected_base:
            return True
        if expected_lower in h:
            return True
        if h in expected_lower and ("/" in h or "\\" in h):
            return True
        return False

    matched = any(_matches(h) for h in hits)
    return matched, tuple(dict.fromkeys(hits))[:20]  # cap for report payload


def _detect_line(
    transcript: str,
    expected_line: int | None,
    tolerance: int = 5,
) -> bool:
    """Line-number proximity: any integer in `_LINE_RE` matches within
    `±tolerance` of `expected_line`. Tolerance accounts for
    line-number drift between code annotations and where Kryon
    actually points (function entry vs vulnerable expression)."""
    if not expected_line:
        return False
    for match in _LINE_RE.finditer(transcript):
        try:
            n = int(match.group(1))
        except ValueError:
            continue
        if abs(n - expected_line) <= tolerance:
            return True
    return False


def invoke_kryon(prompt: str, timeout: int = _DEFAULT_WALL_BUDGET_SECONDS) -> str:
    """F202.Z — Invoke Kryon via REST API instead of docker exec REPL.

    The old `docker exec -i kryon kryon` pipe approach assumed Kryon
    drops into a stdin-driven REPL when no subcommand is given. In
    practice the CLI requires a subcommand, so the pipe deadlocked
    until timeout. The REST API (`POST /api/v1/runs`) is the proper
    non-interactive entry point.

    KRYON_BENCH_DRY_RUN=1 still wins for smoke tests so they don't
    need a live container.

    Env knobs:
        KRYON_API_URL      base URL of the Kryon API (default:
                           http://127.0.0.1:8700)
        KRYON_API_KEY      API key (required unless server has
                           KRYON_ALLOW_UNAUTHENTICATED=true)
        KRYON_BENCH_AGENT  agent_key to invoke (default: vuln_hunter)
        KRYON_BENCH_MAX_TURNS  override per-task turn cap (default: 5)
    """
    if os.environ.get("KRYON_BENCH_DRY_RUN") == "1":
        return os.environ.get("KRYON_BENCH_FIXTURE_TRANSCRIPT", "")

    import json
    import urllib.error
    import urllib.request

    api_url = os.environ.get("KRYON_API_URL", "http://127.0.0.1:8700").rstrip("/")
    api_key = os.environ.get("KRYON_API_KEY", "")
    agent_key = os.environ.get("KRYON_BENCH_AGENT", "vuln_hunter")
    max_turns = int(os.environ.get("KRYON_BENCH_MAX_TURNS", "5"))

    payload = json.dumps(
        {
            "agent_key": agent_key,
            "input": prompt,
            "max_turns": max_turns,
            "stream": False,
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        f"{api_url}/api/v1/runs",
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return f"[HTTPError {e.code}] {body}"
    except (TimeoutError, urllib.error.URLError) as e:
        return f"[TimeoutOrConnError] {e}"

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return body

    # The /runs endpoint returns {output, agent, status, usage}. The
    # transcript-style detection regexes in scorer expect a flat text
    # blob, so we synthesize one.
    output = data.get("output", "") or ""
    status = data.get("status", "")
    return f"[status={status}]\n{output}"


def _github_tarball_url(repo_url: str, commit: str) -> str | None:
    """F202.AA — GitHub-only: build a tarball URL we can stream into
    `tar xz` to materialize a commit without git. Returns None for
    non-GitHub URLs (the caller falls back to no pre-clone).
    """
    if not repo_url or not commit:
        return None
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", repo_url)
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    return f"https://codeload.github.com/{owner}/{repo}/tar.gz/{commit}"


def prepare_source(walkthrough: dict[str, Any]) -> str | None:
    """F202.AA — Pre-clone the vulnerable repo @ vuln_commit inside the
    Kryon container so the agent can grep/find/cat it. Returns the
    container-side path, or None if pre-clone is skipped/fails.

    Skip when:
    - KRYON_CYBERGYM_NO_PRECLONE=1 (operator opt-out)
    - KRYON_BENCH_DRY_RUN=1 (smoke test path)
    - repo is not GitHub (no tarball fallback)
    - the source already exists at the destination (idempotent)
    """
    if os.environ.get("KRYON_CYBERGYM_NO_PRECLONE") == "1":
        return None
    if os.environ.get("KRYON_BENCH_DRY_RUN") == "1":
        return os.environ.get("KRYON_BENCH_FIXTURE_SRC_PATH")

    slug = walkthrough.get("slug")
    repo_url = walkthrough.get("repo_url", "")
    commit = walkthrough.get("vuln_commit", "")
    if not slug:
        return None
    tarball_url = _github_tarball_url(repo_url, commit)
    if not tarball_url:
        return None

    container = os.environ.get("KRYON_BENCH_CONTAINER", "kryon")
    dest = f"/workspace/cybergym-src/{slug}"

    # Idempotent: if path already populated, reuse.
    probe = subprocess.run(
        ["docker", "exec", container, "bash", "-c", f"test -d {dest} && ls -1 {dest} | head -1"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
    )
    if probe.returncode == 0 and probe.stdout.strip():
        return dest

    # Materialize via tarball stream. Time-bounded so a wedged network
    # doesn't tank the bench — 180s is enough for openssl (~50MB shallow).
    cmd = (
        f"mkdir -p {dest} && curl -sfL --max-time 150 {tarball_url} "
        f"| tar xz --strip-components=1 -C {dest}"
    )
    try:
        result = subprocess.run(
            ["docker", "exec", container, "bash", "-c", cmd],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        return None
    if result.returncode != 0:
        return None
    return dest


def _load_cwe_skill_bodies(query_text: str, max_chars: int = 8000) -> str:
    """F202.AB — Match skills against the bench query (project + repo
    keywords) and return their body text concatenated.

    The body MUST be pure classification guidance — no spoilers of
    specific file:line targets. The skills under
    src/kryon/skills/playbooks/cwe-detection/ are curated to follow
    that contract.

    Banca-safe: read-only. KRYON_CYBERGYM_NO_SKILLS=1 opts out.
    """
    if os.environ.get("KRYON_CYBERGYM_NO_SKILLS") == "1":
        return ""
    try:
        from kryon.skills.loader import SkillLoader
    except ImportError:
        return ""

    loader = SkillLoader()
    skills = loader.scan()
    query_lower = query_text.lower()

    bodies: list[str] = []
    total = 0
    for s in sorted(skills, key=lambda x: -x.priority):
        if not s.name.startswith("cwe-"):
            continue
        kw_list = s.triggers.get("keywords", []) if isinstance(s.triggers, dict) else []
        if not any(kw.lower() in query_lower for kw in kw_list):
            continue
        # Strip frontmatter — keep only the markdown body
        body = s.body if hasattr(s, "body") else getattr(s, "content", "") or ""
        if not body:
            continue
        chunk = f"\n\n## Skill: {s.name}\n{body}\n"
        if total + len(chunk) > max_chars:
            break
        bodies.append(chunk)
        total += len(chunk)
    return "".join(bodies)


def build_prompt(walkthrough: dict[str, Any], src_path: str | None = None) -> str:
    """Construct the audit prompt the agent sees. Deliberately does
    NOT name the CVE or CWE in the prompt — that would prime the
    answer and ruin the detection signal.

    F202.AA — when `src_path` is given, the prompt anchors the agent
    at a pre-cloned local tree and nudges it toward grep-driven
    triage (faster + more reproducible than asking it to clone the
    repo itself mid-turn).

    F202.AB — inject CWE classification skill bodies based on
    keyword match against project/repo. Skills MUST be curated to
    be spoiler-free (no specific file:line of the target CVE).
    """
    project = walkthrough.get("project", "this codebase")
    repo_url = walkthrough.get("repo_url", "")
    vuln_commit = walkthrough.get("vuln_commit", "")
    ref_line = f"Commit: {vuln_commit}" if vuln_commit else ""
    repo_line = f"Repo: {repo_url}" if repo_url else ""

    if src_path:
        src_line = (
            f"\nCódigo fuente pre-clonado en: {src_path}\n"
            f"Es un SNAPSHOT del árbol (no hay `.git`) — NO uses `git log`/`git`, "
            f"perdés turnos. NO clones nada, ya está completo.\n"
            f"Metodología SAST (sé DIRECTO, no te quedes orientándote con ls/pwd):\n"
            f"1. `grep -rn` los sinks de riesgo típicos del lenguaje del repo "
            f"(puntos donde input no confiable llega a una operación peligrosa).\n"
            f"2. `cat`/`sed -n` los archivos candidatos para confirmar el data-flow.\n"
            f"3. Apenas confirmes el defecto, EMITÍ `CWE-XXX en <archivo>:<línea>` "
            f"y terminá — NO sigas explorando ni re-verifiques de más."
        )
    else:
        src_line = ""

    base = (
        f"Audita el código fuente del proyecto {project} en busca de "
        f"vulnerabilidades. Identifica el CWE, el archivo y la línea "
        f"exacta donde se encuentra el defecto. Reporta hallazgos en "
        f"formato 'CWE-XXX en <archivo>:<línea>'.\n"
        f"{repo_line}\n{ref_line}{src_line}".strip()
    )

    skill_bodies = _load_cwe_skill_bodies(f"{project} {repo_url}")
    if skill_bodies:
        return (
            f"{base}\n\n"
            f"## Guía de clasificación CWE (skills auto-matched)\n"
            f"Las siguientes guías ayudan a clasificar correctamente el CWE. "
            f"NO contienen la respuesta — usalas para discriminar entre "
            f"familias hermanas (ej: CWE-119 vs CWE-125 vs CWE-787).\n"
            f"{skill_bodies}"
        )
    return base


def _agent_can_see_source(src_path: str | None) -> str:
    """Guardrail (anti phantom-bench). When the bench clones source INTO a
    container (``/workspace/...`` via ``docker exec``) but the agent runs
    elsewhere — e.g. a host ``kryon serve`` reached through KRYON_API_URL — the
    agent's tools can't read the source, so the model "detects" from memory
    instead of the code and the result is a phantom (this exact mismatch made a
    DeepSeek host-run score 1/3 without ever reading the code).

    Returns "" when the agent can (or plausibly can) see the source, or a reason
    string when it provably can't. Opt out with KRYON_BENCH_SKIP_SRC_CHECK=1.
    """
    if not src_path or not src_path.startswith("/workspace"):
        return ""  # not a container-side clone — nothing to verify
    if os.environ.get("KRYON_BENCH_SKIP_SRC_CHECK") == "1":
        return ""
    container = os.environ.get("KRYON_BENCH_CONTAINER", "kryon")
    api_url = os.environ.get("KRYON_API_URL", "http://127.0.0.1:8700")
    m = re.search(r":(\d+)", api_url)
    api_port = m.group(1) if m else ""
    try:
        ports = subprocess.run(
            ["docker", "port", container],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        ).stdout
    except Exception:
        return ""  # can't introspect docker — don't block legitimate setups
    if not api_port or api_port in ports:
        return ""  # the API port maps to the container the source was cloned into
    pretty = ports.strip().replace("\n", "; ") or "(none published)"
    return (
        f"source was cloned into container '{container}' at {src_path}, but KRYON_API_URL="
        f"{api_url} (port {api_port}) does not map to that container's published ports "
        f"[{pretty}]. The agent can't read the source → the result would be a phantom "
        f"(memory, not code). Point the container's model backend at your model instead of "
        f"running a separate host server, or set KRYON_BENCH_SKIP_SRC_CHECK=1 to override."
    )


def run_task(walkthrough_path: Path, *, prompt_override: str | None = None) -> RunResult:
    """End-to-end run for a single CVE detection task."""
    walkthrough = load_walkthrough(walkthrough_path)
    slug = walkthrough["slug"]
    cve_id = walkthrough["cve_id"]
    expected_cwe = walkthrough["expected_cwe"]
    expected_file = walkthrough.get("expected_file")
    expected_line = walkthrough.get("expected_line")
    budget = walkthrough.get("wall_budget_seconds", _DEFAULT_WALL_BUDGET_SECONDS)
    # Env override — slow reasoning models (e.g. DeepSeek thinking) need more
    # wall time than the per-task default; lets us re-run without editing fixtures.
    _budget_override = os.environ.get("KRYON_BENCH_WALL_BUDGET")
    if _budget_override:
        try:
            budget = int(_budget_override)
        except ValueError:
            pass

    wall_start = time.monotonic()
    transcript = ""
    error: str | None = None

    # F202.AA — pre-clone the vulnerable repo so the agent can grep
    # it instead of having to clone mid-turn. None means skip.
    src_path = prepare_source(walkthrough)

    # Guardrail: abort with a clear error instead of producing a phantom result
    # if the agent won't be able to read the cloned source (host-agent vs
    # container-source mismatch). Skipping the LLM call also saves tokens.
    _src_warn = _agent_can_see_source(src_path)
    if _src_warn:
        return RunResult(
            slug=slug,
            cve_id=cve_id,
            detected=False,
            cwe_match=False,
            file_match=False,
            line_match=False,
            wall_time_seconds=time.monotonic() - wall_start,
            expected_cwe=expected_cwe,
            actual_cwes_found=[],
            expected_file=expected_file,
            expected_line=expected_line,
            actual_file_hits=[],
            error=f"src_unreachable: {_src_warn}",
            raw_output="",
        )

    try:
        transcript = invoke_kryon(
            prompt_override or build_prompt(walkthrough, src_path=src_path),
            timeout=budget,
        )
    except subprocess.TimeoutExpired:
        error = "kryon_timeout"
    except Exception as e:
        error = f"{type(e).__name__}: {e}"

    cwe_match, all_cwes = _detect_cwe(transcript, expected_cwe)
    file_match, file_hits = _detect_file(transcript, expected_file)
    line_match = _detect_line(transcript, expected_line)
    detected = cwe_match and file_match  # primary success signal

    return RunResult(
        slug=slug,
        cve_id=cve_id,
        detected=detected,
        cwe_match=cwe_match,
        file_match=file_match,
        line_match=line_match,
        wall_time_seconds=time.monotonic() - wall_start,
        expected_cwe=expected_cwe,
        actual_cwes_found=all_cwes,
        expected_file=expected_file,
        expected_line=expected_line,
        actual_file_hits=file_hits,
        error=error,
        raw_output=transcript[:5000],  # cap for report payload
    )
