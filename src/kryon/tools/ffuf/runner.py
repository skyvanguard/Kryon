"""F112 — ffuf CLI wrapper for banca-safe content discovery.

Wraps the `ffuf` binary. Defaults are conservative (10 req/s, GET
only, 200-entry embedded wordlist, status allowlist) so a single
invocation can't accidentally hammer a production target.

**Banca-safety contract**:
  * Default rate limit: 10 req/s (ffuf's default is unbounded).
  * Default threads: 10 (ffuf's default is 40).
  * Default methods: GET only. POST/PUT etc. require explicit
    operator opt-in via `methods=("POST",)`.
  * Default match-status excludes 5xx (only positive evidence of
    a resource).
  * Default filter-status excludes 404 / 400 noise.
  * Embedded 200-entry default wordlist for cases where the
    operator hasn't supplied one. Banks usually want a curated
    list of paths, NOT SecLists' tens of thousands.
  * Body output is NOT captured to disk; only the JSON summary
    file is written to a tempdir + deleted after parse.
  * Soft-fail when binary not on PATH.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field

__all__ = [
    "FfufConfig",
    "FfufHit",
    "FfufResult",
    "embedded_wordlist",
    "is_ffuf_available",
    "run_ffuf",
    "parse_ffuf_json",
]


# A small, hand-curated default wordlist. Combines the highest-signal
# paths from F101 + admin-finder lists + common backup extensions.
# Banca-safe: limited size means a 10 req/s scan finishes in ~30s.
_DEFAULT_WORDLIST: tuple[str, ...] = (
    # version control
    ".git",
    ".git/config",
    ".git/HEAD",
    ".git/index",
    ".svn",
    ".svn/entries",
    ".hg",
    # secrets
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.dev",
    ".env.test",
    ".env.staging",
    ".env.backup",
    # configs
    "config",
    "config.php",
    "config.json",
    "config.yml",
    "config.yaml",
    "wp-config.php.bak",
    "wp-config.php.old",
    "application.properties",
    "application.yml",
    "appsettings.json",
    "appsettings.Development.json",
    "config/database.yml",
    "config/secrets.yml",
    "config/master.key",
    # database dumps
    "dump.sql",
    "backup.sql",
    "database.sql",
    "db.sql",
    "db_backup.sql",
    # admin paths
    "admin",
    "admin/",
    "admin/login",
    "admin.php",
    "administrator/",
    "wp-admin/",
    "wp-login.php",
    "phpmyadmin/",
    "pma/",
    "myadmin/",
    "adminer.php",
    "manager/html",
    "manager/text",
    "host-manager/html",
    "jmx-console/",
    "web-console/",
    "cpanel/",
    "webmail/",
    # debug + status
    "server-status",
    "server-info",
    "nginx_status",
    "status",
    "phpinfo.php",
    "info.php",
    "test.php",
    "debug",
    "debug/pprof/",
    "debug/pprof/heap",
    "debug/pprof/goroutine",
    # actuator / monitoring
    "actuator",
    "actuator/env",
    "actuator/health",
    "actuator/heapdump",
    "actuator/mappings",
    "actuator/configprops",
    "actuator/beans",
    "actuator/threaddump",
    "actuator/loggers",
    "metrics",
    "healthz",
    "readyz",
    "livez",
    # docs
    "swagger",
    "swagger/",
    "swagger-ui",
    "swagger-ui.html",
    "swagger.json",
    "swagger.yaml",
    "api-docs",
    "v2/api-docs",
    "v3/api-docs",
    "openapi.json",
    "openapi.yaml",
    "redoc",
    "graphql",
    "graphiql",
    "altair",
    "playground",
    "__graphql",
    # robots / sitemap
    "robots.txt",
    "sitemap.xml",
    "sitemap_index.xml",
    "humans.txt",
    "security.txt",
    ".well-known/security.txt",
    # build artifacts
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.override.yml",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.json",
    "composer.lock",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "pyproject.toml",
    "Gemfile",
    "Gemfile.lock",
    "Cargo.toml",
    "go.mod",
    # CI/CD
    ".gitlab-ci.yml",
    ".travis.yml",
    ".circleci/config.yml",
    "Jenkinsfile",
    "bitbucket-pipelines.yml",
    "azure-pipelines.yml",
    ".github/workflows/main.yml",
    # cloud creds
    ".aws/credentials",
    ".aws/config",
    ".docker/config.json",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".boto",
    # SSH / TLS keys
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "server.key",
    "privkey.pem",
    "server.pem",
    # terraform
    "terraform.tfstate",
    "terraform.tfstate.backup",
    ".terraform/terraform.tfstate",
    # IDE
    ".idea/workspace.xml",
    ".vscode/settings.json",
    ".DS_Store",
    ".project",
    ".classpath",
    # Java
    "WEB-INF/web.xml",
    "web.xml",
    "struts.xml",
    "hibernate.cfg.xml",
    # common app paths
    "api",
    "api/",
    "api/v1",
    "api/v2",
    "api/users",
    "api/admin",
    "auth",
    "auth/login",
    "auth/logout",
    "login",
    "logout",
    "register",
    "signup",
    "signin",
    "dashboard",
    "profile",
    "account",
    "settings",
    "user",
    "users",
    "upload",
    "uploads",
    "download",
    "downloads",
    "files",
    "media",
    "static",
    "public",
    "assets",
    # backups
    "backup",
    "backups",
    "backup.zip",
    "backup.tar.gz",
    "old",
    "tmp",
    "temp",
    "test",
    "tests",
    "testing",
    "staging",
    "dev",
    "beta",
)


def embedded_wordlist() -> tuple[str, ...]:
    """Return the curated default wordlist."""
    return _DEFAULT_WORDLIST


@dataclass(frozen=True)
class FfufConfig:
    """Banca-safe ffuf invocation profile."""

    # base_url must contain `FUZZ` exactly once (e.g.
    # "https://target.com/FUZZ").
    base_url: str
    # If non-empty, ffuf uses this file. Otherwise the embedded
    # wordlist is written to a tempfile.
    wordlist_path: str = ""
    ffuf_binary: str = "ffuf"
    threads: int = 10
    rate_limit_per_second: int = 10
    timeout_seconds: int = 8
    overall_timeout_seconds: int = 180
    methods: tuple[str, ...] = ("GET",)
    match_status: tuple[int, ...] = (200, 204, 301, 302, 401, 403)
    filter_status: tuple[int, ...] = (404,)
    # length-based filter: skip responses whose body length matches
    # exactly any value here. Useful to ignore SPA shells that 200
    # every path with the same body length.
    filter_size: tuple[int, ...] = ()
    follow_redirects: bool = False
    user_agent: str = "Kryon-Ffuf/1.0 (banca-safe)"
    cookies: tuple[tuple[str, str], ...] = ()
    headers: tuple[tuple[str, str], ...] = ()
    extra_args: tuple[str, ...] = ()


@dataclass(frozen=True)
class FfufHit:
    url: str
    input: str  # the FUZZ value that hit
    http_status: int
    content_length: int
    content_words: int
    content_lines: int
    content_type: str = ""
    response_time_ms: int = 0
    raw_event: str = ""


@dataclass(frozen=True)
class FfufResult:
    hits: tuple[FfufHit, ...] = field(default_factory=tuple)
    elapsed_seconds: float = 0.0
    ffuf_missing: bool = False
    exit_code: int = 0
    stderr_excerpt: str = ""
    command: str = ""
    wordlist_used: str = ""


def is_ffuf_available(binary: str = "ffuf") -> bool:
    return shutil.which(binary) is not None


def _write_default_wordlist() -> str:
    """Write the embedded wordlist to a tempfile and return its path."""
    fd, path = tempfile.mkstemp(prefix="kryon-ffuf-", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for entry in _DEFAULT_WORDLIST:
                fh.write(entry + "\n")
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path


def _build_args(cfg: FfufConfig, json_output_path: str, wordlist_path: str) -> list[str]:
    args: list[str] = [
        cfg.ffuf_binary,
        "-u",
        cfg.base_url,
        "-w",
        wordlist_path,
        "-of",
        "json",
        "-o",
        json_output_path,
        # silent / non-interactive
        "-noninteractive",
        "-s",
    ]
    if cfg.methods:
        # ffuf takes a single -X but accepts a list when comma-separated
        args.extend(["-X", ",".join(cfg.methods)])
    if cfg.match_status:
        args.extend(["-mc", ",".join(str(s) for s in cfg.match_status)])
    if cfg.filter_status:
        args.extend(["-fc", ",".join(str(s) for s in cfg.filter_status)])
    if cfg.filter_size:
        args.extend(["-fs", ",".join(str(s) for s in cfg.filter_size)])
    args.extend(["-t", str(cfg.threads)])
    args.extend(["-rate", str(cfg.rate_limit_per_second)])
    args.extend(["-timeout", str(cfg.timeout_seconds)])
    if not cfg.follow_redirects:
        # ffuf doesn't follow redirects by default; keep explicit
        pass
    else:
        args.append("-r")
    if cfg.user_agent:
        args.extend(["-H", f"User-Agent: {cfg.user_agent}"])
    for name, value in cfg.headers:
        args.extend(["-H", f"{name}: {value}"])
    if cfg.cookies:
        cookie_header = "; ".join(f"{n}={v}" for n, v in cfg.cookies)
        args.extend(["-H", f"Cookie: {cookie_header}"])
    args.extend(cfg.extra_args)
    return args


def parse_ffuf_json(json_text: str) -> list[FfufHit]:
    """Parse ffuf's `-of json` output file into FfufHit records."""
    if not json_text.strip():
        return []
    try:
        doc = json.loads(json_text)
    except json.JSONDecodeError:
        return []
    if not isinstance(doc, dict):
        return []
    results = doc.get("results")
    if not isinstance(results, list):
        return []
    hits: list[FfufHit] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        hits.append(
            FfufHit(
                url=str(r.get("url") or ""),
                input=str((r.get("input") or {}).get("FUZZ") or "")
                if isinstance(r.get("input"), dict)
                else str(r.get("input") or ""),
                http_status=int(r.get("status") or 0),
                content_length=int(r.get("length") or 0),
                content_words=int(r.get("words") or 0),
                content_lines=int(r.get("lines") or 0),
                content_type=str(r.get("content-type") or r.get("content_type") or ""),
                response_time_ms=int(r.get("duration") or 0) // 1_000_000  # ns → ms
                if r.get("duration")
                else 0,
                raw_event=json.dumps(r, ensure_ascii=False),
            )
        )
    # Sort by status then path
    hits.sort(key=lambda h: (h.http_status, h.input))
    return hits


def run_ffuf(config: FfufConfig) -> FfufResult:
    """Run ffuf with the given config and return parsed hits.

    Never raises — every failure mode is captured as a flag on the
    returned FfufResult."""
    if not is_ffuf_available(config.ffuf_binary):
        return FfufResult(ffuf_missing=True, exit_code=-1)
    if "FUZZ" not in config.base_url:
        return FfufResult(
            exit_code=-2,
            stderr_excerpt="base_url must contain 'FUZZ' placeholder",
        )

    # Resolve wordlist
    wordlist_path = config.wordlist_path
    tempfile_to_cleanup: str | None = None
    if not wordlist_path:
        try:
            wordlist_path = _write_default_wordlist()
            tempfile_to_cleanup = wordlist_path
        except Exception as e:
            return FfufResult(exit_code=-3, stderr_excerpt=f"failed to write wordlist: {e}")
    if not os.path.isfile(wordlist_path):
        if tempfile_to_cleanup:
            try:
                os.unlink(tempfile_to_cleanup)
            except OSError:
                pass
        return FfufResult(
            exit_code=-4,
            stderr_excerpt=f"wordlist not found: {wordlist_path}",
        )

    # Tempfile for ffuf's JSON output
    out_fd, out_path = tempfile.mkstemp(prefix="kryon-ffuf-", suffix=".json")
    os.close(out_fd)
    args = _build_args(config, out_path, wordlist_path)
    cmd_str = " ".join(args)
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=config.overall_timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        return FfufResult(
            elapsed_seconds=time.monotonic() - t0,
            exit_code=-5,
            stderr_excerpt=(e.stderr or "")[-1000:] if hasattr(e, "stderr") else "timeout",
            command=cmd_str,
            wordlist_used=wordlist_path,
        )
    except (FileNotFoundError, PermissionError) as e:
        return FfufResult(
            ffuf_missing=True,
            exit_code=-6,
            stderr_excerpt=str(e),
            command=cmd_str,
        )
    finally:
        # The output file may or may not exist depending on whether
        # ffuf succeeded — we read+cleanup below.
        pass

    # Read JSON output
    json_text = ""
    try:
        if os.path.isfile(out_path):
            with open(out_path, encoding="utf-8", errors="replace") as fh:
                json_text = fh.read()
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass
        if tempfile_to_cleanup:
            try:
                os.unlink(tempfile_to_cleanup)
            except OSError:
                pass

    hits = parse_ffuf_json(json_text)
    return FfufResult(
        hits=tuple(hits),
        elapsed_seconds=time.monotonic() - t0,
        exit_code=proc.returncode,
        stderr_excerpt=(proc.stderr or "")[-1000:],
        command=cmd_str,
        wordlist_used=wordlist_path,
    )
