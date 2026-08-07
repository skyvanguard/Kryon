"""Fase A — unified feed refresh for the appliance's "growing determinism".

Orchestrates the update mechanisms that already existed but lived scattered
and manual: nuclei-templates, the ExploitDB CSV, the NVD CVE cache, and skill
playbooks. Each feed is best-effort and ISOLATED — one failing feed never
aborts the others, so a nightly `kryon update` degrades gracefully.

Both the CLI (`kryon update`) and the scheduler (kind="update") drive this.
Heavy imports are deferred into each updater so importing this module is cheap.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

_DETAIL_CAP = 200


@dataclass(frozen=True)
class UpdateResult:
    """Outcome of refreshing one feed."""

    name: str
    status: str  # "ok" | "failed" | "skipped"
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def failed(self) -> bool:
        return self.status == "failed"


# --- individual feeds ------------------------------------------------------


def update_nuclei_templates(*, runner: Callable | None = None, timeout: int = 300) -> UpdateResult:
    """Refresh nuclei-templates from upstream (`nuclei -update-templates`).
    ``runner`` is injectable for testing; defaults to ``subprocess.run``."""
    run = runner or subprocess.run
    try:
        proc = run(
            ["nuclei", "-update-templates", "-silent"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return UpdateResult("nuclei-templates", "skipped", "nuclei binary not found")
    except subprocess.TimeoutExpired:
        return UpdateResult("nuclei-templates", "failed", f"timed out after {timeout}s")
    except Exception as exc:  # noqa: BLE001 — best-effort; never propagate
        return UpdateResult("nuclei-templates", "failed", f"{type(exc).__name__}: {str(exc)[:_DETAIL_CAP]}")
    rc = getattr(proc, "returncode", 1)
    if rc == 0:
        return UpdateResult("nuclei-templates", "ok", "templates refreshed from upstream")
    stderr = (getattr(proc, "stderr", "") or "")[:_DETAIL_CAP]
    return UpdateResult("nuclei-templates", "failed", f"exit {rc}: {stderr}")


def update_exploitdb(*, force: bool = True) -> UpdateResult:
    """Refresh the ExploitDB CSV (feeds the CVE cross-reference)."""
    try:
        from kryon.knowledge.exploitdb_scraper import ExploitDBScraper

        path = ExploitDBScraper().download_csv(force_refresh=force)
        return UpdateResult("exploitdb", "ok", f"CSV refreshed → {path}")
    except Exception as exc:  # noqa: BLE001
        return UpdateResult("exploitdb", "failed", f"{type(exc).__name__}: {str(exc)[:_DETAIL_CAP]}")


def update_cve_cache(*, years_range: str | None = None) -> UpdateResult:
    """Refresh the NVD CVE cache (the anti-hallucination gate). Defaults to the
    current + previous year — recent CVEs matter most for a fresh scan; pass a
    range for a wider backfill."""
    try:
        from kryon.validation.cve_cache_updater import resolve_years, update_cache

        if years_range:
            years = resolve_years(year=None, years_range=years_range, all_years=False)
        else:
            y = datetime.now(timezone.utc).year
            years = [y - 1, y]
        result = update_cache(years)
        summary = result.summary() if hasattr(result, "summary") else f"years {years[0]}..{years[-1]}"
        if getattr(result, "errors", None):
            return UpdateResult("cve-cache", "failed", summary[:_DETAIL_CAP])
        return UpdateResult("cve-cache", "ok", summary[:_DETAIL_CAP])
    except Exception as exc:  # noqa: BLE001
        return UpdateResult("cve-cache", "failed", f"{type(exc).__name__}: {str(exc)[:_DETAIL_CAP]}")


def update_skills(*, repo_url: str | None, branch: str = "main", force: bool = False) -> UpdateResult:
    """Pull skill playbooks from an upstream git repo. Skipped when no repo is
    configured (it's opt-in — there's no canonical public playbook repo)."""
    if not repo_url:
        return UpdateResult("skills", "skipped", "no --skills-repo configured")
    try:
        from kryon.skills.updater import update_from_git

        r = update_from_git(repo_url, branch=branch, force=force)
        if getattr(r, "failed", None):
            return UpdateResult("skills", "failed", f"{len(r.failed)} playbook(s) failed")
        n_add, n_upd = len(getattr(r, "added", [])), len(getattr(r, "updated", []))
        return UpdateResult("skills", "ok", f"+{n_add} added, {n_upd} updated")
    except Exception as exc:  # noqa: BLE001
        return UpdateResult("skills", "failed", f"{type(exc).__name__}: {str(exc)[:_DETAIL_CAP]}")


def update_openvas_feed(*, runner: Callable | None = None, timeout: int = 1800) -> UpdateResult:
    """Sync the Greenbone Community Feed via ``greenbone-feed-sync``.

    Only runs when the binary is present locally (the "operator on Kali"
    model). In the separate-container appliance the OpenVAS container manages
    its own feed, so a missing binary is ``skipped`` — not a failure. Feed sync
    pulls GBs → generous timeout. ``runner`` is injectable for testing."""
    run = runner or subprocess.run
    try:
        proc = run(
            ["greenbone-feed-sync"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return UpdateResult(
            "openvas-feed", "skipped", "greenbone-feed-sync not found (OpenVAS container manages its own feed)"
        )
    except subprocess.TimeoutExpired:
        return UpdateResult("openvas-feed", "failed", f"timed out after {timeout}s")
    except Exception as exc:  # noqa: BLE001 — best-effort; never propagate
        return UpdateResult("openvas-feed", "failed", f"{type(exc).__name__}: {str(exc)[:_DETAIL_CAP]}")
    rc = getattr(proc, "returncode", 1)
    if rc == 0:
        return UpdateResult("openvas-feed", "ok", "Greenbone Community Feed synced")
    stderr = (getattr(proc, "stderr", "") or "")[:_DETAIL_CAP]
    return UpdateResult("openvas-feed", "failed", f"exit {rc}: {stderr}")


def update_cinc_profiles(
    *,
    profiles: list[str] | None = None,
    cache_dir: str | None = None,
    runner: Callable | None = None,
    timeout: int = 300,
) -> UpdateResult:
    """Pre-fetch the dev-sec/CIS Cinc profiles into a local cache (git clone/pull).

    Cinc can fetch profiles from a git URL at exec time, so this is mainly for
    air-gapped appliances. Skipped when git is absent or no git-URL profiles are
    configured. ``runner`` is injectable for testing."""
    import shutil
    from pathlib import Path

    if shutil.which("git") is None:
        return UpdateResult("cinc-profiles", "skipped", "git not found")

    from kryon.integrations.cinc.config import profiles_from_env

    profs = profiles if profiles is not None else profiles_from_env()
    git_urls = [p for p in profs if p.startswith(("http://", "https://", "git@"))]
    if not git_urls:
        return UpdateResult("cinc-profiles", "skipped", "no git-URL profiles to cache")

    cdir = Path(cache_dir) if cache_dir else (Path.home() / ".kryon" / "cinc-profiles")
    cdir.mkdir(parents=True, exist_ok=True)
    run = runner or subprocess.run
    ok = failed = 0
    for url in git_urls:
        name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        dest = cdir / name
        try:
            if dest.exists():
                proc = run(
                    ["git", "-C", str(dest), "pull", "--ff-only"], capture_output=True, text=True, timeout=timeout
                )
            else:
                proc = run(
                    ["git", "clone", "--depth", "1", url, str(dest)], capture_output=True, text=True, timeout=timeout
                )
            ok += 1 if getattr(proc, "returncode", 1) == 0 else 0
            failed += 0 if getattr(proc, "returncode", 1) == 0 else 1
        except Exception:  # noqa: BLE001 — best-effort per profile
            failed += 1
    if failed and not ok:
        return UpdateResult("cinc-profiles", "failed", f"{failed} profile(s) failed")
    return UpdateResult("cinc-profiles", "ok", f"{ok} cached, {failed} failed")


def update_cve_corpus(
    *,
    limit: int = 200,
    ecosystems: list[str] | None = None,
    scraper: Callable | None = None,
    enricher: Callable | None = None,
    ingester: Callable | None = None,
    jsonl_path: str | None = None,
) -> UpdateResult:
    """Refresh the CVE-diff corpus — the 0-day hunter's novelty backbone.

    Pipeline: scrape GHSA advisories with fix commits → enrich each into a
    before/after diff JSONL → ingest into the ChromaDB corpus. Until this fed
    the corpus, it stayed empty and ``novelty_gate`` reported EVERYTHING as
    "likely-novel" (M7) — inert.

    Gated on ``KRYON_EMBEDDING_BASE_URL``: the corpus needs an embedding
    backend and, like the rest of the RAG surface, is OFF by default
    (banca-safe). Without it we ``skip`` rather than fall back to Chroma's
    default embedder, which would hang air-gapped downloading the ~80MB ONNX
    model. Opt-in (not in ``DEFAULT_FEEDS``); the pipeline is heavy (clones the
    ~300MB advisory DB + each fix-commit repo), so ``KRYON_CVE_CORPUS_LIMIT``
    caps the advisory count. The three stages are injectable for testing.
    """
    import os

    if not os.environ.get("KRYON_EMBEDDING_BASE_URL"):
        return UpdateResult("cve-corpus", "skipped", "KRYON_EMBEDDING_BASE_URL not set (corpus embeddings disabled)")

    try:
        limit = int(os.environ.get("KRYON_CVE_CORPUS_LIMIT", str(limit)))

        # 1. Scrape advisories that carry a parseable fix commit.
        if scraper is None:
            from kryon.knowledge.scrapers.github_advisory_scraper import GitHubAdvisoryScraper

            def scraper(*, limit, ecosystems):  # noqa: A002 — mirror scrape() kwargs
                return GitHubAdvisoryScraper().scrape(limit=limit, ecosystems=ecosystems)

        advisories = scraper(limit=limit, ecosystems=ecosystems)
        if not advisories:
            return UpdateResult("cve-corpus", "ok", "0 advisories with fix commits found")

        # 2. Enrich each fix commit into a before/after diff JSONL.
        import tempfile
        from pathlib import Path

        out = jsonl_path or str(Path(tempfile.gettempdir()) / "kryon_cve_corpus_enriched.jsonl")
        if enricher is None:
            from kryon.knowledge.scrapers.cve_diff_enricher import enrich_batch

            enrich_fn: Callable = enrich_batch
        else:
            enrich_fn = enricher
        stats = enrich_fn(advisories, out_path=out)
        written = stats.get("entries_written", 0) if isinstance(stats, dict) else 0
        if not written:
            return UpdateResult("cve-corpus", "ok", f"{len(advisories)} advisories, 0 diffs enriched")

        # 3. Ingest the enriched JSONL into the ChromaDB corpus.
        if ingester is None:
            from kryon.knowledge.cve_corpus import ingest_jsonl

            ingest_fn: Callable = ingest_jsonl
        else:
            ingest_fn = ingester
        n = ingest_fn(out)
        return UpdateResult("cve-corpus", "ok", f"{n} entries ingested from {len(advisories)} advisories")
    except Exception as exc:  # noqa: BLE001 — best-effort; never propagate
        return UpdateResult("cve-corpus", "failed", f"{type(exc).__name__}: {str(exc)[:_DETAIL_CAP]}")


# --- orchestrator ----------------------------------------------------------

DEFAULT_FEEDS: tuple[str, ...] = ("nuclei", "exploitdb", "cve-cache")
ALL_FEEDS: tuple[str, ...] = ("nuclei", "exploitdb", "cve-cache", "skills", "openvas", "cinc", "cve-corpus")


def run_updates(
    feeds: list[str] | None = None,
    *,
    cve_years: str | None = None,
    skills_repo: str | None = None,
    skills_branch: str = "main",
    skills_force: bool = False,
    nuclei_runner: Callable | None = None,
    openvas_runner: Callable | None = None,
    cinc_runner: Callable | None = None,
) -> list[UpdateResult]:
    """Refresh the selected feeds (default: nuclei + exploitdb + cve-cache).
    Isolated per feed — a failure is recorded, not raised."""
    selected = list(feeds) if feeds else list(DEFAULT_FEEDS)
    results: list[UpdateResult] = []
    for feed in selected:
        if feed == "nuclei":
            results.append(update_nuclei_templates(runner=nuclei_runner))
        elif feed == "exploitdb":
            results.append(update_exploitdb())
        elif feed == "cve-cache":
            results.append(update_cve_cache(years_range=cve_years))
        elif feed == "skills":
            results.append(update_skills(repo_url=skills_repo, branch=skills_branch, force=skills_force))
        elif feed == "openvas":
            results.append(update_openvas_feed(runner=openvas_runner))
        elif feed == "cinc":
            results.append(update_cinc_profiles(runner=cinc_runner))
        elif feed == "cve-corpus":
            results.append(update_cve_corpus())
        else:
            results.append(UpdateResult(feed, "skipped", "unknown feed"))
    return results
