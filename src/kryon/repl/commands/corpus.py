"""
/corpus — inspect and query the CVE-with-diff corpus from the REPL.

Subcommands:
  /corpus                       — summary: count, CWE distribution, top repos
  /corpus stats                 — same as no-args
  /corpus query "<snippet>"     — run recall_similar_code_pattern + pretty-print
  /corpus show <ghsa_or_cve>    — full record for one entry
  /corpus cwe                   — CWE frequency table
  /corpus repos                 — unique repos with entry counts

Lets you sanity-check retrieval quality WITHOUT launching a full /hunt.
"""

from __future__ import annotations

import os
from collections import Counter
from typing import Optional

from rich.console import Console
from rich.table import Table

from kryon.repl.commands.base import Command, register_command

console = Console()


def _get_collection():
    """Lazy import so REPL startup isn't affected."""
    from kryon.knowledge import cve_corpus
    return cve_corpus._get_collection(), cve_corpus


class CorpusCommand(Command):
    def __init__(self):
        super().__init__(
            name="/corpus",
            description="Inspect the CVE-with-diff corpus (recall_similar_code_pattern backend)",
        )
        self.add_subcommand("stats", "Counts + CWE distribution + top repos", self.handle_stats)
        self.add_subcommand("query", "Semantic query against the corpus", self.handle_query)
        self.add_subcommand("show", "Show one entry by GHSA / CVE id", self.handle_show)
        self.add_subcommand("cwe", "CWE frequency table", self.handle_cwe)
        self.add_subcommand("repos", "Unique repos with entry counts", self.handle_repos)

    def handle_no_args(self) -> bool:
        return self.handle_stats(None)

    # ------------------------------------------------------------------

    def handle_stats(self, args: Optional[list[str]] = None) -> bool:
        try:
            coll, cvc = _get_collection()
        except Exception as e:
            console.print(f"[red]corpus unavailable: {e}[/red]")
            return False

        stats = cvc.corpus_stats()
        count = stats.get("count", 0)

        if count == 0:
            console.print("[yellow]Corpus is empty.[/yellow] Run:")
            console.print("  [cyan]python scripts/ingest_cve_corpus.py --scrape-limit 300 --enrich-limit 100[/cyan]")
            return True

        # Pull all metadatas for aggregation (capped)
        data = coll.get(limit=min(count, 1000))
        metas = data.get("metadatas") or []

        cwe_counter: Counter = Counter()
        repo_counter: Counter = Counter()
        severity_counter: Counter = Counter()
        for m in metas:
            for c in (m.get("cwe_ids") or "").split(","):
                c = c.strip()
                if c:
                    cwe_counter[c] += 1
            if m.get("repo"):
                repo_counter[m["repo"]] += 1
            if m.get("severity"):
                severity_counter[m["severity"]] += 1

        # Header
        console.print()
        console.print(f"[bold cyan]Corpus: {stats.get('collection', '?')}[/bold cyan]")
        console.print(f"  entries:     [bold]{count}[/bold]")
        console.print(f"  persist dir: [dim]{stats.get('persist_dir', '?')}[/dim]")
        console.print()

        # CWE table
        if cwe_counter:
            t = Table(title="CWE distribution (top 10)", show_header=True)
            t.add_column("CWE", style="cyan")
            t.add_column("count", justify="right")
            for cwe, n in cwe_counter.most_common(10):
                t.add_row(cwe, str(n))
            console.print(t)

        # Severity
        if severity_counter:
            console.print("\n[bold]Severity:[/bold]", end=" ")
            bits = [f"{sev}={n}" for sev, n in severity_counter.most_common()]
            console.print("  ".join(bits))

        # Top repos
        if repo_counter:
            t2 = Table(title="Top repos (10)", show_header=True)
            t2.add_column("repo", style="green")
            t2.add_column("count", justify="right")
            for repo, n in repo_counter.most_common(10):
                t2.add_row(repo, str(n))
            console.print(t2)

        return True

    # ------------------------------------------------------------------

    def handle_query(self, args: Optional[list[str]] = None) -> bool:
        if not args:
            console.print("[yellow]usage: /corpus query \"<code snippet or CWE keyword>\"[/yellow]")
            return False

        # Re-join args (they may have been space-split) and strip surrounding quotes
        query = " ".join(args).strip()
        if query.startswith('"') and query.endswith('"'):
            query = query[1:-1]
        if query.startswith("'") and query.endswith("'"):
            query = query[1:-1]

        try:
            _, cvc = _get_collection()
        except Exception as e:
            console.print(f"[red]corpus unavailable: {e}[/red]")
            return False

        matches = cvc._query_similar(query, top_k=8)
        if not matches:
            console.print("[yellow]no matches.[/yellow]")
            return True

        t = Table(title=f"Top matches for: {query[:60]}")
        t.add_column("rank", justify="right")
        t.add_column("CVE / GHSA", style="cyan")
        t.add_column("CWE", style="magenta")
        t.add_column("repo", style="green")
        t.add_column("excerpt")
        for i, m in enumerate(matches, 1):
            cve = m.get("cve_id") or m.get("ghsa_id", "")[:12]
            excerpt = (m.get("pattern_excerpt", "") or "").replace("\n", " ")[:80]
            t.add_row(
                str(i),
                cve,
                (m.get("cwe_ids", "") or "")[:25],
                m.get("repo", ""),
                excerpt + "...",
            )
        console.print(t)
        return True

    # ------------------------------------------------------------------

    def handle_show(self, args: Optional[list[str]] = None) -> bool:
        if not args:
            console.print("[yellow]usage: /corpus show <GHSA-xxxx-... | CVE-YYYY-NNNN>[/yellow]")
            return False

        needle = args[0]
        try:
            coll, _ = _get_collection()
        except Exception as e:
            console.print(f"[red]corpus unavailable: {e}[/red]")
            return False

        # Walk metadatas looking for a match
        data = coll.get(limit=1000)
        ids = data.get("ids") or []
        docs = data.get("documents") or []
        metas = data.get("metadatas") or []
        found_idx = None
        for i, m in enumerate(metas):
            if m.get("cve_id") == needle or m.get("ghsa_id") == needle:
                found_idx = i
                break
        if found_idx is None:
            console.print(f"[red]no entry matches {needle!r}[/red]")
            return False

        meta = metas[found_idx]
        console.print(f"\n[bold cyan]{meta.get('ghsa_id', '')}[/bold cyan] "
                      f"{meta.get('cve_id', '')}")
        for k, v in meta.items():
            console.print(f"  [dim]{k}:[/dim] {v}")
        console.print("\n[bold]Pattern:[/bold]")
        console.print(docs[found_idx][:3000])
        if len(docs[found_idx]) > 3000:
            console.print(f"[dim]... ({len(docs[found_idx]) - 3000} more chars)[/dim]")
        return True

    # ------------------------------------------------------------------

    def handle_cwe(self, args: Optional[list[str]] = None) -> bool:
        try:
            coll, _ = _get_collection()
        except Exception as e:
            console.print(f"[red]corpus unavailable: {e}[/red]")
            return False

        data = coll.get(limit=2000)
        metas = data.get("metadatas") or []
        counter: Counter = Counter()
        for m in metas:
            for c in (m.get("cwe_ids") or "").split(","):
                c = c.strip()
                if c:
                    counter[c] += 1

        t = Table(title=f"CWE frequency  (N={sum(counter.values())}, unique={len(counter)})")
        t.add_column("CWE", style="cyan")
        t.add_column("count", justify="right")
        t.add_column("%", justify="right")
        total = sum(counter.values()) or 1
        for cwe, n in counter.most_common():
            t.add_row(cwe, str(n), f"{n/total*100:.1f}")
        console.print(t)
        return True

    def handle_repos(self, args: Optional[list[str]] = None) -> bool:
        try:
            coll, _ = _get_collection()
        except Exception as e:
            console.print(f"[red]corpus unavailable: {e}[/red]")
            return False

        data = coll.get(limit=2000)
        metas = data.get("metadatas") or []
        counter: Counter = Counter()
        for m in metas:
            if m.get("repo"):
                counter[m["repo"]] += 1

        t = Table(title=f"Repos represented  (unique={len(counter)})")
        t.add_column("repo", style="green")
        t.add_column("count", justify="right")
        for repo, n in counter.most_common():
            t.add_row(repo, str(n))
        console.print(t)
        return True


# Register
register_command(CorpusCommand())
