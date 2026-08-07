"""Juice Shop RAG — semantic retriever over the writeup corpus (F18.3).

Given a query string (typically a challenge name + description), returns
the top-k most relevant writeups from ``docs/juice_shop_writeups.json``
with their known-working payload.

Uses Ollama's ``nomic-embed-text`` via the REST embeddings endpoint.
Falls back to a token-overlap scorer when Ollama is unreachable so the
bench always has *some* retrieval signal.

Usage:
    from juice_shop_rag import JuiceShopRAG
    rag = JuiceShopRAG()
    rag.build()
    for hit in rag.query("login as admin SQL injection", k=3):
        print(hit["key"], hit["payload"])
"""

from __future__ import annotations

import json
import math
import os
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
CORPUS_PATH = REPO / "docs" / "juice_shop_writeups.json"
SUCCESS_PATH = REPO / "docs" / "juice_shop_success_cases.json"
OLLAMA_URL = os.environ.get("OLLAMA_HOST_URL", "http://localhost:11435/v1")
EMBED_MODEL = os.environ.get("KRYON_EMBEDDING_MODEL", "nomic-embed-text")


@dataclass
class Writeup:
    key: str
    name: str
    category: str
    difficulty: int
    payload: str
    solution: str

    @property
    def doc_text(self) -> str:
        """Text used to compute the embedding."""
        return f"{self.name}. Category: {self.category}. {self.solution}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "category": self.category,
            "difficulty": self.difficulty,
            "payload": self.payload,
            "solution": self.solution,
        }


@dataclass
class SuccessCase:
    """A previously-validated attack sequence (PTT-style). RapidPen pattern:
    retrieve these on every tool output so the model can see a concrete
    worked example when its current turn result resembles a known flag.
    """

    challenge_key: str
    query: str
    steps: list[str]
    expected_response: str
    notes: str = ""

    @property
    def doc_text(self) -> str:
        return f"{self.query}. Steps: {' | '.join(self.steps)}. {self.expected_response}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenge_key": self.challenge_key,
            "query": self.query,
            "steps": self.steps,
            "expected_response": self.expected_response,
            "notes": self.notes,
        }


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _tokenize(s: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", s.lower()) if len(w) > 2}


def _jaccard(a: str, b: str) -> float:
    ta, tb = _tokenize(a), _tokenize(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def _embed_via_ollama(text: str, timeout_s: int = 10) -> list[float] | None:
    """Get an embedding from Ollama. Returns None on any failure."""
    payload = json.dumps({"model": EMBED_MODEL, "input": text}).encode()
    req = urllib.request.Request(
        f"{OLLAMA_URL}/embeddings",
        data=payload,
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer ollama"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as r:
            doc = json.loads(r.read())
        # Ollama-flavoured OpenAI-compat returns {"data": [{"embedding": [...]}]}
        data = doc.get("data") or []
        if data and isinstance(data, list):
            return data[0].get("embedding")
        # Fallback: native Ollama /api/embeddings shape
        if "embedding" in doc:
            return doc["embedding"]
        return None
    except Exception:
        return None


class JuiceShopRAG:
    """Dual-index RAG (RapidPen pattern).

    - ``writeups``  — generic "how-to" corpus (per-challenge writeup with
      payload + solution). Retrieved once at session start to seed the
      system prompt.
    - ``successes`` — worked PTT-style command sequences. Retrieved on
      every tool output so the model can spot "this looks like pattern X,
      try the next step". Smaller, higher precision index.
    """

    def __init__(
        self,
        corpus_path: Path = CORPUS_PATH,
        success_path: Path = SUCCESS_PATH,
    ):
        self.corpus_path = corpus_path
        self.success_path = success_path
        self.writeups: list[Writeup] = []
        self.successes: list[SuccessCase] = []
        self._embeddings: list[list[float] | None] = []
        self._success_embeddings: list[list[float] | None] = []
        self._mode: str = "jaccard"  # "ollama" or "jaccard"

    def _load_corpus(self) -> None:
        raw = json.loads(self.corpus_path.read_text(encoding="utf-8"))
        self.writeups = [Writeup(**w) for w in raw]
        if self.success_path.exists():
            raw_s = json.loads(self.success_path.read_text(encoding="utf-8"))
            self.successes = [SuccessCase(**s) for s in raw_s]

    def build(self) -> None:
        """Load corpora + pre-compute embeddings. Lazy — call once."""
        if self.writeups:
            return
        self._load_corpus()

        # Try Ollama once; if the first embedding fails we fall back.
        probe = _embed_via_ollama(self.writeups[0].doc_text)
        if probe is None:
            self._mode = "jaccard"
            self._embeddings = [None] * len(self.writeups)
            self._success_embeddings = [None] * len(self.successes)
            return

        self._mode = "ollama"
        self._embeddings = [probe]
        for w in self.writeups[1:]:
            e = _embed_via_ollama(w.doc_text)
            self._embeddings.append(e)

        # Embed success cases too (small corpus, fine to embed eagerly).
        self._success_embeddings = []
        for sc in self.successes:
            self._success_embeddings.append(_embed_via_ollama(sc.doc_text))

    def query(self, q: str, k: int = 3) -> list[dict[str, Any]]:
        """Return the top-k most relevant writeups for query q (generic)."""
        if not self.writeups:
            self.build()

        scored: list[tuple[float, Writeup]] = []

        q_emb = _embed_via_ollama(q) if self._mode == "ollama" else None

        for w, e in zip(self.writeups, self._embeddings):
            if q_emb is not None and e is not None:
                score = _cosine(q_emb, e)
            else:
                # Jaccard on name + category + solution blob
                score = _jaccard(q, w.doc_text)
            scored.append((score, w))

        scored.sort(key=lambda t: t[0], reverse=True)
        return [
            {**w.to_dict(), "score": round(s, 3)}
            for s, w in scored[:k]
            if s > 0
        ]

    def query_success(
        self,
        q: str,
        k: int = 1,
        min_score: float = 0.3,
    ) -> list[dict[str, Any]]:
        """Return top-k success cases whose query description matches `q`.

        `min_score` filters out low-confidence matches — we only want to
        inject a hint when we're fairly sure it applies. Lower threshold
        for jaccard (noisier) so the caller can pass 0.25 or so.
        """
        if not self.successes:
            self.build()
        if not self.successes:
            return []

        scored: list[tuple[float, SuccessCase]] = []
        q_emb = _embed_via_ollama(q) if self._mode == "ollama" else None

        for sc, e in zip(self.successes, self._success_embeddings):
            if q_emb is not None and e is not None:
                score = _cosine(q_emb, e)
            else:
                score = _jaccard(q, sc.doc_text)
            scored.append((score, sc))

        scored.sort(key=lambda t: t[0], reverse=True)
        return [
            {**sc.to_dict(), "score": round(s, 3)}
            for s, sc in scored[:k]
            if s >= min_score
        ]

    def describe(self) -> dict[str, Any]:
        return {
            "corpus_size": len(self.writeups),
            "success_size": len(self.successes),
            "mode": self._mode,
            "embed_model": EMBED_MODEL if self._mode == "ollama" else None,
        }


def main() -> int:
    """CLI: python juice_shop_rag.py "query text" [k]"""
    import sys
    q = sys.argv[1] if len(sys.argv) > 1 else "SQL injection on login"
    k = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    rag = JuiceShopRAG()
    rag.build()
    print(f"RAG mode: {rag._mode}, corpus: {len(rag.writeups)}\n")
    print(f"Query: {q!r}\nTop-{k}:")
    for hit in rag.query(q, k=k):
        print(f"  [{hit['score']:.3f}] {hit['key']} — {hit['name']} "
              f"({hit['category']}, {hit['difficulty']}*)")
        print(f"     sol: {hit['solution'][:120]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
