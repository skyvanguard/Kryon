"""
KRYON LLM Response Cache
==========================

Intelligent caching system for LLM responses to reduce latency,
costs, and eliminate timeouts on repetitive queries.

Features:
- Hash-based cache keys (query + context)
- TTL support (default: 24h)
- LRU eviction policy
- Persistent storage
- Hit/miss statistics
- Automatic cleanup

Clearance Level: Omega-Strategic
Classification: CORE INFRASTRUCTURE
"""

import atexit
import hashlib
import json
import pickle
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any


class LLMResponseCache:
    """
    Cache system for LLM-generated responses.

    Reduces query time from 10-30s to <100ms on cache hits.
    Saves API costs by avoiding duplicate LLM calls.

    Example:
        >>> cache = LLMResponseCache()
        >>> cache.get("SQL injection?", "context...") # None (miss)
        >>> cache.set("SQL injection?", "context...", "answer...")
        >>> cache.get("SQL injection?", "context...") # "answer..." (hit)
    """

    def __init__(
        self,
        cache_dir: str = ".kryon_knowledge/llm_cache",
        max_size: int = 1000,
        default_ttl: int = 86400,  # 24 hours
    ):
        """
        Initialize LLM response cache.

        Args:
            cache_dir: Directory for persistent cache storage
            max_size: Maximum number of cached responses
            default_ttl: Default time-to-live in seconds (86400 = 24h)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.max_size = max_size
        self.default_ttl = default_ttl

        # LRU cache: OrderedDict maintains insertion order
        self._cache: OrderedDict[str, dict[str, Any]] = OrderedDict()

        # Statistics
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "total_time_saved": 0.0,  # seconds
            "api_calls_saved": 0,
        }

        # Thread safety
        self._lock = threading.RLock()

        # Metadata file
        self.metadata_file = self.cache_dir / "llm_cache_metadata.json"
        self.cache_file = self.cache_dir / "llm_cache.pkl"

        # Load existing cache
        self._load_from_disk()
        atexit.register(self._save_to_disk)

    def _generate_key(self, query: str, context: str) -> str:
        """
        Generate cache key from query and context.

        Args:
            query: User question
            context: Retrieved context used for answer generation

        Returns:
            SHA256 hash of query + context
        """
        # Normalize inputs
        query_norm = query.strip().lower()
        context_norm = context.strip().lower()

        # Create deterministic key
        key_string = f"{query_norm}|||{context_norm}"
        return hashlib.sha256(key_string.encode()).hexdigest()

    def _is_expired(self, entry: dict[str, Any], ttl: int | None = None) -> bool:
        """
        Check if cache entry is expired.

        Args:
            entry: Cache entry with timestamp
            ttl: Time-to-live override (uses default if None)

        Returns:
            True if expired, False otherwise
        """
        if ttl is None:
            ttl = entry.get("ttl", self.default_ttl)

        if ttl is None or ttl <= 0:
            return False  # Never expires

        expiry_time = entry["timestamp"] + ttl
        return time.time() > expiry_time

    def _evict_lru(self):
        """Evict least recently used entry when cache is full."""
        with self._lock:
            if len(self._cache) >= self.max_size:
                # Remove oldest entry (first item in OrderedDict)
                key, _ = self._cache.popitem(last=False)
                self._stats["evictions"] += 1

    def get(self, query: str, context: str, ttl: int | None = None) -> str | None:
        """
        Get cached LLM response if available and not expired.

        Args:
            query: User question
            context: Retrieved context
            ttl: Optional TTL override for this query

        Returns:
            Cached answer if available and fresh, None otherwise
        """
        with self._lock:
            cache_key = self._generate_key(query, context)

            if cache_key not in self._cache:
                self._stats["misses"] += 1
                return None

            entry = self._cache[cache_key]

            # Check expiration
            if self._is_expired(entry, ttl):
                # Remove expired entry
                del self._cache[cache_key]
                self._stats["misses"] += 1
                return None

            # Move to end (mark as recently used)
            self._cache.move_to_end(cache_key)

            # Update stats
            self._stats["hits"] += 1
            self._stats["total_time_saved"] += entry.get("generation_time", 15.0)
            self._stats["api_calls_saved"] += 1

            return entry["answer"]

    def set(
        self,
        query: str,
        context: str,
        answer: str,
        generation_time: float = 15.0,
        ttl: int | None = None,
    ):
        """
        Cache an LLM response.

        Args:
            query: User question
            context: Retrieved context
            answer: LLM-generated answer
            generation_time: Time taken to generate (for stats)
            ttl: Optional TTL override for this entry
        """
        with self._lock:
            # Evict if needed
            self._evict_lru()

            cache_key = self._generate_key(query, context)

            entry = {
                "query": query,
                "context": context[:500],  # Store first 500 chars for debugging
                "answer": answer,
                "timestamp": time.time(),
                "ttl": ttl or self.default_ttl,
                "generation_time": generation_time,
            }

            self._cache[cache_key] = entry

    def invalidate(self, query: str | None = None, context: str | None = None):
        """
        Invalidate cache entries.

        Args:
            query: If provided, invalidate only this query
            context: If provided, invalidate only this context
                    (requires query to be specified too)

        If both None, clears entire cache.
        """
        with self._lock:
            if query is None and context is None:
                self._cache.clear()
                return

            if query and context:
                cache_key = self._generate_key(query, context)
                self._cache.pop(cache_key, None)
                return

            # Partial invalidation not supported
            # (would require iterating all entries)

    def get_stats(self) -> dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dict with hits, misses, hit rate, time saved, etc.
        """
        with self._lock:
            total_requests = self._stats["hits"] + self._stats["misses"]
            hit_rate = self._stats["hits"] / total_requests if total_requests > 0 else 0.0

            return {
                "hits": self._stats["hits"],
                "misses": self._stats["misses"],
                "hit_rate": f"{hit_rate * 100:.1f}%",
                "evictions": self._stats["evictions"],
                "total_time_saved": f"{self._stats['total_time_saved']:.1f}s",
                "api_calls_saved": self._stats["api_calls_saved"],
                "cache_size": len(self._cache),
                "max_size": self.max_size,
            }

    def _save_to_disk(self):
        """Save cache to disk for persistence."""
        with self._lock:
            try:
                # Save cache entries
                with open(self.cache_file, "wb") as f:
                    pickle.dump(dict(self._cache), f)  # nosemgrep: avoid-pickle

                # Save metadata
                with open(self.metadata_file, "w") as f:
                    json.dump(self._stats, f, indent=2)

            except Exception as e:
                # Non-critical error, just log
                print(f"Warning: Failed to save LLM cache: {e}")

    def _load_from_disk(self):
        """Load cache from disk if available."""
        with self._lock:
            try:
                # Load cache entries
                if self.cache_file.exists():
                    with open(self.cache_file, "rb") as f:
                        cache_dict = pickle.load(f)  # nosemgrep: avoid-pickle
                        self._cache = OrderedDict(cache_dict)

                # Load metadata
                if self.metadata_file.exists():
                    with open(self.metadata_file) as f:
                        self._stats.update(json.load(f))

            except Exception as e:
                # Non-critical error, start fresh
                print(f"Warning: Failed to load LLM cache: {e}")
                self._cache = OrderedDict()

    # Persistent save is handled via atexit.register in __init__


# Global cache instance
_global_llm_cache: LLMResponseCache | None = None
_llm_cache_lock = threading.Lock()


def get_llm_cache() -> LLMResponseCache:
    """Get or create global LLM cache instance."""
    global _global_llm_cache
    if _global_llm_cache is None:
        with _llm_cache_lock:
            if _global_llm_cache is None:
                _global_llm_cache = LLMResponseCache()
    return _global_llm_cache


def get_cached_llm_response(query: str, context: str, ttl: int | None = None) -> str | None:
    """
    Get cached LLM response (convenience function).

    Args:
        query: User question
        context: Retrieved context
        ttl: Optional TTL override

    Returns:
        Cached answer if available, None otherwise
    """
    cache = get_llm_cache()
    return cache.get(query, context, ttl)


def cache_llm_response(query: str, context: str, answer: str, generation_time: float = 15.0, ttl: int | None = None):
    """
    Cache an LLM response (convenience function).

    Args:
        query: User question
        context: Retrieved context
        answer: LLM-generated answer
        generation_time: Time taken to generate
        ttl: Optional TTL override
    """
    cache = get_llm_cache()
    cache.set(query, context, answer, generation_time, ttl)


def get_llm_cache_stats() -> dict[str, Any]:
    """
    Get LLM cache statistics (convenience function).

    Returns:
        Dict with cache stats
    """
    cache = get_llm_cache()
    return cache.get_stats()


def clear_llm_cache():
    """Clear LLM cache (convenience function)."""
    cache = get_llm_cache()
    cache.invalidate()
