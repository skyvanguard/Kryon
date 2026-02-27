"""
Smart Cache Manager

LRU-based cache with TTL support, persistent storage, and automatic cleanup.
Optimizes KRYON operations by caching expensive scan results and preventing duplicates.
"""

import hashlib
import json
import logging
import threading
import time
import zlib
from collections import OrderedDict
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class CacheManager:
    """
    Thread-safe LRU cache with TTL and persistent storage.

    Features:
    - LRU eviction policy
    - Time-to-live (TTL) support
    - Persistent storage to disk
    - Thread-safe operations
    - Hit/miss statistics
    - Automatic cleanup of expired entries
    """

    def __init__(
        self,
        max_size: int = 1000,
        default_ttl: int = 3600,  # 1 hour default
        cache_dir: str = ".kryon_cache",
        enable_persistence: bool = True,
    ):
        """
        Initialize cache manager.

        Args:
            max_size: Maximum number of cache entries
            default_ttl: Default time-to-live in seconds
            cache_dir: Directory for persistent cache storage
            enable_persistence: Enable disk persistence
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache_dir = Path(cache_dir)
        self.enable_persistence = enable_persistence

        # LRU cache: OrderedDict maintains insertion order
        self._cache: OrderedDict[str, dict[str, Any]] = OrderedDict()

        # Statistics
        self._stats = {"hits": 0, "misses": 0, "evictions": 0, "expirations": 0}

        # Thread safety
        self._lock = threading.RLock()

        # Create cache directory
        if self.enable_persistence:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Load persistent cache
        self._load_from_disk()

    def _generate_key(self, *args, **kwargs) -> str:
        """Generate cache key from function arguments."""
        key_data = {"args": args, "kwargs": kwargs}
        key_string = json.dumps(key_data, sort_keys=True, default=str)
        return hashlib.sha256(key_string.encode()).hexdigest()

    def _is_expired(self, entry: dict[str, Any]) -> bool:
        """Check if cache entry is expired."""
        if entry.get("ttl") is None:
            return False
        expiry_time = entry["timestamp"] + entry["ttl"]
        return time.time() > expiry_time

    def _evict_lru(self):
        """Evict least recently used entry."""
        with self._lock:
            if len(self._cache) >= self.max_size:
                # Remove oldest entry (first item in OrderedDict)
                key, _ = self._cache.popitem(last=False)
                self._stats["evictions"] += 1
                self._remove_from_disk(key)

    def _remove_expired(self):
        """Remove all expired entries."""
        with self._lock:
            expired_keys = []
            for key, entry in self._cache.items():
                if self._is_expired(entry):
                    expired_keys.append(key)

            for key in expired_keys:
                del self._cache[key]
                self._stats["expirations"] += 1
                self._remove_from_disk(key)

    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        with self._lock:
            if key not in self._cache:
                self._stats["misses"] += 1
                return None

            entry = self._cache[key]

            # Check expiration
            if self._is_expired(entry):
                del self._cache[key]
                self._stats["expirations"] += 1
                self._stats["misses"] += 1
                self._remove_from_disk(key)
                return None

            # Move to end (mark as recently used)
            self._cache.move_to_end(key)
            self._stats["hits"] += 1

            return entry["value"]

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """
        Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (None for no expiration)
        """
        with self._lock:
            # Evict LRU if at capacity
            if key not in self._cache:
                self._evict_lru()

            # Create cache entry
            entry = {
                "value": value,
                "timestamp": time.time(),
                "ttl": ttl if ttl is not None else self.default_ttl,
            }

            # Store in cache (will be moved to end automatically)
            self._cache[key] = entry
            self._cache.move_to_end(key)

            # Persist to disk
            self._save_to_disk(key, entry)

    def delete(self, key: str) -> bool:
        """
        Delete entry from cache.

        Args:
            key: Cache key

        Returns:
            True if deleted, False if not found
        """
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                self._remove_from_disk(key)
                return True
            return False

    def clear(self):
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()
            self._stats = {"hits": 0, "misses": 0, "evictions": 0, "expirations": 0}

            # Clear disk cache
            if self.enable_persistence and self.cache_dir.exists():
                for file in self.cache_dir.glob("*.cache"):
                    file.unlink()

    def get_stats(self) -> dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with hit/miss/eviction counts and ratios
        """
        with self._lock:
            total_requests = self._stats["hits"] + self._stats["misses"]
            hit_ratio = self._stats["hits"] / total_requests if total_requests > 0 else 0

            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self._stats["hits"],
                "misses": self._stats["misses"],
                "evictions": self._stats["evictions"],
                "expirations": self._stats["expirations"],
                "hit_ratio": round(hit_ratio, 3),
                "total_requests": total_requests,
            }

    def cleanup(self):
        """Perform cleanup: remove expired entries."""
        self._remove_expired()

    def _save_to_disk(self, key: str, entry: dict[str, Any]):
        """Save cache entry to disk with compression (JSON format)."""
        if not self.enable_persistence:
            return

        try:
            cache_file = self.cache_dir / f"{key}.cache"
            json_data = json.dumps(entry, default=str).encode("utf-8")
            compressed_data = zlib.compress(json_data, level=6)
            with open(cache_file, "wb") as f:
                f.write(compressed_data)
        except Exception:
            logger.debug("Cache persistence write failed for key %s", key, exc_info=True)

    def _remove_from_disk(self, key: str):
        """Remove cache entry from disk."""
        if not self.enable_persistence:
            return

        try:
            cache_file = self.cache_dir / f"{key}.cache"
            if cache_file.exists():
                cache_file.unlink()
        except Exception:
            pass

    def _load_from_disk(self):
        """Load cache entries from disk with decompression (JSON format)."""
        if not self.enable_persistence or not self.cache_dir.exists():
            return

        try:
            for cache_file in self.cache_dir.glob("*.cache"):
                try:
                    with open(cache_file, "rb") as f:
                        compressed_data = f.read()

                    # Decompress and deserialize as JSON
                    try:
                        json_data = zlib.decompress(compressed_data)
                        entry = json.loads(json_data)
                    except (zlib.error, json.JSONDecodeError):
                        # Old pickle format or corrupted — remove and skip
                        logger.debug("Removing incompatible cache file: %s", cache_file.name)
                        cache_file.unlink(missing_ok=True)
                        continue

                    # Check if expired
                    if not self._is_expired(entry):
                        key = cache_file.stem
                        self._cache[key] = entry
                    else:
                        cache_file.unlink(missing_ok=True)
                except Exception:
                    continue
        except Exception:
            logger.debug("Cache load from disk failed", exc_info=True)


# Global cache instance
_global_cache: Optional[CacheManager] = None
_cache_lock = threading.Lock()


def get_cache() -> CacheManager:
    """Get or create global cache instance."""
    global _global_cache
    if _global_cache is None:
        with _cache_lock:
            if _global_cache is None:
                _global_cache = CacheManager()
    return _global_cache


def clear_cache():
    """Clear global cache."""
    cache = get_cache()
    cache.clear()


def cache_stats() -> dict[str, Any]:
    """Get global cache statistics."""
    cache = get_cache()
    return cache.get_stats()


def cache_result(ttl: Optional[int] = None, key_prefix: str = ""):
    """
    Decorator to cache function results.

    Args:
        ttl: Time-to-live in seconds
        key_prefix: Prefix for cache keys

    Example:
        @cache_result(ttl=3600)
        def expensive_scan(target: str) -> dict:
            # Expensive operation
            return result
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache = get_cache()

            # Generate cache key
            key_data = f"{key_prefix}:{func.__name__}:{args}:{kwargs}"
            key = hashlib.sha256(key_data.encode()).hexdigest()

            # Try to get from cache
            cached_value = cache.get(key)
            if cached_value is not None:
                return cached_value

            # Execute function
            result = func(*args, **kwargs)

            # Cache result
            cache.set(key, result, ttl=ttl)

            return result

        # Add cache management methods to wrapper
        wrapper.cache_key = lambda *args, **kwargs: hashlib.sha256(
            f"{key_prefix}:{func.__name__}:{args}:{kwargs}".encode()
        ).hexdigest()
        wrapper.cache_clear = lambda: get_cache().clear()
        wrapper.cache_stats = lambda: get_cache().get_stats()

        return wrapper

    return decorator


def cache_by_key(cache_key: str, ttl: Optional[int] = None) -> Callable:
    """
    Decorator to cache function results with explicit key.

    Args:
        cache_key: Explicit cache key
        ttl: Time-to-live in seconds

    Example:
        @cache_by_key(cache_key="nmap_scan_192.168.1.1", ttl=7200)
        def scan_network():
            return result
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache = get_cache()

            # Generate full key
            key = hashlib.sha256(cache_key.encode()).hexdigest()

            # Try to get from cache
            cached_value = cache.get(key)
            if cached_value is not None:
                return cached_value

            # Execute function
            result = func(*args, **kwargs)

            # Cache result
            cache.set(key, result, ttl=ttl)

            return result

        return wrapper

    return decorator


class CachedResult:
    """
    Context manager for manual cache operations.

    Example:
        with CachedResult(key="my_scan", ttl=3600) as cache:
            if cache.exists():
                return cache.get()

            result = expensive_operation()
            cache.set(result)
            return result
    """

    def __init__(self, key: str, ttl: Optional[int] = None):
        self.key = hashlib.sha256(key.encode()).hexdigest()
        self.ttl = ttl
        self.cache = get_cache()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def exists(self) -> bool:
        """Check if value exists in cache."""
        return self.cache.get(self.key) is not None

    def get(self) -> Optional[Any]:
        """Get value from cache."""
        return self.cache.get(self.key)

    def set(self, value: Any):
        """Set value in cache."""
        self.cache.set(self.key, value, ttl=self.ttl)

    def delete(self):
        """Delete value from cache."""
        self.cache.delete(self.key)
