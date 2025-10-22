"""
Scan Result Cache

Specialized caching for security scan results with similarity detection,
deduplication, and intelligent result merging.
"""

import json
import hashlib
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import re

from .cache_manager import CacheManager, get_cache


class ScanCache:
    """
    Specialized cache for security scan results.

    Features:
    - Scan result deduplication
    - Similarity detection (same target, similar parameters)
    - Result merging from multiple scans
    - Scan history tracking
    - Target-based indexing
    """

    def __init__(self, cache_manager: Optional[CacheManager] = None):
        """
        Initialize scan cache.

        Args:
            cache_manager: Underlying cache manager (uses global if None)
        """
        self.cache = cache_manager or get_cache()
        self.scan_index_key = "skynet:scan_index"

    def _normalize_target(self, target: str) -> str:
        """
        Normalize target for consistent caching.

        Args:
            target: Target URL/IP/domain

        Returns:
            Normalized target string
        """
        # Remove protocol
        target = re.sub(r'^https?://', '', target)

        # Remove trailing slashes
        target = target.rstrip('/')

        # Lowercase domain/hostname
        if '/' in target:
            parts = target.split('/', 1)
            target = parts[0].lower() + '/' + parts[1]
        else:
            target = target.lower()

        return target

    def _generate_scan_key(
        self,
        tool: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate unique key for scan result."""
        normalized_target = self._normalize_target(target)

        key_data = {
            "tool": tool,
            "target": normalized_target,
            "params": params or {}
        }

        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_string.encode()).hexdigest()

    def _get_scan_index(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get scan index (target -> scan metadata)."""
        index = self.cache.get(self.scan_index_key)
        if index is None:
            return {}
        return index

    def _update_scan_index(
        self,
        target: str,
        tool: str,
        scan_key: str,
        params: Optional[Dict[str, Any]] = None
    ):
        """Update scan index with new scan metadata."""
        index = self._get_scan_index()
        normalized_target = self._normalize_target(target)

        if normalized_target not in index:
            index[normalized_target] = []

        # Add scan metadata
        scan_metadata = {
            "tool": tool,
            "scan_key": scan_key,
            "timestamp": time.time(),
            "params": params or {}
        }

        index[normalized_target].append(scan_metadata)

        # Save updated index (no expiration for index)
        self.cache.set(self.scan_index_key, index, ttl=None)

    def cache_scan(
        self,
        tool: str,
        target: str,
        result: Any,
        params: Optional[Dict[str, Any]] = None,
        ttl: int = 7200  # 2 hours default for scan results
    ) -> str:
        """
        Cache scan result.

        Args:
            tool: Tool name (nmap, nuclei, etc.)
            target: Scan target
            result: Scan result to cache
            params: Scan parameters
            ttl: Time-to-live in seconds

        Returns:
            Cache key
        """
        scan_key = self._generate_scan_key(tool, target, params)

        # Wrap result with metadata
        cached_data = {
            "tool": tool,
            "target": target,
            "result": result,
            "params": params or {},
            "cached_at": time.time(),
            "cached_at_readable": datetime.now().isoformat()
        }

        # Cache result
        self.cache.set(scan_key, cached_data, ttl=ttl)

        # Update index
        self._update_scan_index(target, tool, scan_key, params)

        return scan_key

    def get_scan(
        self,
        tool: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Optional[Any]:
        """
        Get cached scan result.

        Args:
            tool: Tool name
            target: Scan target
            params: Scan parameters

        Returns:
            Cached result or None
        """
        scan_key = self._generate_scan_key(tool, target, params)
        cached_data = self.cache.get(scan_key)

        if cached_data is not None:
            return cached_data["result"]

        return None

    def get_scan_metadata(
        self,
        tool: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get scan metadata (timestamp, params, etc.).

        Args:
            tool: Tool name
            target: Scan target
            params: Scan parameters

        Returns:
            Scan metadata or None
        """
        scan_key = self._generate_scan_key(tool, target, params)
        cached_data = self.cache.get(scan_key)

        if cached_data is not None:
            return {
                "tool": cached_data["tool"],
                "target": cached_data["target"],
                "params": cached_data["params"],
                "cached_at": cached_data["cached_at"],
                "cached_at_readable": cached_data["cached_at_readable"],
                "age_seconds": time.time() - cached_data["cached_at"]
            }

        return None

    def find_similar_scans(
        self,
        target: str,
        tool: Optional[str] = None,
        max_age: Optional[int] = None  # seconds
    ) -> List[Dict[str, Any]]:
        """
        Find similar scans for target.

        Args:
            target: Target to search for
            tool: Filter by specific tool (optional)
            max_age: Maximum age of results in seconds (optional)

        Returns:
            List of similar scan metadata
        """
        index = self._get_scan_index()
        normalized_target = self._normalize_target(target)

        if normalized_target not in index:
            return []

        similar_scans = []
        current_time = time.time()

        for scan_meta in index[normalized_target]:
            # Filter by tool if specified
            if tool and scan_meta["tool"] != tool:
                continue

            # Filter by age if specified
            if max_age:
                age = current_time - scan_meta["timestamp"]
                if age > max_age:
                    continue

            # Get full scan data
            cached_data = self.cache.get(scan_meta["scan_key"])
            if cached_data:
                similar_scans.append({
                    "tool": scan_meta["tool"],
                    "timestamp": scan_meta["timestamp"],
                    "age_seconds": current_time - scan_meta["timestamp"],
                    "params": scan_meta["params"],
                    "scan_key": scan_meta["scan_key"]
                })

        # Sort by timestamp (newest first)
        similar_scans.sort(key=lambda x: x["timestamp"], reverse=True)

        return similar_scans

    def get_target_history(self, target: str) -> List[Dict[str, Any]]:
        """
        Get complete scan history for target.

        Args:
            target: Target to get history for

        Returns:
            List of all scans performed on target
        """
        return self.find_similar_scans(target)

    def delete_target_scans(self, target: str) -> int:
        """
        Delete all cached scans for target.

        Args:
            target: Target to delete scans for

        Returns:
            Number of scans deleted
        """
        index = self._get_scan_index()
        normalized_target = self._normalize_target(target)

        if normalized_target not in index:
            return 0

        # Delete all scan results
        count = 0
        for scan_meta in index[normalized_target]:
            if self.cache.delete(scan_meta["scan_key"]):
                count += 1

        # Remove from index
        del index[normalized_target]
        self.cache.set(self.scan_index_key, index, ttl=None)

        return count

    def get_all_targets(self) -> List[str]:
        """Get list of all cached targets."""
        index = self._get_scan_index()
        return list(index.keys())

    def get_cache_summary(self) -> Dict[str, Any]:
        """
        Get summary of cached scans.

        Returns:
            Summary with target count, tool distribution, etc.
        """
        index = self._get_scan_index()

        total_targets = len(index)
        total_scans = sum(len(scans) for scans in index.values())

        # Tool distribution
        tool_counts = {}
        for scans in index.values():
            for scan in scans:
                tool = scan["tool"]
                tool_counts[tool] = tool_counts.get(tool, 0) + 1

        # Recent activity (last 24 hours)
        cutoff_time = time.time() - 86400  # 24 hours
        recent_scans = 0
        for scans in index.values():
            for scan in scans:
                if scan["timestamp"] > cutoff_time:
                    recent_scans += 1

        return {
            "total_targets": total_targets,
            "total_scans": total_scans,
            "tool_distribution": tool_counts,
            "recent_scans_24h": recent_scans,
            "targets": list(index.keys())[:10]  # First 10 targets
        }


# Global scan cache instance
_global_scan_cache: Optional[ScanCache] = None


def get_scan_cache() -> ScanCache:
    """Get or create global scan cache instance."""
    global _global_scan_cache
    if _global_scan_cache is None:
        _global_scan_cache = ScanCache()
    return _global_scan_cache


def cache_scan_result(
    tool: str,
    target: str,
    result: Any,
    params: Optional[Dict[str, Any]] = None,
    ttl: int = 7200
) -> str:
    """
    Cache scan result (convenience function).

    Args:
        tool: Tool name
        target: Scan target
        result: Result to cache
        params: Scan parameters
        ttl: Time-to-live in seconds

    Returns:
        Cache key
    """
    scan_cache = get_scan_cache()
    return scan_cache.cache_scan(tool, target, result, params, ttl)


def find_similar_scans(
    target: str,
    tool: Optional[str] = None,
    max_age: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Find similar scans (convenience function).

    Args:
        target: Target to search for
        tool: Filter by tool (optional)
        max_age: Max age in seconds (optional)

    Returns:
        List of similar scans
    """
    scan_cache = get_scan_cache()
    return scan_cache.find_similar_scans(target, tool, max_age)


def get_cached_scan(
    tool: str,
    target: str,
    params: Optional[Dict[str, Any]] = None
) -> Optional[Any]:
    """
    Get cached scan result (convenience function).

    Args:
        tool: Tool name
        target: Scan target
        params: Scan parameters

    Returns:
        Cached result or None
    """
    scan_cache = get_scan_cache()
    return scan_cache.get_scan(tool, target, params)
