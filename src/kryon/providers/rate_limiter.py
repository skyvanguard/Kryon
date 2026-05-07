"""Async rate limiter with sliding window for LLM API providers."""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""

    rpm: int = 30  # requests per minute
    tpm: int = 6000  # tokens per minute


# Pre-configured presets for common providers
PRESETS: dict[str, RateLimitConfig] = {
    "groq_free": RateLimitConfig(rpm=30, tpm=6000),
    "groq_paid": RateLimitConfig(rpm=100, tpm=100000),
    "openai": RateLimitConfig(rpm=500, tpm=90000),
    "ollama": RateLimitConfig(rpm=9999, tpm=999999),
    "deepseek": RateLimitConfig(rpm=500, tpm=200000),
}


@dataclass
class RateLimiter:
    """Async rate limiter using a sliding window approach.

    Tracks both requests-per-minute and tokens-per-minute and waits
    when either limit would be exceeded.
    """

    config: RateLimitConfig = field(default_factory=lambda: PRESETS["groq_free"])
    _request_times: deque = field(default_factory=deque, init=False, repr=False)
    _token_log: deque = field(default_factory=deque, init=False, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    @classmethod
    def from_preset(cls, name: str) -> RateLimiter:
        """Create a RateLimiter from a named preset."""
        if name not in PRESETS:
            raise ValueError(f"Unknown preset '{name}'. Available: {list(PRESETS.keys())}")
        return cls(config=PRESETS[name])

    @classmethod
    def detect_provider(cls, base_url: str | None = None) -> RateLimiter:
        """Auto-detect provider from OPENAI_BASE_URL and return appropriate limiter."""
        import os

        url: str = base_url or os.getenv("OPENAI_BASE_URL", "") or ""
        url_lower = url.lower()

        if "deepseek.com" in url_lower:
            return cls.from_preset("deepseek")
        if "groq.com" in url_lower:
            return cls.from_preset("groq_free")
        if "localhost" in url_lower or "127.0.0.1" in url_lower or "11434" in url_lower:
            return cls.from_preset("ollama")
        if "openai.com" in url_lower or not url:
            return cls.from_preset("openai")

        # Default to conservative limits
        return cls.from_preset("groq_free")

    async def acquire(self, estimated_tokens: int = 500) -> float:
        """Wait until a request can be made without exceeding rate limits.

        Args:
            estimated_tokens: Estimated token count for this request.

        Returns:
            Number of seconds waited (0.0 if no wait was needed).
        """
        total_waited = 0.0

        async with self._lock:
            while True:
                now = time.monotonic()
                window_start = now - 60.0

                # Prune old entries outside the 1-minute window
                while self._request_times and self._request_times[0] < window_start:
                    self._request_times.popleft()
                while self._token_log and self._token_log[0][0] < window_start:
                    self._token_log.popleft()

                # Check RPM
                rpm_ok = len(self._request_times) < self.config.rpm

                # Check TPM
                current_tokens = sum(t[1] for t in self._token_log)
                tpm_ok = (current_tokens + estimated_tokens) <= self.config.tpm

                if rpm_ok and tpm_ok:
                    # Record this request
                    self._request_times.append(now)
                    self._token_log.append((now, estimated_tokens))
                    return total_waited

                # Calculate wait time
                if not rpm_ok and self._request_times:
                    wait_rpm = self._request_times[0] - window_start + 0.1
                else:
                    wait_rpm = 0.0

                if not tpm_ok and self._token_log:
                    wait_tpm = self._token_log[0][0] - window_start + 0.1
                else:
                    wait_tpm = 0.0

                wait_time = max(wait_rpm, wait_tpm, 0.1)

                # Release the lock while waiting so other coroutines can check
                self._lock.release()
                try:
                    await asyncio.sleep(wait_time)
                    total_waited += wait_time
                finally:
                    await self._lock.acquire()

    @property
    def requests_remaining(self) -> int:
        """Approximate requests remaining in the current window."""
        now = time.monotonic()
        window_start = now - 60.0
        count = sum(1 for t in self._request_times if t >= window_start)
        return max(0, self.config.rpm - count)

    @property
    def tokens_remaining(self) -> int:
        """Approximate tokens remaining in the current window."""
        now = time.monotonic()
        window_start = now - 60.0
        used = sum(t[1] for t in self._token_log if t[0] >= window_start)
        return max(0, self.config.tpm - used)
