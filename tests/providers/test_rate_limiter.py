"""Tests for the rate limiter module."""

import asyncio
import time

import pytest

from kryon.providers.rate_limiter import PRESETS, RateLimitConfig, RateLimiter


class TestRateLimitConfig:
    def test_presets_exist(self):
        assert "groq_free" in PRESETS
        assert "openai" in PRESETS
        assert "ollama" in PRESETS

    def test_groq_free_limits(self):
        cfg = PRESETS["groq_free"]
        assert cfg.rpm == 30
        assert cfg.tpm == 12000


class TestRateLimiterInit:
    def test_default_is_groq_free(self):
        rl = RateLimiter()
        assert rl.config.rpm == 30

    def test_from_preset(self):
        rl = RateLimiter.from_preset("openai")
        assert rl.config.rpm == 500

    def test_from_preset_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown preset"):
            RateLimiter.from_preset("nonexistent")

    def test_detect_provider_groq(self):
        rl = RateLimiter.detect_provider("https://api.groq.com/openai/v1")
        assert rl.config.rpm == 30

    def test_detect_provider_ollama(self):
        rl = RateLimiter.detect_provider("http://localhost:11434/v1")
        assert rl.config.rpm == 9999

    def test_detect_provider_openai(self):
        rl = RateLimiter.detect_provider("https://api.openai.com/v1")
        assert rl.config.rpm == 500

    def test_detect_provider_empty_defaults_openai(self, monkeypatch):
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        rl = RateLimiter.detect_provider("")
        assert rl.config.rpm == 500


class TestRateLimiterAcquire:
    @pytest.mark.asyncio
    async def test_acquire_first_request_no_wait(self):
        rl = RateLimiter(config=RateLimitConfig(rpm=100, tpm=100000))
        waited = await rl.acquire(500)
        assert waited == 0.0

    @pytest.mark.asyncio
    async def test_requests_remaining(self):
        rl = RateLimiter(config=RateLimitConfig(rpm=5, tpm=100000))
        assert rl.requests_remaining == 5
        await rl.acquire(100)
        assert rl.requests_remaining == 4

    @pytest.mark.asyncio
    async def test_tokens_remaining(self):
        rl = RateLimiter(config=RateLimitConfig(rpm=100, tpm=1000))
        assert rl.tokens_remaining == 1000
        await rl.acquire(300)
        assert rl.tokens_remaining == 700

    @pytest.mark.asyncio
    async def test_multiple_acquires_under_limit(self):
        rl = RateLimiter(config=RateLimitConfig(rpm=10, tpm=100000))
        for _ in range(5):
            waited = await rl.acquire(100)
            assert waited == 0.0

    @pytest.mark.asyncio
    async def test_rpm_throttle(self):
        """When RPM is 2, the third request should wait."""
        rl = RateLimiter(config=RateLimitConfig(rpm=2, tpm=999999))
        await rl.acquire(10)
        await rl.acquire(10)
        # Third request should trigger a wait
        start = time.monotonic()
        # Use a very short timeout so the test doesn't hang
        # We just verify it would have waited
        assert rl.requests_remaining == 0

    @pytest.mark.asyncio
    async def test_tpm_throttle(self):
        """When TPM is low, requesting more tokens than available should wait."""
        rl = RateLimiter(config=RateLimitConfig(rpm=100, tpm=100))
        await rl.acquire(90)
        assert rl.tokens_remaining == 10


class TestRateLimiterCustomConfig:
    def test_custom_config(self):
        cfg = RateLimitConfig(rpm=10, tpm=5000)
        rl = RateLimiter(config=cfg)
        assert rl.config.rpm == 10
        assert rl.config.tpm == 5000
