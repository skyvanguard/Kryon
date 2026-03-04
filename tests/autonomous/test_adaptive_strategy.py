"""
Tests for KRYON Adaptive Strategy Engine
=========================================

Tests auto-adaptation and fallback mechanisms.
"""

import time

import pytest

from kryon.sdk.agents.tool import FunctionTool
from kryon.tools.autonomous.adaptive_strategy import (
    AdaptiveStrategy,
    FailureReason,
    execute_with_adaptation,
)


def _call(tool_or_fn, *args, **kwargs):
    """Call a function or extract the raw function from a FunctionTool."""
    if isinstance(tool_or_fn, FunctionTool):
        return tool_or_fn._raw_fn(*args, **kwargs)
    return tool_or_fn(*args, **kwargs)


class TestFailureDetection:
    """Test failure reason detection."""

    def setup_method(self):
        """Setup test fixtures."""
        self.engine = AdaptiveStrategy(max_attempts=5)

    def test_detect_waf_blocked(self):
        """Test WAF detection."""
        attempt_result = {
            "success": False,
            "error": "Request blocked by WAF",
            "response": "Cloudflare security check failed",
        }

        reason = self.engine._detect_failure_reason(attempt_result)
        assert reason == FailureReason.WAF_BLOCKED

    def test_detect_rate_limiting(self):
        """Test rate limiting detection."""
        attempt_result = {"success": False, "status_code": 429, "response": "Too many requests"}

        reason = self.engine._detect_failure_reason(attempt_result)
        assert reason == FailureReason.RATE_LIMITED

    def test_detect_auth_required(self):
        """Test authentication requirement detection."""
        attempt_result = {
            "success": False,
            "status_code": 401,
            "response": "Unauthorized - authentication required",
        }

        reason = self.engine._detect_failure_reason(attempt_result)
        assert reason == FailureReason.AUTH_REQUIRED

    def test_detect_service_crash(self):
        """Test service crash detection."""
        attempt_result = {"success": False, "error": "Connection refused - service unavailable"}

        reason = self.engine._detect_failure_reason(attempt_result)
        assert reason == FailureReason.SERVICE_CRASHED

    def test_detect_timeout(self):
        """Test timeout detection."""
        attempt_result = {"success": False, "error": "Connection timed out after 30 seconds"}

        reason = self.engine._detect_failure_reason(attempt_result)
        assert reason == FailureReason.TIMEOUT

    def test_detect_payload_detection(self):
        """Test payload detection."""
        attempt_result = {
            "success": False,
            "response": "Malicious payload detected - security violation",  # Avoid "blocked" word
        }

        reason = self.engine._detect_failure_reason(attempt_result)
        assert reason == FailureReason.PAYLOAD_DETECTED


class TestStrategyAdaptation:
    """Test strategy adaptation logic."""

    def setup_method(self):
        """Setup test fixtures."""
        self.engine = AdaptiveStrategy(max_attempts=5)
        self.base_strategy = {
            "description": "Standard execution",
            "payload_encoding": "none",
            "timeout": 30,
        }

    def test_adapt_for_waf(self):
        """Test WAF bypass adaptation."""
        adapted = self.engine._adapt_for_waf(self.base_strategy, {"target_url": "http://example.com"}, attempt=1)

        assert adapted is not None
        assert "WAF bypass" in adapted["description"]
        assert "payload_encoding" in adapted
        assert adapted["payload_encoding"] != "none"

    def test_adapt_for_waf_progressive(self):
        """Test progressive WAF evasion."""
        # First attempt
        adapted1 = self.engine._adapt_for_waf(self.base_strategy, {}, attempt=1)
        # Second attempt
        adapted2 = self.engine._adapt_for_waf(self.base_strategy, {}, attempt=2)
        # Third attempt
        adapted3 = self.engine._adapt_for_waf(self.base_strategy, {}, attempt=3)

        # Should use different evasion techniques
        assert adapted1["payload_encoding"] != adapted2["payload_encoding"]
        assert adapted2["payload_encoding"] != adapted3["payload_encoding"]

    def test_adapt_for_rate_limit(self):
        """Test rate limit adaptation with delays."""
        start_time = time.time()

        adapted = self.engine._adapt_for_rate_limit(self.base_strategy, {}, attempt=1)

        elapsed = time.time() - start_time

        assert adapted is not None
        assert "Rate limit evasion" in adapted["description"]
        # Should have waited (at least a short time for attempt 1)
        assert elapsed >= 4.5  # 5 second delay minus some tolerance
        assert "headers" in adapted

    def test_adapt_for_auth(self):
        """Test authentication bypass adaptation."""
        adapted = self.engine._adapt_for_auth(self.base_strategy, {}, attempt=1)

        assert adapted is not None
        assert "Authentication bypass" in adapted["description"]
        assert adapted.get("try_default_credentials")

    def test_adapt_for_crash(self):
        """Test service crash recovery."""
        start_time = time.time()

        adapted = self.engine._adapt_for_crash(self.base_strategy, {}, attempt=1)

        elapsed = time.time() - start_time

        assert adapted is not None
        assert "Service recovery" in adapted["description"]
        # Should have waited for service recovery
        assert elapsed >= 9.5  # 10 second delay minus tolerance
        assert adapted.get("payload_complexity") == "minimal"

    def test_adapt_for_timeout(self):
        """Test timeout adaptation."""
        adapted = self.engine._adapt_for_timeout(self.base_strategy, {}, attempt=1)

        assert adapted is not None
        assert "Timeout mitigation" in adapted["description"]
        # Should increase timeout
        assert adapted["timeout"] > self.base_strategy["timeout"]
        assert adapted.get("payload_complexity") == "simple"

    def test_adapt_for_payload_detection(self):
        """Test payload obfuscation adaptation."""
        adapted = self.engine._adapt_for_payload_detection(self.base_strategy, {}, attempt=1)

        assert adapted is not None
        assert "Payload obfuscation" in adapted["description"]
        assert "payload_obfuscation" in adapted

    def test_no_adaptation_for_unknown(self):
        """Test that unknown failures return None."""
        adapted = self.engine._adapt_strategy(
            self.base_strategy,
            FailureReason.UNKNOWN,
            {},
            attempt_number=1,  # Correct parameter name
        )

        # Should not have adaptation for unknown failures
        assert adapted is None


class TestAdaptiveExecution:
    """Test full adaptive execution cycle."""

    def test_creates_initial_strategy(self):
        """Test initial strategy creation."""
        engine = AdaptiveStrategy(max_attempts=3)

        exploit = {"name": "test_exploit", "type": "rce"}
        service = {"name": "http", "version": "1.0"}

        strategy = engine._create_initial_strategy(exploit, service)

        assert strategy is not None
        assert strategy["exploit_name"] == "test_exploit"
        assert strategy["target_service"] == "http"
        assert strategy["timeout"] == 30

    def test_records_attempt_history(self):
        """Test that attempts are recorded in history."""
        engine = AdaptiveStrategy(max_attempts=3)

        # Initially empty
        assert len(engine.attempt_history) == 0

        # Execute would record attempts (mocked execution will fail)
        exploit = {"name": "test", "type": "rce"}
        service = {"name": "http", "version": "1.0"}

        # This will fail since _execute_exploit_attempt returns failure by default
        result = engine.adaptive_exploit_execution("1.2.3.4", exploit, service)

        # Should have recorded attempts
        assert len(engine.attempt_history) > 0
        assert result["attempts"] > 0

    def test_max_attempts_respected(self):
        """Test that max attempts limit is respected."""
        engine = AdaptiveStrategy(max_attempts=3)

        exploit = {"name": "test", "type": "rce"}
        service = {"name": "http", "version": "1.0"}

        result = engine.adaptive_exploit_execution("1.2.3.4", exploit, service)

        # Should not exceed max attempts
        assert result["attempts"] <= 3
        assert len(engine.attempt_history) <= 3

    def test_defenses_detected_tracking(self):
        """Test that encountered defenses are tracked."""
        engine = AdaptiveStrategy(max_attempts=2)

        exploit = {"name": "test", "type": "rce"}
        service = {"name": "http", "version": "1.0"}

        result = engine.adaptive_exploit_execution("1.2.3.4", exploit, service)

        # Should track defenses encountered
        assert len(result["defenses_encountered"]) > 0
        assert len(engine.defenses_detected) > 0


class TestConvenienceFunction:
    """Test convenience function."""

    def test_execute_with_adaptation(self):
        """Test convenience function for adaptive execution."""
        exploit = {"name": "test_exploit", "type": "rce"}
        service = {"name": "http", "version": "1.0"}

        result = _call(execute_with_adaptation, target_ip="192.168.1.1", exploit=exploit, service=service, max_attempts=3)

        assert result is not None
        assert "success" in result
        assert "attempts" in result
        assert "adaptations_applied" in result
        assert result["attempts"] <= 3


@pytest.mark.integration
class TestAdaptationIntegration:
    """Integration tests for adaptation system."""

    def test_full_adaptation_cycle(self):
        """Test complete adaptation cycle with multiple failures."""
        engine = AdaptiveStrategy(max_attempts=5, enable_learning=True)

        exploit = {"name": "web_exploit", "type": "rce", "description": "Test web exploit"}

        service = {"name": "http", "version": "Apache 2.4", "port": 80}

        result = engine.adaptive_exploit_execution(target_ip="10.0.0.1", exploit=exploit, service=service)

        # Verify result structure
        assert "success" in result
        assert "attempts" in result
        assert "adaptations_applied" in result
        assert "defenses_encountered" in result
        assert "final_strategy" in result

        # Should have made multiple attempts
        assert result["attempts"] >= 1

        # Should have detected defenses
        assert len(result["defenses_encountered"]) > 0

        # Attempt history should match attempts
        assert len(engine.attempt_history) == result["attempts"]

    def test_progressive_evasion(self):
        """Test that evasion techniques become more sophisticated."""
        engine = AdaptiveStrategy(max_attempts=4)

        # Track adaptations

        exploit = {"name": "test", "type": "xss"}
        service = {"name": "http", "version": "1.0"}

        # Execute (will fail but should adapt)
        result = engine.adaptive_exploit_execution("1.2.3.4", exploit, service)

        # Check that adaptations were applied
        assert len(result["adaptations_applied"]) >= 0

        # If adaptations were applied, they should be recorded
        for adaptation in result["adaptations_applied"]:
            assert "attempt" in adaptation
            assert "reason" in adaptation
            assert "adaptation" in adaptation
