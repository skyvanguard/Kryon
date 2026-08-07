"""Active target-health monitoring — the XBOW "back off if the target is
stressed" safety layer.

Static throttling (nmap -T2, nuclei rate-limit) caps intensity blindly. This
reacts to the target's LIVE behavior: a burst of 5xx/429/errors or climbing
latency means slow down or stop, so the test never degrades production.

Pure + testable: feed it observations via :meth:`record`, ask for an
:meth:`assessment`. The caller decides how to honor the recommended backoff.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from statistics import median

HEALTHY = "healthy"
DEGRADED = "degraded"
UNHEALTHY = "unhealthy"


@dataclass(frozen=True)
class HealthAssessment:
    state: str  # healthy | degraded | unhealthy
    backoff_seconds: float
    reason: str
    error_rate: float
    samples: int


class TargetHealthMonitor:
    """Sliding-window health monitor for a single target under test."""

    def __init__(
        self,
        *,
        window: int = 20,
        min_samples: int = 5,
        error_rate_degraded: float = 0.20,
        error_rate_unhealthy: float = 0.50,
        latency_factor: float = 3.0,
        degraded_backoff_s: float = 15.0,
        unhealthy_backoff_s: float = 60.0,
    ) -> None:
        self._errors: deque[int] = deque(maxlen=window)
        self._durations: deque[float] = deque(maxlen=window)
        self._baseline_ms: float | None = None
        self._min_samples = min_samples
        self._err_degraded = error_rate_degraded
        self._err_unhealthy = error_rate_unhealthy
        self._latency_factor = latency_factor
        self._degraded_backoff = degraded_backoff_s
        self._unhealthy_backoff = unhealthy_backoff_s

    @staticmethod
    def _is_error(status_code: int | None, error: bool) -> bool:
        # A connection error, a 5xx, or a 429 (rate-limited) counts as stress.
        return error or status_code is None or status_code >= 500 or status_code == 429

    def record(self, *, status_code: int | None = None, duration_ms: float = 0.0, error: bool = False) -> None:
        """Record one probe/request outcome against the target."""
        is_err = self._is_error(status_code, error)
        self._errors.append(1 if is_err else 0)
        if not is_err and duration_ms > 0:
            self._durations.append(duration_ms)
            # Establish the baseline from the first healthy window, then keep
            # the lowest median seen (the target's "fresh" latency).
            if len(self._durations) >= self._min_samples:
                med = median(self._durations)
                if self._baseline_ms is None or med < self._baseline_ms:
                    self._baseline_ms = med

    def assessment(self) -> HealthAssessment:
        n = len(self._errors)
        if n < self._min_samples:
            return HealthAssessment(HEALTHY, 0.0, "warming up", 0.0, n)

        err_rate = sum(self._errors) / n

        latency_ratio = 1.0
        if self._baseline_ms and self._durations:
            latency_ratio = median(self._durations) / self._baseline_ms

        if err_rate >= self._err_unhealthy or latency_ratio >= self._latency_factor * 2:
            return HealthAssessment(
                UNHEALTHY,
                self._unhealthy_backoff,
                f"error_rate={err_rate:.0%}, latency x{latency_ratio:.1f}",
                err_rate,
                n,
            )
        if err_rate >= self._err_degraded or latency_ratio >= self._latency_factor:
            return HealthAssessment(
                DEGRADED,
                self._degraded_backoff,
                f"error_rate={err_rate:.0%}, latency x{latency_ratio:.1f}",
                err_rate,
                n,
            )
        return HealthAssessment(HEALTHY, 0.0, "nominal", err_rate, n)

    def should_back_off(self) -> bool:
        return self.assessment().state != HEALTHY
