"""
Timing utilities for tracking active and idle time in SKYNET.

This module provides functions for measuring:
- Active time: When the LLM is processing or tools are executing
- Idle time: When waiting for user input
"""

import threading
import time

# Global timing variables for tracking active and idle time
_active_timer_start = None
_active_time_total = 0.0
_idle_timer_start = None
_idle_time_total = 0.0
_timing_lock = threading.Lock()


def start_active_timer():
    """
    Start measuring active time (when LLM is processing or tool is executing).
    Pauses the idle timer if it's running.
    """
    global _active_timer_start, _idle_timer_start, _idle_time_total

    with _timing_lock:
        # If idle timer is running, pause it and accumulate time
        if _idle_timer_start is not None:
            idle_duration = time.time() - _idle_timer_start
            _idle_time_total += idle_duration
            _idle_timer_start = None

        # Start active timer if not already running
        if _active_timer_start is None:
            _active_timer_start = time.time()


def stop_active_timer():
    """
    Stop measuring active time and accumulate the total.
    Restarts the idle timer.
    """
    global _active_timer_start, _active_time_total, _idle_timer_start

    with _timing_lock:
        # If active timer is running, pause it and accumulate time
        if _active_timer_start is not None:
            active_duration = time.time() - _active_timer_start
            _active_time_total += active_duration
            _active_timer_start = None

        # Start idle timer if not already running
        if _idle_timer_start is None:
            _idle_timer_start = time.time()


def start_idle_timer():
    """
    Start measuring idle time (when waiting for user input).
    Pauses the active timer if it's running.
    """
    global _idle_timer_start, _active_timer_start, _active_time_total

    with _timing_lock:
        # If active timer is running, pause it and accumulate time
        if _active_timer_start is not None:
            active_duration = time.time() - _active_timer_start
            _active_time_total += active_duration
            _active_timer_start = None

        # Start idle timer if not already running
        if _idle_timer_start is None:
            _idle_timer_start = time.time()


def stop_idle_timer():
    """
    Stop measuring idle time and accumulate the total.
    Restarts the active timer.
    """
    global _idle_timer_start, _idle_time_total, _active_timer_start

    with _timing_lock:
        # If idle timer is running, pause it and accumulate time
        if _idle_timer_start is not None:
            idle_duration = time.time() - _idle_timer_start
            _idle_time_total += idle_duration
            _idle_timer_start = None

        # Start active timer if not already running
        if _active_timer_start is None:
            _active_timer_start = time.time()


def get_active_time():
    """
    Get the total active time (LLM processing, tool execution).
    Returns a formatted string like "1h 30m 45s" or "45s" or "5m 30s".
    """
    global _active_time_total, _active_timer_start

    with _timing_lock:
        # Calculate total active time including current active period if running
        total_active_seconds = _active_time_total
        if _active_timer_start is not None:
            current_active_duration = time.time() - _active_timer_start
            total_active_seconds += current_active_duration

    # Format the time string
    hours, remainder = divmod(int(total_active_seconds), 3600)
    minutes, seconds = divmod(remainder, 60)

    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    else:
        return f"{seconds}s"


def get_idle_time():
    """
    Get the total idle time (waiting for user input).
    Returns a formatted string like "1h 30m 45s" or "45s" or "5m 30s".
    """
    global _idle_time_total, _idle_timer_start

    with _timing_lock:
        # Calculate total idle time including current idle period if running
        total_idle_seconds = _idle_time_total
        if _idle_timer_start is not None:
            current_idle_duration = time.time() - _idle_timer_start
            total_idle_seconds += current_idle_duration

    # Format the time string
    hours, remainder = divmod(int(total_idle_seconds), 3600)
    minutes, seconds = divmod(remainder, 60)

    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    else:
        return f"{seconds}s"


def get_active_time_seconds():
    """
    Get the total active time in seconds for precise measurement.
    Returns a float representing the total number of seconds.
    """
    global _active_time_total, _active_timer_start

    with _timing_lock:
        # Calculate total active time including current active period if running
        total_active_seconds = _active_time_total
        if _active_timer_start is not None:
            current_active_duration = time.time() - _active_timer_start
            total_active_seconds += current_active_duration

    return total_active_seconds


def get_idle_time_seconds():
    """
    Get the total idle time in seconds for precise measurement.
    Returns a float representing the total number of seconds.
    """
    global _idle_time_total, _idle_timer_start

    with _timing_lock:
        # Calculate total idle time including current idle period if running
        total_idle_seconds = _idle_time_total
        if _idle_timer_start is not None:
            current_idle_duration = time.time() - _idle_timer_start
            total_idle_seconds += current_idle_duration

    return total_idle_seconds


# Initialize idle timer at module load - system starts in idle state
start_idle_timer()
