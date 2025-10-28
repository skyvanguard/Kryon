"""
Logging and tracing module for Skynet framework.
Provides detailed execution visibility and debugging capabilities.
"""
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import json
from enum import Enum


class LogLevel(Enum):
    """Log levels for Skynet."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ColoredFormatter(logging.Formatter):
    """Colored formatter for terminal output."""

    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'        # Reset
    }

    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{log_color}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)


class SkynetLogger:
    """Main logger for Skynet framework with tracing capabilities."""

    def __init__(self, name: str = "skynet", log_file: Optional[Path] = None, level: str = "INFO"):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        self.traces: list = []
        self.current_session: Optional[str] = None

        # Clear existing handlers
        self.logger.handlers.clear()

        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, level.upper()))
        console_formatter = ColoredFormatter(
            '%(asctime)s | %(levelname)s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

        # File handler if specified
        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)  # File gets all logs
            file_formatter = logging.Formatter(
                '%(asctime)s | %(levelname)s | %(name)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)

    def start_session(self, session_id: Optional[str] = None) -> str:
        """Start a new logging session."""
        if session_id is None:
            session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_session = session_id
        self.logger.info(f"Started session: {session_id}")
        return session_id

    def end_session(self):
        """End the current logging session."""
        if self.current_session:
            self.logger.info(f"Ended session: {self.current_session}")
            self.current_session = None

    def trace(self, event_type: str, data: Dict[str, Any], agent_name: Optional[str] = None):
        """Record a trace event for detailed execution tracking."""
        trace_entry = {
            "timestamp": datetime.now().isoformat(),
            "session_id": self.current_session,
            "event_type": event_type,
            "agent": agent_name,
            "data": data
        }
        self.traces.append(trace_entry)

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f"TRACE | {event_type} | {agent_name or 'system'} | {json.dumps(data, default=str)}")

    def log_agent_action(self, agent_name: str, action: str, details: Dict[str, Any]):
        """Log an agent action."""
        self.trace("agent_action", {"action": action, **details}, agent_name)
        self.logger.info(f"[{agent_name}] {action}")

    def log_tool_use(self, agent_name: str, tool_name: str, input_data: Any, output_data: Any):
        """Log tool usage by an agent."""
        self.trace("tool_use", {
            "tool": tool_name,
            "input": str(input_data)[:500],  # Truncate for readability
            "output": str(output_data)[:500]
        }, agent_name)
        self.logger.info(f"[{agent_name}] Used tool: {tool_name}")

    def log_error(self, agent_name: str, error: Exception, context: Optional[Dict] = None):
        """Log an error with context."""
        error_data = {
            "error_type": type(error).__name__,
            "error_message": str(error),
            "context": context or {}
        }
        self.trace("error", error_data, agent_name)
        self.logger.error(f"[{agent_name}] Error: {error}", exc_info=True)

    def export_traces(self, output_path: Path):
        """Export traces to a JSON file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(self.traces, f, indent=2, default=str)
        self.logger.info(f"Exported {len(self.traces)} traces to {output_path}")

    def clear_traces(self):
        """Clear all stored traces."""
        self.traces.clear()
        self.logger.debug("Cleared all traces")

    def debug(self, message: str):
        """Log a debug message."""
        self.logger.debug(message)

    def info(self, message: str):
        """Log an info message."""
        self.logger.info(message)

    def warning(self, message: str):
        """Log a warning message."""
        self.logger.warning(message)

    def error(self, message: str):
        """Log an error message."""
        self.logger.error(message)

    def critical(self, message: str):
        """Log a critical message."""
        self.logger.critical(message)


# Global logger instance
_logger: Optional[SkynetLogger] = None


def get_logger() -> SkynetLogger:
    """Get or create the global logger instance."""
    global _logger
    if _logger is None:
        from .config import get_config
        config = get_config()
        _logger = SkynetLogger(
            name="skynet",
            log_file=config.log_file,
            level=config.log_level
        )
    return _logger


def set_logger(logger: SkynetLogger):
    """Set the global logger instance."""
    global _logger
    _logger = logger
