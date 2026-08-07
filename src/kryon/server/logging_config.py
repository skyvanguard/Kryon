"""Structured logging configuration for KRYON server."""

from __future__ import annotations

import logging
import logging.config
from typing import Any


class RequestIdFilter(logging.Filter):
    """Injects request_id into log records from contextvars."""

    def filter(self, record: logging.LogRecord) -> bool:
        from kryon.server.middleware.request_id import get_request_id

        record.request_id = get_request_id() or "-"  # type: ignore[attr-defined]
        return True


def setup_logging(debug: bool = False) -> None:
    """Configure structured logging for the server."""
    level = "DEBUG" if debug else "INFO"

    config: dict[str, Any] = {
        "version": 1,
        "disable_existing_loggers": False,
        "filters": {
            "request_id": {"()": RequestIdFilter},
        },
        "formatters": {
            "json": {
                "format": '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","request_id":"%(request_id)s","message":"%(message)s"}',
                "datefmt": "%Y-%m-%dT%H:%M:%S",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "json",
                "filters": ["request_id"],
                "stream": "ext://sys.stderr",
            },
        },
        "root": {
            "level": level,
            "handlers": ["console"],
        },
        "loggers": {
            "kryon": {"level": level, "propagate": True},
            "uvicorn": {"level": "WARNING", "propagate": True},
        },
    }
    logging.config.dictConfig(config)


def get_logger(name: str) -> logging.Logger:
    """Get a named logger with the request_id filter."""
    return logging.getLogger(name)
