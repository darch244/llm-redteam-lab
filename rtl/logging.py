"""Logging configuration for the lab.

Default human-readable logs use a ``rich`` console handler. Passing
``json=True`` emits structured JSON lines suitable for ingestion into a SIEM
or log aggregator, which matters when a red-team engagement is run against a
monitored target.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

try:  # rich is a hard dependency, but keep import order defensive for embedding
    from rich.console import Console
    from rich.logging import RichHandler
except ImportError:  # pragma: no cover
    Console = None  # type: ignore[assignment,misc]
    RichHandler = None  # type: ignore[assignment,misc]

LOGGER_NAME = "rtl"


class JsonFormatter(logging.Formatter):
    """Minimal structured JSON formatter for machine-readable audit logs."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        for key in ("target", "attack_id", "scenario", "engine"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        return json.dumps(payload, default=str)


_CONSOLE = Console(stderr=True) if Console is not None else None


def setup_logging(level: str = "INFO", json_mode: bool = False) -> None:
    """Configure the root ``rtl`` logger.

    Args:
        level: Standard logging level name (``DEBUG``, ``INFO``, ...).
        json_mode: Emit newline-delimited JSON instead of rich text.
    """
    numeric = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger(LOGGER_NAME)
    root.setLevel(numeric)
    root.handlers.clear()

    if json_mode and Console is not None:
        handler: logging.Handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(JsonFormatter())
    elif RichHandler is not None and _CONSOLE is not None:
        handler = RichHandler(
            console=_CONSOLE,
            show_path=False,
            show_time=True,
            rich_tracebacks=True,
            markup=True,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
    else:  # pragma: no cover - stdlib fallback
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s"))

    root.addHandler(handler)
    root.propagate = False


def get_logger(name: str) -> logging.Logger:
    """Return a child logger of the ``rtl`` hierarchy."""
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


__all__ = ["get_logger", "setup_logging"]
