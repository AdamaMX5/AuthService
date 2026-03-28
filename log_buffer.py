# log_buffer.py
"""
In-memory log ring buffer with per-request correlation IDs.

A single InMemoryLogHandler is installed on the root logger at startup.
Every log record that reaches the root logger is appended to a fixed-size
deque so that recent entries can be queried via the admin API.

Correlation IDs are injected automatically by RequestIDMiddleware in main.py:
it sets `request_id_var` for the lifetime of each HTTP request, and the
handler picks up that value for every log record produced within that request.
"""

import logging
import uuid
from collections import deque
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Correlation-ID context variable
# ---------------------------------------------------------------------------
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

# ---------------------------------------------------------------------------
# Ring buffer
# ---------------------------------------------------------------------------
_BUFFER_MAX_SIZE = 2000


class _LogEntry:
    __slots__ = ("timestamp", "level", "logger_name", "message", "request_id")

    def __init__(
        self,
        timestamp: datetime,
        level: str,
        logger_name: str,
        message: str,
        request_id: str | None,
    ) -> None:
        self.timestamp = timestamp
        self.level = level
        self.logger_name = logger_name
        self.message = message
        self.request_id = request_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level,
            "logger": self.logger_name,
            "message": self.message,
            "request_id": self.request_id,
        }


_buffer: deque[_LogEntry] = deque(maxlen=_BUFFER_MAX_SIZE)


# ---------------------------------------------------------------------------
# Custom handler
# ---------------------------------------------------------------------------
class InMemoryLogHandler(logging.Handler):
    """Appends structured log records to the in-memory ring buffer."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = _LogEntry(
                timestamp=datetime.fromtimestamp(record.created, tz=timezone.utc),
                level=record.levelname,
                logger_name=record.name,
                message=self.format(record),
                request_id=request_id_var.get(),
            )
            _buffer.append(entry)
        except Exception:
            self.handleError(record)


# ---------------------------------------------------------------------------
# Query helper
# ---------------------------------------------------------------------------
_VALID_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def query_logs(
    *,
    minutes: float,
    min_level: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """
    Return (page, total_matching) filtered by time window and minimum log level.

    Parameters
    ----------
    minutes:   How far back to look (e.g. 5.0 = last 5 minutes).
    min_level: Minimum severity to include (e.g. "WARNING" returns WARNING+).
               None means no level filter.
    limit:     Page size.
    offset:    Number of matching entries to skip before the page.
    """
    cutoff = datetime.now(tz=timezone.utc) - timedelta(minutes=minutes)

    min_level_num: int = 0
    if min_level:
        parsed = logging.getLevelName(min_level.upper())
        if isinstance(parsed, int):
            min_level_num = parsed

    matching = [
        e
        for e in _buffer
        if e.timestamp >= cutoff
        and (min_level_num == 0 or logging.getLevelName(e.level) >= min_level_num)
    ]

    total = len(matching)
    page = [e.to_dict() for e in matching[offset : offset + limit]]
    return page, total
