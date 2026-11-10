"""Structured logging with a strict field whitelist.

Only the keys in ``ALLOWED_FIELDS`` are ever emitted. Log calls should pass
metadata via ``extra={"ss": {...}}``; anything else (and every exception
traceback) is dropped, so a stray variable holding scanner output cannot end
up in a log file.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

ALLOWED_FIELDS = frozenset(
    {
        "event",
        "scan_id",
        "repository_id",
        "finding_id",
        "mode",
        "status",
        "policy_result",
        "error_code",
        "duration_ms",
        "total_findings",
        "blocking_findings",
        "dropped_fields",
        "scanner_version",
        "count",
        "method",
        "route",
        "status_code",
    }
)

LOGGER_NAME = "secretsentinel"


class WhitelistJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
        }
        # The message itself must be a constant string written by developers.
        payload["msg"] = record.msg if isinstance(record.msg, str) else "log"
        extra = getattr(record, "ss", None)
        if isinstance(extra, dict):
            for key, value in extra.items():
                if key in ALLOWED_FIELDS and isinstance(value, (str, int, float, bool, type(None))):
                    payload[key] = value
        return json.dumps(payload, separators=(",", ":"))


def get_logger(name: str = LOGGER_NAME) -> logging.Logger:
    return logging.getLogger(name)


def configure_logging(level: str = "INFO") -> None:
    logger = logging.getLogger(LOGGER_NAME)
    if any(isinstance(h.formatter, WhitelistJsonFormatter) for h in logger.handlers):
        logger.setLevel(level)
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(WhitelistJsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False


def log_event(level: int, event: str, **fields) -> None:
    get_logger().log(level, event, extra={"ss": {"event": event, **fields}})
