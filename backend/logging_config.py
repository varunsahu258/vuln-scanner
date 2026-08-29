"""Structured JSON logging configuration for backend services."""

from datetime import datetime, timezone
import json
import logging
import sys


class JsonFormatter(logging.Formatter):
    """Render scan-request log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        for field in ("source_ip", "target_url", "outcome", "scan_id"):
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        return json.dumps(payload, default=str)


def configure_logging() -> None:
    """Configure the backend logger once, writing JSON logs to stdout."""
    logger = logging.getLogger("backend")
    if any(getattr(handler, "_vuln_scanner_json", False) for handler in logger.handlers):
        return

    handler = logging.StreamHandler(sys.stdout)
    handler._vuln_scanner_json = True  # type: ignore[attr-defined]
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
