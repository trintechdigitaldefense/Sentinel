# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Structured logging with daily rotation (feature 4)."""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        for key in ("event", "severity", "host", "action"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(
    level: str = "INFO",
    json_files: bool = True,
    retention_days: int = 30,
    log_dir: Optional[Path] = None,
) -> logging.Logger:
    log_dir = log_dir or Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("sentinel")
    logger.handlers.clear()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    # Console — human readable
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logger.level)
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
    logger.addHandler(ch)

    if json_files:
        fh = logging.handlers.TimedRotatingFileHandler(
            filename=str(log_dir / "sentinel.jsonl"),
            when="midnight",
            backupCount=max(1, int(retention_days)),
            encoding="utf-8",
        )
        fh.setLevel(logger.level)
        fh.setFormatter(JsonFormatter())
        logger.addHandler(fh)

    return logger
