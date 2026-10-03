"""File logging for PulseOps. The TUI owns the terminal, so diagnostics go to a rotating file."""
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

LOGGER_NAME = "pulseops"


def default_log_path() -> Path:
    cache = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(cache) / "pulseops" / "pulseops.log"


def setup_logging(path: Optional[Path] = None, level: int = logging.INFO) -> Optional[Path]:
    """Configures the `pulseops` logger. Returns the log file path, or None if it is not writable."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False
    if logger.handlers:
        return getattr(logger, "_pulseops_path", None)

    path = path or default_log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    except OSError:
        logger.addHandler(logging.NullHandler())
        return None
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger._pulseops_path = path
    return path


def get_logger(name: str = "") -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME)
