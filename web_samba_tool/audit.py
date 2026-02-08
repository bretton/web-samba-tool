from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

AUDIT_LOGGER_NAME = "web_samba_tool.audit"
DEFAULT_AUDIT_LOG_PATH = "run/audit.log"


class AuditConfigurationError(RuntimeError):
    pass


def _resolved_audit_log_path() -> str:
    configured_path = os.environ.get("APP_AUDIT_LOG", DEFAULT_AUDIT_LOG_PATH).strip()
    if not configured_path:
        configured_path = DEFAULT_AUDIT_LOG_PATH

    if os.path.isabs(configured_path):
        return configured_path

    return os.path.abspath(configured_path)


def configure_audit_logger() -> str:
    path = _resolved_audit_log_path()
    directory = os.path.dirname(path) or "."

    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as exc:
        raise AuditConfigurationError(f"Failed to create audit log directory: {directory}") from exc

    logger = logging.getLogger(AUDIT_LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    try:
        file_handler = logging.FileHandler(path, encoding="utf-8")
    except OSError as exc:
        raise AuditConfigurationError(f"Failed to open audit log file: {path}") from exc

    file_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(file_handler)

    try:
        os.chmod(path, 0o600)
    except OSError:
        # Best effort only; this can fail on some filesystems.
        pass

    return path


def audit_event(event: str, *, outcome: str, **fields: object) -> None:
    payload: dict[str, object] = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event,
        "outcome": outcome,
    }

    for key, value in fields.items():
        if value is not None:
            payload[key] = value

    logger = logging.getLogger(AUDIT_LOGGER_NAME)
    logger.info(json.dumps(payload, sort_keys=True, separators=(",", ":")))
