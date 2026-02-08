from __future__ import annotations

import hmac
import os
import threading
import time
from functools import wraps
from typing import Callable, TypeVar

F = TypeVar("F", bound=Callable[..., object])

_LOGIN_RATE_LOCK = threading.Lock()
_FAILED_LOGIN_ATTEMPTS: dict[str, list[float]] = {}
_LOGIN_LOCKOUT_UNTIL: dict[str, float] = {}

_PLACEHOLDER_ADMIN_HASHES = {
    "replace-with-werkzeug-hash",
    "changeme",
    "change-me",
    "password-hash-here",
}


def admin_username() -> str:
    return os.environ.get("APP_ADMIN_USER", "").strip()


def admin_password_hash() -> str:
    return os.environ.get("APP_ADMIN_PASSWORD_HASH", "").strip()


def auth_is_configured() -> bool:
    return bool(admin_username() and admin_password_hash())


def auth_warnings() -> list[str]:
    return auth_configuration_errors()


def auth_configuration_errors() -> list[str]:
    errors: list[str] = []
    configured_username = admin_username()
    configured_hash = admin_password_hash()

    if not configured_username:
        errors.append("APP_ADMIN_USER is not set.")
    if not configured_hash:
        errors.append("APP_ADMIN_PASSWORD_HASH is not set.")
    elif configured_hash.lower() in _PLACEHOLDER_ADMIN_HASHES:
        errors.append("APP_ADMIN_PASSWORD_HASH uses a placeholder value.")

    return errors


def verify_credentials(username: str, password: str) -> bool:
    from werkzeug.security import check_password_hash

    expected_username = admin_username()
    expected_password_hash = admin_password_hash()
    if not expected_username or not expected_password_hash:
        return False

    username_ok = hmac.compare_digest(username.strip(), expected_username)
    password_ok = check_password_hash(expected_password_hash, password)
    return username_ok and password_ok


def _read_positive_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _login_limits() -> tuple[int, int, int]:
    max_attempts = _read_positive_int_env("APP_LOGIN_MAX_ATTEMPTS", 5)
    window_seconds = _read_positive_int_env("APP_LOGIN_WINDOW_SECONDS", 900)
    lockout_seconds = _read_positive_int_env("APP_LOGIN_LOCKOUT_SECONDS", 900)
    return max_attempts, window_seconds, lockout_seconds


def _rate_limit_key(remote_addr: str | None) -> str:
    key = (remote_addr or "unknown").strip()
    return key or "unknown"


def _prune_state(now: float, window_seconds: int) -> None:
    stale_keys = []
    for key, attempts in _FAILED_LOGIN_ATTEMPTS.items():
        fresh_attempts = [attempt for attempt in attempts if now - attempt <= window_seconds]
        if fresh_attempts:
            _FAILED_LOGIN_ATTEMPTS[key] = fresh_attempts
        else:
            stale_keys.append(key)

    for key in stale_keys:
        _FAILED_LOGIN_ATTEMPTS.pop(key, None)

    expired_lockouts = [key for key, until in _LOGIN_LOCKOUT_UNTIL.items() if now >= until]
    for key in expired_lockouts:
        _LOGIN_LOCKOUT_UNTIL.pop(key, None)


def login_retry_after_seconds(remote_addr: str | None) -> int:
    now = time.monotonic()
    _, window_seconds, _ = _login_limits()

    with _LOGIN_RATE_LOCK:
        _prune_state(now, window_seconds)
        key = _rate_limit_key(remote_addr)
        lockout_until = _LOGIN_LOCKOUT_UNTIL.get(key)
        if lockout_until is None:
            return 0
        return max(1, int(lockout_until - now))


def record_failed_login(remote_addr: str | None) -> int:
    now = time.monotonic()
    max_attempts, window_seconds, lockout_seconds = _login_limits()
    key = _rate_limit_key(remote_addr)

    with _LOGIN_RATE_LOCK:
        _prune_state(now, window_seconds)
        attempts = _FAILED_LOGIN_ATTEMPTS.setdefault(key, [])
        attempts.append(now)

        if len(attempts) < max_attempts:
            return 0

        _LOGIN_LOCKOUT_UNTIL[key] = now + lockout_seconds
        _FAILED_LOGIN_ATTEMPTS.pop(key, None)
        return lockout_seconds


def clear_failed_login(remote_addr: str | None) -> None:
    key = _rate_limit_key(remote_addr)
    with _LOGIN_RATE_LOCK:
        _FAILED_LOGIN_ATTEMPTS.pop(key, None)
        _LOGIN_LOCKOUT_UNTIL.pop(key, None)


def reset_login_rate_limit_state_for_tests() -> None:
    with _LOGIN_RATE_LOCK:
        _FAILED_LOGIN_ATTEMPTS.clear()
        _LOGIN_LOCKOUT_UNTIL.clear()


def login_required(view: F) -> F:
    @wraps(view)
    def wrapped(*args, **kwargs):
        from flask import redirect, request, session, url_for

        if session.get("authenticated"):
            return view(*args, **kwargs)
        next_path = request.path
        if request.query_string:
            next_path = f"{next_path}?{request.query_string.decode('utf-8', errors='ignore')}"
        return redirect(url_for("login", next=next_path))

    return wrapped  # type: ignore[return-value]


def sanitize_next_path(value: str | None) -> str:
    from flask import url_for

    if not value:
        return url_for("index")
    if not value.startswith("/"):
        return url_for("index")
    if value.startswith("//"):
        return url_for("index")
    return value


def do_login(username: str) -> None:
    from flask import session

    session.clear()
    session["authenticated"] = True
    session["auth_user"] = username


def do_logout() -> None:
    from flask import flash, session

    session.clear()
    flash("Logged out.", "success")
