from __future__ import annotations

import os
from flask import Flask, flash, redirect, render_template, request, session, url_for

from .audit import AuditConfigurationError, audit_event, configure_audit_logger
from .auth import (
    admin_username,
    auth_configuration_errors,
    auth_is_configured,
    auth_warnings,
    clear_failed_login,
    do_login,
    do_logout,
    login_required,
    login_retry_after_seconds,
    record_failed_login,
    sanitize_next_path,
    verify_credentials,
)

from .system import (
    CommandError,
    CommandTimeoutError,
    candidate_groups,
    create_managed_user,
    delete_managed_user,
    list_managed_users,
    list_shares,
    runtime_warnings,
    update_managed_user_groups,
)

_PLACEHOLDER_APP_SECRETS = {
    "change-me-in-production",
    "replace-with-random-secret",
    "changeme",
    "change-me",
    "secret",
}


def _startup_configuration_errors() -> list[str]:
    errors = auth_configuration_errors()
    app_secret = os.environ.get("APP_SECRET", "").strip()
    if not app_secret:
        errors.append("APP_SECRET is not set.")
    elif app_secret.lower() in _PLACEHOLDER_APP_SECRETS:
        errors.append("APP_SECRET uses a placeholder value.")
    return errors


def _client_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for.strip():
        return forwarded_for.split(",", maxsplit=1)[0].strip()
    return request.remote_addr or "unknown"


def create_app() -> Flask:
    startup_errors = _startup_configuration_errors()
    if startup_errors:
        joined_errors = " ".join(startup_errors)
        raise RuntimeError(f"Invalid startup configuration. {joined_errors}")

    try:
        audit_log_path = configure_audit_logger()
    except AuditConfigurationError as exc:
        raise RuntimeError(str(exc)) from exc

    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ["APP_SECRET"]
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["AUDIT_LOG_PATH"] = audit_log_path

    audit_event("startup", outcome="success", audit_log_path=audit_log_path)

    @app.get("/")
    @login_required
    def index():
        users = []
        groups = []
        shares = []
        editable_groups_by_user = {}
        warnings = runtime_warnings()
        warnings.extend(auth_warnings())

        try:
            users = list_managed_users()
            groups = candidate_groups()
            shares = list_shares()
            editable_groups_by_user = {
                user.username: sorted(set(groups).union(user.groups)) for user in users
            }
        except CommandTimeoutError as exc:
            flash("System command timed out while loading data. Please try again.", "error")
            audit_event(
                "dashboard_load",
                outcome="timeout",
                client_ip=_client_ip(),
                error=str(exc),
            )
        except CommandError as exc:
            flash(str(exc), "error")
            audit_event(
                "dashboard_load",
                outcome="error",
                client_ip=_client_ip(),
                error=str(exc),
            )

        return render_template(
            "index.html",
            users=users,
            groups=groups,
            shares=shares,
            editable_groups_by_user=editable_groups_by_user,
            warnings=warnings,
        )

    @app.get("/login")
    def login():
        if session.get("authenticated"):
            return redirect(url_for("index"))
        return render_template(
            "login.html",
            warnings=auth_warnings(),
            next_path=sanitize_next_path(request.args.get("next")),
        )

    @app.post("/login")
    def login_post():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_path = sanitize_next_path(request.form.get("next"))
        client_ip = _client_ip()

        retry_after_seconds = login_retry_after_seconds(client_ip)
        if retry_after_seconds > 0:
            flash(
                f"Too many failed logins. Try again in {retry_after_seconds} seconds.",
                "error",
            )
            audit_event(
                "login",
                outcome="blocked",
                username=username,
                client_ip=client_ip,
                retry_after_seconds=retry_after_seconds,
            )
            return redirect(url_for("login", next=next_path))

        if not auth_is_configured():
            flash(
                "Authentication is not configured. Set APP_ADMIN_USER and APP_ADMIN_PASSWORD_HASH.",
                "error",
            )
            audit_event(
                "login",
                outcome="error",
                username=username,
                client_ip=client_ip,
                error="authentication_not_configured",
            )
            return redirect(url_for("login"))

        if verify_credentials(username, password):
            clear_failed_login(client_ip)
            do_login(admin_username())
            flash("Login successful.", "success")
            audit_event(
                "login",
                outcome="success",
                username=username,
                client_ip=client_ip,
            )
            return redirect(next_path)

        retry_after_seconds = record_failed_login(client_ip)
        if retry_after_seconds > 0:
            flash(
                f"Too many failed logins. Try again in {retry_after_seconds} seconds.",
                "error",
            )
        flash("Invalid username or password.", "error")
        audit_event(
            "login",
            outcome="failure",
            username=username,
            client_ip=client_ip,
            retry_after_seconds=retry_after_seconds or None,
        )
        return redirect(url_for("login", next=next_path))

    @app.post("/logout")
    @login_required
    def logout():
        current_user = session.get("auth_user")
        client_ip = _client_ip()
        do_logout()
        audit_event(
            "logout",
            outcome="success",
            username=current_user,
            client_ip=client_ip,
        )
        return redirect(url_for("login"))

    @app.post("/users")
    @login_required
    def create_user():
        username = request.form.get("username", "").strip()
        unix_password = request.form.get("unix_password", "")
        samba_password = request.form.get("samba_password", "")
        group_names = request.form.getlist("groups")
        actor = session.get("auth_user")
        client_ip = _client_ip()

        if request.form.get("same_password") == "on" and not samba_password:
            samba_password = unix_password

        try:
            create_managed_user(username, unix_password, samba_password, group_names)
            flash(f"Created user {username} and Samba account.", "success")
            audit_event(
                "user_create",
                outcome="success",
                actor=actor,
                username=username,
                groups=",".join(sorted(set(group_names))),
                client_ip=client_ip,
            )
        except CommandTimeoutError as exc:
            flash("User creation timed out while running a system command.", "error")
            audit_event(
                "user_create",
                outcome="timeout",
                actor=actor,
                username=username,
                client_ip=client_ip,
                error=str(exc),
            )
        except (ValueError, CommandError) as exc:
            flash(str(exc), "error")
            audit_event(
                "user_create",
                outcome="error",
                actor=actor,
                username=username,
                client_ip=client_ip,
                error=str(exc),
            )

        return redirect(url_for("index"))

    @app.post("/users/<username>/delete")
    @login_required
    def delete_user(username: str):
        actor = session.get("auth_user")
        client_ip = _client_ip()
        try:
            delete_managed_user(username)
            flash(f"Deleted user {username} and removed Samba account.", "success")
            audit_event(
                "user_delete",
                outcome="success",
                actor=actor,
                username=username,
                client_ip=client_ip,
            )
        except CommandTimeoutError as exc:
            flash("User deletion timed out while running a system command.", "error")
            audit_event(
                "user_delete",
                outcome="timeout",
                actor=actor,
                username=username,
                client_ip=client_ip,
                error=str(exc),
            )
        except (ValueError, CommandError) as exc:
            flash(str(exc), "error")
            audit_event(
                "user_delete",
                outcome="error",
                actor=actor,
                username=username,
                client_ip=client_ip,
                error=str(exc),
            )

        return redirect(url_for("index"))

    @app.post("/users/<username>/groups")
    @login_required
    def update_user_groups(username: str):
        group_names = request.form.getlist("groups")
        actor = session.get("auth_user")
        client_ip = _client_ip()
        try:
            update_managed_user_groups(username, group_names)
            flash(f"Updated supplemental groups for user {username}.", "success")
            audit_event(
                "user_groups_update",
                outcome="success",
                actor=actor,
                username=username,
                groups=",".join(sorted(set(group_names))),
                client_ip=client_ip,
            )
        except CommandTimeoutError as exc:
            flash("Group update timed out while running a system command.", "error")
            audit_event(
                "user_groups_update",
                outcome="timeout",
                actor=actor,
                username=username,
                client_ip=client_ip,
                error=str(exc),
            )
        except (ValueError, CommandError) as exc:
            flash(str(exc), "error")
            audit_event(
                "user_groups_update",
                outcome="error",
                actor=actor,
                username=username,
                client_ip=client_ip,
                error=str(exc),
            )

        return redirect(url_for("index"))

    return app
