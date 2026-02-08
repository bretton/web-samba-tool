# AGENTS.md

This file defines how coding agents should work in this repository.

## Project Summary

- Project: `web-samba-tool`
- Purpose: Internal web UI for managing Linux users and Samba users on Ubuntu 24.04 hosts.
- Runtime: Flask app behind Gunicorn + nginx.
- Security model: authenticated admin UI + rate-limited login + passwordless `sudo -n` for a narrow command set.

Core files:
- `web_samba_tool/app.py`
- `web_samba_tool/system.py`
- `web_samba_tool/auth.py`
- `web_samba_tool/audit.py`
- `tests/`
- `deploy/web-samba-tool.service`
- `deploy/nginx-web-samba-tool.conf`

## Non-Negotiable Safety Invariants

Agents must preserve these behaviors unless explicitly asked to change them:

1. Authentication is required for management actions.
2. Failed-login rate limiting remains enabled.
3. Startup fails when required auth/secret config is missing or placeholder.
4. User deletion remains restricted to tool-managed users only.
5. Plaintext credentials are never written to logs, audit events, or persistent files.
6. Privileged operations continue to run through `sudo -n` command execution.
7. Any rollback/cleanup path in user creation must remain intact on partial failures.

If a requested change conflicts with these invariants, pause and call it out clearly.

## Editing Rules

- Keep changes minimal and scoped to the request.
- Do not silently weaken validation for usernames, groups, or passwords.
- Do not introduce broad shell execution; keep explicit argument lists for subprocess calls.
- Avoid changing deploy templates unless the request is deployment-related.
- Preserve `APPUSER` placeholders in deploy templates.
- Do not commit generated runtime files (`run/`, logs, temp files).

## Testing Expectations

Run tests after meaningful backend changes:

```bash
python3 -m unittest discover -s tests -v
```

Test policy:
- New or changed behavior in `system.py`, `auth.py`, `audit.py`, or startup flow should include test updates.
- Mock system/subprocess interactions in tests. Do not run destructive user-management commands against the host as part of tests.
- If tests cannot be run, explain why in the final report.

## Environment Contract

Required environment variables:
- `APP_SECRET`
- `APP_ADMIN_USER`
- `APP_ADMIN_PASSWORD_HASH`

Common optional variables:
- `APP_AUDIT_LOG`
- `APP_MANAGED_USERS_FILE`
- `APP_COMMAND_TIMEOUT_SECONDS`
- `APP_LOGIN_MAX_ATTEMPTS`
- `APP_LOGIN_WINDOW_SECONDS`
- `APP_LOGIN_LOCKOUT_SECONDS`

Agents should not hardcode secrets or hashes in source files.

## Scope Boundaries

In scope:
- Flask routes/templates/static UI for the app
- Auth, audit, and user-management logic
- Tests and documentation updates tied to code changes

Out of scope unless explicitly requested:
- Direct edits to `/etc/samba/smb.conf`
- Broader OS provisioning/hardening beyond this app
- Production migration or internet-exposed deployment assumptions

## Recommended Workflow

1. Read relevant files and existing tests first.
2. Implement the smallest safe change.
3. Update/add tests for behavioral changes.
4. Run tests.
5. Summarize what changed, what was validated, and any remaining risk.
