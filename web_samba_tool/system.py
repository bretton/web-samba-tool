from __future__ import annotations

import fcntl
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
import grp
import pwd
from contextlib import contextmanager
from typing import Iterable

USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
GROUP_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
DEFAULT_MANAGED_USERS_FILE = "run/managed_users.json"
DEFAULT_COMMAND_TIMEOUT_SECONDS = 15.0
DEFAULT_DISALLOWED_SUPPLEMENTAL_GROUPS = {"nogroup", "root"}
SUDO_PREFIX = ["sudo", "-n"]
REQUIRED_COMMANDS = [
    "adduser",
    "deluser",
    "usermod",
    "chpasswd",
    "smbpasswd",
    "pdbedit",
    "getent",
    "id",
]


@dataclass
class ManagedUser:
    username: str
    uid: int
    groups: list[str]
    samba_enabled: bool


@dataclass
class ShareInfo:
    name: str
    group: str
    mode: str


class CommandError(RuntimeError):
    def __init__(self, cmd: list[str], returncode: int, stdout: str, stderr: str):
        message = stderr.strip() or stdout.strip() or "Unknown command failure"
        super().__init__(f"{' '.join(cmd)} failed: {message}")
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class CommandTimeoutError(CommandError):
    def __init__(self, cmd: list[str], timeout_seconds: float, stdout: str, stderr: str):
        super().__init__(cmd, 124, stdout, stderr)
        self.timeout_seconds = timeout_seconds
        detail = stderr.strip() or stdout.strip()
        if detail:
            self.args = (f"{' '.join(cmd)} timed out after {timeout_seconds:.1f}s: {detail}",)
        else:
            self.args = (f"{' '.join(cmd)} timed out after {timeout_seconds:.1f}s",)


def _command_timeout_seconds() -> float:
    raw = os.environ.get("APP_COMMAND_TIMEOUT_SECONDS", "").strip()
    if not raw:
        return DEFAULT_COMMAND_TIMEOUT_SECONDS
    try:
        parsed = float(raw)
    except ValueError:
        return DEFAULT_COMMAND_TIMEOUT_SECONDS
    if parsed <= 0:
        return DEFAULT_COMMAND_TIMEOUT_SECONDS
    return parsed


def run_command(
    cmd: list[str],
    *,
    input_text: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    timeout_seconds = _command_timeout_seconds()
    try:
        result = subprocess.run(
            cmd,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise CommandError(cmd, 127, "", str(exc)) from exc
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        raise CommandTimeoutError(cmd, timeout_seconds, stdout, stderr) from exc

    if check and result.returncode != 0:
        raise CommandError(cmd, result.returncode, result.stdout, result.stderr)

    return result


def _validate_username(username: str) -> str:
    normalized = username.strip()
    if not USERNAME_RE.match(normalized):
        raise ValueError(
            "Invalid username. Use lowercase letters, digits, underscores, or hyphens."
        )
    return normalized


def _validate_groups(groups: Iterable[str]) -> list[str]:
    disallowed = disallowed_supplemental_groups()
    validated = []
    for group_name in groups:
        cleaned = group_name.strip()
        if not GROUP_RE.match(cleaned):
            raise ValueError(f"Invalid group name: {group_name}")
        if cleaned in disallowed:
            raise ValueError(f"Group is not allowed for assignment: {cleaned}")
        validated.append(cleaned)
    return sorted(set(validated))


def _validate_password(value: str, *, label: str, allow_colon: bool) -> str:
    if not value:
        raise ValueError(f"{label} is required.")

    for character in value:
        codepoint = ord(character)
        if codepoint < 32 or codepoint == 127:
            raise ValueError(f"{label} cannot contain control characters.")
        if not allow_colon and character == ":":
            raise ValueError(f"{label} cannot contain ':'.")

    return value


def _get_uid_min() -> int:
    path = "/etc/login.defs"
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("UID_MIN"):
                    _, value = line.split(maxsplit=1)
                    return int(value)
    except (FileNotFoundError, OSError, ValueError):
        pass
    return 1000


def _parse_group_entry(entry: str) -> tuple[str, int]:
    name, _, gid, _ = entry.strip().split(":", maxsplit=3)
    return name, int(gid)


def _all_groups() -> list[tuple[str, int]]:
    result = run_command(["getent", "group"])
    entries = []
    for raw in result.stdout.splitlines():
        if not raw.strip():
            continue
        entries.append(_parse_group_entry(raw))
    return entries


def disallowed_supplemental_groups() -> set[str]:
    raw = os.environ.get("APP_DISALLOWED_SUPPLEMENTAL_GROUPS", "").strip()
    if not raw:
        return set(DEFAULT_DISALLOWED_SUPPLEMENTAL_GROUPS)

    parsed = set()
    for value in raw.split(","):
        cleaned = value.strip()
        if cleaned and GROUP_RE.match(cleaned):
            parsed.add(cleaned)

    return parsed or set(DEFAULT_DISALLOWED_SUPPLEMENTAL_GROUPS)


def candidate_groups() -> list[str]:
    uid_min = _get_uid_min()
    groups = {name for name, gid in _all_groups() if gid >= uid_min}
    disallowed = disallowed_supplemental_groups()

    for share in list_shares():
        groups.add(share.group)

    return sorted(group for group in groups if group not in disallowed)


def _group_exists(group_name: str) -> bool:
    result = run_command(["getent", "group", group_name], check=False)
    return result.returncode == 0


def _user_exists(username: str) -> bool:
    result = run_command(["getent", "passwd", username], check=False)
    return result.returncode == 0


def _managed_users_file() -> str:
    configured_path = os.environ.get("APP_MANAGED_USERS_FILE", DEFAULT_MANAGED_USERS_FILE).strip()
    if not configured_path:
        configured_path = DEFAULT_MANAGED_USERS_FILE
    if os.path.isabs(configured_path):
        return configured_path
    return os.path.abspath(configured_path)


@contextmanager
def _managed_users_lock() -> Iterable[str]:
    managed_users_path = _managed_users_file()
    directory = os.path.dirname(managed_users_path) or "."
    os.makedirs(directory, exist_ok=True)
    lock_path = f"{managed_users_path}.lock"
    with open(lock_path, "a+", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            yield managed_users_path
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _load_managed_usernames(path: str) -> set[str]:
    if not os.path.exists(path):
        return set()

    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, list):
        raise ValueError(f"Managed users file is invalid: {path}")

    usernames = set()
    for value in payload:
        if isinstance(value, str) and USERNAME_RE.match(value.strip()):
            usernames.add(value.strip())
    return usernames


def _write_managed_usernames(path: str, usernames: set[str]) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    file_descriptor, temporary_path = tempfile.mkstemp(
        prefix=".managed-users-",
        suffix=".json",
        dir=directory,
        text=True,
    )

    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
            json.dump(sorted(usernames), handle)
            handle.write("\n")
        os.replace(temporary_path, path)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)

    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _store_command_error(exc: Exception) -> CommandError:
    return CommandError(["managed-user-store"], 1, "", str(exc))


def _is_tool_managed_user(username: str) -> bool:
    try:
        with _managed_users_lock() as managed_users_path:
            usernames = _load_managed_usernames(managed_users_path)
    except (OSError, ValueError) as exc:
        raise _store_command_error(exc) from exc
    return username in usernames


def _add_tool_managed_user(username: str) -> None:
    try:
        with _managed_users_lock() as managed_users_path:
            usernames = _load_managed_usernames(managed_users_path)
            usernames.add(username)
            _write_managed_usernames(managed_users_path, usernames)
    except (OSError, ValueError) as exc:
        raise _store_command_error(exc) from exc


def _remove_tool_managed_user(username: str) -> None:
    try:
        with _managed_users_lock() as managed_users_path:
            usernames = _load_managed_usernames(managed_users_path)
            usernames.discard(username)
            _write_managed_usernames(managed_users_path, usernames)
    except (OSError, ValueError) as exc:
        raise _store_command_error(exc) from exc


def _tool_managed_usernames() -> set[str]:
    try:
        with _managed_users_lock() as managed_users_path:
            return _load_managed_usernames(managed_users_path)
    except (OSError, ValueError) as exc:
        raise _store_command_error(exc) from exc


def _samba_usernames() -> set[str]:
    result = run_command(SUDO_PREFIX + ["pdbedit", "-L"], check=False)
    if result.returncode != 0:
        return set()

    usernames = set()
    for line in result.stdout.splitlines():
        if not line.strip() or ":" not in line:
            continue
        usernames.add(line.split(":", maxsplit=1)[0].strip())
    return usernames


def list_managed_users() -> list[ManagedUser]:
    uid_min = _get_uid_min()
    tool_managed = _tool_managed_usernames()
    if not tool_managed:
        return []

    samba_users = _samba_usernames()
    users: list[ManagedUser] = []

    result = run_command(["getent", "passwd"])
    for raw in result.stdout.splitlines():
        if not raw.strip():
            continue

        username, _, uid, _, _, home, shell = raw.split(":", maxsplit=6)
        if username not in tool_managed:
            continue

        uid_value = int(uid)
        if uid_value < uid_min:
            continue
        if not home.startswith("/home/"):
            continue
        if shell.strip() in {"/usr/sbin/nologin", "/bin/false"}:
            continue

        group_result = run_command(["id", "-nG", username], check=False)
        groups = []
        if group_result.returncode == 0:
            groups = sorted(group_result.stdout.strip().split())

        users.append(
            ManagedUser(
                username=username,
                uid=uid_value,
                groups=groups,
                samba_enabled=username in samba_users,
            )
        )

    users.sort(key=lambda item: item.username)
    return users


def list_shares() -> list[ShareInfo]:
    shares_path = "/shares"
    if not os.path.isdir(shares_path):
        return []

    shares: list[ShareInfo] = []
    try:
        entries = sorted(os.scandir(shares_path), key=lambda item: item.name)
    except OSError:
        return []

    for entry in entries:
        if not entry.is_dir(follow_symlinks=False):
            continue
        try:
            stat_result = os.stat(entry.path)
            group_name = grp.getgrgid(stat_result.st_gid).gr_name
            mode = oct(stat_result.st_mode & 0o777)
        except (OSError, KeyError):
            continue
        shares.append(ShareInfo(name=entry.name, group=group_name, mode=mode))

    return shares


def create_managed_user(
    username: str,
    unix_password: str,
    samba_password: str,
    groups: Iterable[str],
) -> None:
    normalized_username = _validate_username(username)
    normalized_groups = _validate_groups(groups)
    validated_unix_password = _validate_password(
        unix_password,
        label="Linux password",
        allow_colon=False,
    )
    validated_samba_password = _validate_password(
        samba_password,
        label="Samba password",
        allow_colon=True,
    )

    if _user_exists(normalized_username):
        raise ValueError(f"User already exists: {normalized_username}")

    for group_name in normalized_groups:
        if not _group_exists(group_name):
            raise ValueError(f"Group does not exist: {group_name}")

    current_user = pwd.getpwuid(os.getuid()).pw_name
    if normalized_username == current_user:
        raise ValueError("Refusing to create a user with the same name as the app runtime user.")

    user_created = False
    try:
        run_command(
            SUDO_PREFIX
            + [
                "adduser",
                "--disabled-password",
                "--gecos",
                "",
                normalized_username,
            ]
        )
        user_created = True

        run_command(
            SUDO_PREFIX + ["chpasswd"],
            input_text=f"{normalized_username}:{validated_unix_password}\n",
        )

        if normalized_groups:
            run_command(
                SUDO_PREFIX
                + ["usermod", "-aG", ",".join(normalized_groups), normalized_username]
            )

        run_command(
            SUDO_PREFIX + ["smbpasswd", "-a", "-s", normalized_username],
            input_text=f"{validated_samba_password}\n{validated_samba_password}\n",
        )
        _add_tool_managed_user(normalized_username)
    except CommandError:
        if user_created:
            run_command(SUDO_PREFIX + ["smbpasswd", "-x", normalized_username], check=False)
            run_command(
                SUDO_PREFIX + ["deluser", "--remove-home", normalized_username],
                check=False,
            )
        raise


def delete_managed_user(username: str) -> None:
    normalized_username = _validate_username(username)

    if not _is_tool_managed_user(normalized_username):
        raise ValueError(f"Refusing to delete unmanaged user: {normalized_username}")

    if not _user_exists(normalized_username):
        raise ValueError(f"User does not exist: {normalized_username}")

    uid_min = _get_uid_min()
    passwd_result = run_command(["getent", "passwd", normalized_username])
    _, _, uid, _, _, _, _ = passwd_result.stdout.strip().split(":", maxsplit=6)
    uid_value = int(uid)
    if uid_value < uid_min:
        raise ValueError("Refusing to delete a system account.")

    current_user = pwd.getpwuid(os.getuid()).pw_name
    if normalized_username == current_user:
        raise ValueError("Refusing to delete the app runtime user.")

    run_command(SUDO_PREFIX + ["smbpasswd", "-x", normalized_username], check=False)
    run_command(SUDO_PREFIX + ["deluser", "--remove-home", normalized_username])
    _remove_tool_managed_user(normalized_username)


def update_managed_user_groups(username: str, groups: Iterable[str]) -> None:
    normalized_username = _validate_username(username)
    normalized_groups = _validate_groups(groups)

    if not _is_tool_managed_user(normalized_username):
        raise ValueError(f"Refusing to edit unmanaged user: {normalized_username}")

    if not _user_exists(normalized_username):
        raise ValueError(f"User does not exist: {normalized_username}")

    uid_min = _get_uid_min()
    passwd_result = run_command(["getent", "passwd", normalized_username])
    _, _, uid, _, _, _, _ = passwd_result.stdout.strip().split(":", maxsplit=6)
    uid_value = int(uid)
    if uid_value < uid_min:
        raise ValueError("Refusing to modify groups for a system account.")

    current_user = pwd.getpwuid(os.getuid()).pw_name
    if normalized_username == current_user:
        raise ValueError("Refusing to modify groups for the app runtime user.")

    for group_name in normalized_groups:
        if not _group_exists(group_name):
            raise ValueError(f"Group does not exist: {group_name}")

    run_command(
        SUDO_PREFIX + ["usermod", "-G", ",".join(normalized_groups), normalized_username]
    )


def _runtime_search_path() -> str:
    parts = [value for value in os.environ.get("PATH", "").split(os.pathsep) if value]
    for extra in ("/usr/sbin", "/sbin"):
        if extra not in parts:
            parts.append(extra)
    return os.pathsep.join(parts)


def runtime_warnings() -> list[str]:
    warnings: list[str] = []

    # Verify sudoers for a harmless command that this app already needs.
    sudo_check = run_command(SUDO_PREFIX + ["getent", "passwd", "root"], check=False)
    if sudo_check.returncode != 0:
        warnings.append(
            "Passwordless sudo is not configured for this app user. "
            "Configure /etc/sudoers.d as documented in README.md."
        )

    search_path = _runtime_search_path()
    for command in REQUIRED_COMMANDS:
        if shutil.which(command, path=search_path) is None:
            warnings.append(f"Required command not found in PATH: {command}")

    return warnings
