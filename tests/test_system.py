import json
import os
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from web_samba_tool.system import (
    CommandTimeoutError,
    create_managed_user,
    delete_managed_user,
    list_managed_users,
    run_command,
)


def _completed_process(cmd: list[str], stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(cmd, returncode=returncode, stdout=stdout, stderr=stderr)


class SystemHardeningTests(unittest.TestCase):
    def test_create_user_rejects_control_chars_in_unix_password(self) -> None:
        with self.assertRaisesRegex(ValueError, "control characters"):
            create_managed_user("alice", "bad\npass", "safe-pass", [])

    def test_delete_rejects_unmanaged_users(self) -> None:
        with patch("web_samba_tool.system._is_tool_managed_user", return_value=False):
            with self.assertRaisesRegex(ValueError, "unmanaged user"):
                delete_managed_user("alice")

    def test_run_command_timeout_raises_command_timeout_error(self) -> None:
        timeout_exc = subprocess.TimeoutExpired(cmd=["id"], timeout=0.01, output="", stderr="")
        with patch("web_samba_tool.system.subprocess.run", side_effect=timeout_exc):
            with self.assertRaises(CommandTimeoutError):
                run_command(["id"])

    def test_list_managed_users_only_returns_tool_users(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            managed_file = os.path.join(temp_dir, "managed_users.json")
            with open(managed_file, "w", encoding="utf-8") as handle:
                json.dump(["managed"], handle)

            def fake_run_command(cmd, *, input_text=None, check=True):
                if cmd == ["getent", "passwd"]:
                    stdout = (
                        "managed:x:1001:1001::/home/managed:/bin/bash\n"
                        "other:x:1002:1002::/home/other:/bin/bash\n"
                    )
                    return _completed_process(cmd, stdout=stdout)
                if cmd[:3] == ["sudo", "-n", "pdbedit"]:
                    return _completed_process(cmd, stdout="managed:1001:\n")
                if cmd[:2] == ["id", "-nG"] and len(cmd) == 3:
                    if cmd[2] == "managed":
                        return _completed_process(cmd, stdout="managed-group\n")
                    return _completed_process(cmd, stdout="other-group\n")
                raise AssertionError(f"Unexpected command: {cmd}")

            with patch.dict(os.environ, {"APP_MANAGED_USERS_FILE": managed_file}, clear=False):
                with patch("web_samba_tool.system.run_command", side_effect=fake_run_command):
                    users = list_managed_users()

        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].username, "managed")

    def test_create_user_records_managed_registry(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            managed_file = os.path.join(temp_dir, "managed_users.json")

            def fake_run_command(cmd, *, input_text=None, check=True):
                return _completed_process(cmd)

            with patch.dict(os.environ, {"APP_MANAGED_USERS_FILE": managed_file}, clear=False):
                with patch("web_samba_tool.system.run_command", side_effect=fake_run_command):
                    with patch("web_samba_tool.system._user_exists", return_value=False):
                        with patch("web_samba_tool.system._group_exists", return_value=True):
                            with patch("web_samba_tool.system.os.getuid", return_value=1000):
                                with patch(
                                    "web_samba_tool.system.pwd.getpwuid",
                                    return_value=SimpleNamespace(pw_name="appuser"),
                                ):
                                    create_managed_user("alice", "safePass123", "safePass123", [])

            with open(managed_file, "r", encoding="utf-8") as handle:
                users = json.load(handle)

        self.assertEqual(users, ["alice"])


if __name__ == "__main__":
    unittest.main()
