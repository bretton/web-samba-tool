import os
import tempfile
import unittest
from unittest.mock import patch

from web_samba_tool import create_app

try:
    import flask  # noqa: F401

    HAS_FLASK = True
except ModuleNotFoundError:
    HAS_FLASK = False


@unittest.skipIf(not HAS_FLASK, "Flask dependencies are not installed")
class AppGroupUpdateRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.env_patcher = patch.dict(
            os.environ,
            {
                "APP_SECRET": "not-a-placeholder-secret-value",
                "APP_ADMIN_USER": "admin",
                "APP_ADMIN_PASSWORD_HASH": "scrypt:32768:8:1$dummy$safe",
                "APP_AUDIT_LOG": os.path.join(self.temp_dir.name, "audit.log"),
            },
            clear=False,
        )
        self.env_patcher.start()
        self.addCleanup(self.env_patcher.stop)
        self.app = create_app()
        self.client = self.app.test_client()

    def _login_session(self) -> None:
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["auth_user"] = "admin"

    def test_update_user_groups_requires_login(self) -> None:
        response = self.client.post("/users/alice/groups", data={"groups": ["finance"]})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_update_user_groups_calls_system_function(self) -> None:
        self._login_session()
        with patch("web_samba_tool.app.update_managed_user_groups") as mock_update:
            response = self.client.post(
                "/users/alice/groups",
                data={"groups": ["finance", "nasusers"]},
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        mock_update.assert_called_once_with("alice", ["finance", "nasusers"])


if __name__ == "__main__":
    unittest.main()
