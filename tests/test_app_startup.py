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
class AppStartupTests(unittest.TestCase):
    def test_startup_fails_with_placeholder_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(
                os.environ,
                {
                    "APP_SECRET": "change-me-in-production",
                    "APP_ADMIN_USER": "admin",
                    "APP_ADMIN_PASSWORD_HASH": "scrypt:32768:8:1$dummy$dummy",
                    "APP_AUDIT_LOG": os.path.join(temp_dir, "audit.log"),
                },
                clear=False,
            ):
                with self.assertRaisesRegex(RuntimeError, "APP_SECRET"):
                    create_app()

    def test_startup_fails_with_placeholder_password_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.dict(
                os.environ,
                {
                    "APP_SECRET": "a" * 64,
                    "APP_ADMIN_USER": "admin",
                    "APP_ADMIN_PASSWORD_HASH": "replace-with-werkzeug-hash",
                    "APP_AUDIT_LOG": os.path.join(temp_dir, "audit.log"),
                },
                clear=False,
            ):
                with self.assertRaisesRegex(RuntimeError, "APP_ADMIN_PASSWORD_HASH"):
                    create_app()


if __name__ == "__main__":
    unittest.main()
