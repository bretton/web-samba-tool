import os
import unittest
from unittest.mock import patch

from web_samba_tool.auth import (
    clear_failed_login,
    login_retry_after_seconds,
    record_failed_login,
    reset_login_rate_limit_state_for_tests,
)


class LoginRateLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_login_rate_limit_state_for_tests()

    def tearDown(self) -> None:
        reset_login_rate_limit_state_for_tests()

    def test_lockout_after_max_failed_attempts(self) -> None:
        ip = "10.0.0.25"
        with patch.dict(
            os.environ,
            {
                "APP_LOGIN_MAX_ATTEMPTS": "2",
                "APP_LOGIN_WINDOW_SECONDS": "120",
                "APP_LOGIN_LOCKOUT_SECONDS": "300",
            },
            clear=False,
        ):
            self.assertEqual(login_retry_after_seconds(ip), 0)
            self.assertEqual(record_failed_login(ip), 0)

            lockout_seconds = record_failed_login(ip)
            self.assertEqual(lockout_seconds, 300)
            self.assertGreaterEqual(login_retry_after_seconds(ip), 1)

            clear_failed_login(ip)
            self.assertEqual(login_retry_after_seconds(ip), 0)


if __name__ == "__main__":
    unittest.main()
