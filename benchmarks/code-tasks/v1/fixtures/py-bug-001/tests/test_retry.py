from __future__ import annotations

import unittest

from retry import retry


class RetryTests(unittest.TestCase):
    def test_attempt_limit_is_total_number_of_calls(self):
        calls = 0

        def fail() -> None:
            nonlocal calls
            calls += 1
            raise RuntimeError("no")

        with self.assertRaisesRegex(RuntimeError, "no"):
            retry(fail, max_attempts=3)
        self.assertEqual(calls, 3)

    def test_success_returns_without_an_extra_call(self):
        calls = 0

        def succeed() -> str:
            nonlocal calls
            calls += 1
            return "ok"

        self.assertEqual(retry(succeed), "ok")
        self.assertEqual(calls, 1)


if __name__ == "__main__":
    unittest.main()
