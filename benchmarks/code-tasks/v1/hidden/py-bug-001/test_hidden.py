from __future__ import annotations

import unittest

from retry import retry


class HiddenRetryTests(unittest.TestCase):
    def test_non_positive_limit_is_rejected_without_calling_operation(self):
        for limit in (0, -1):
            calls = 0

            def operation() -> None:
                nonlocal calls
                calls += 1

            with self.subTest(limit=limit), self.assertRaises(ValueError):
                retry(operation, max_attempts=limit)
            self.assertEqual(calls, 0)

    def test_last_exception_object_is_preserved(self):
        last = RuntimeError("last")
        failures = [RuntimeError("first"), last]

        def fail() -> None:
            raise failures.pop(0)

        with self.assertRaises(RuntimeError) as raised:
            retry(fail, max_attempts=2)
        self.assertIs(raised.exception, last)
        self.assertEqual(str(raised.exception), "last")

    def test_unmatched_exception_is_not_retried(self):
        calls = 0

        def fail() -> None:
            nonlocal calls
            calls += 1
            raise TypeError("stop")

        with self.assertRaises(TypeError):
            retry(fail, max_attempts=3, exceptions=(ValueError,))
        self.assertEqual(calls, 1)


if __name__ == "__main__":
    unittest.main()
