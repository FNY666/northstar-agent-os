import unittest
from unittest.mock import patch
import formats
from formats import parse


class ContractTests(unittest.TestCase):
    def test_stable_error(self):
        with self.assertRaisesRegex(ValueError, "^unknown format: missing$"):
            parse("missing", "x")

    def test_duplicate(self):
        with self.assertRaises(ValueError):
            formats.register_parser("json", lambda _: None)

    def test_propagate(self):
        failure = RuntimeError("parser failed")
        def fail(_):
            raise failure
        formats.register_parser("hidden-error", fail)
        with self.assertRaises(RuntimeError) as raised:
            parse("hidden-error", "")
        self.assertIs(raised.exception, failure)


if __name__ == "__main__":
    unittest.main()
