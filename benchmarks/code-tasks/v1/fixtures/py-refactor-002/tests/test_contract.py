import unittest
from unittest.mock import patch
import formats
from formats import parse


class ContractTests(unittest.TestCase):
    def test_legacy(self):
        self.assertEqual(parse("json", '{"a":1}'), {"a": 1})
        self.assertEqual(parse("csv", 'a,"b,c"\n'), [["a", "b,c"]])

    def test_registration(self):
        formats.register_parser("public-upper", str.upper)
        self.assertEqual(parse("public-upper", "hello"), "HELLO")


if __name__ == "__main__":
    unittest.main()
