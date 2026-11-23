import unittest
from unittest.mock import patch
from names import normalize_names


class ContractTests(unittest.TestCase):
    def test_ordered(self):
        self.assertEqual(normalize_names([" Alice ", "BOB", "Alice"]), ["alice", "bob", "alice"])

    def test_limit(self):
        with self.assertRaises(ValueError):
            normalize_names(["a", "b"], limit=1)


if __name__ == "__main__":
    unittest.main()
