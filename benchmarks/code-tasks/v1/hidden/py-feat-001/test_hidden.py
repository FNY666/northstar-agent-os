import unittest
from unittest.mock import patch
from names import normalize_names


class ContractTests(unittest.TestCase):
    def test_unicode(self):
        self.assertEqual(normalize_names(["Straße\u2003Name", "\t\n"]), ["strasse name", ""])

    def test_bounded_consumption(self):
        def source():
            yield "a"
            yield "b"
            raise AssertionError("consumed after detecting the limit")
        with self.assertRaises(ValueError):
            normalize_names(source(), limit=1)

    def test_edge_cases(self):
        self.assertEqual(normalize_names([], limit=0), [])
        with self.assertRaises(TypeError):
            normalize_names([None])
        with self.assertRaises(ValueError):
            normalize_names([], limit=-1)


if __name__ == "__main__":
    unittest.main()
