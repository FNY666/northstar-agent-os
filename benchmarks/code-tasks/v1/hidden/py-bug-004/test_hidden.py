import unittest
from unittest.mock import patch
from pagination import collect


class ContractTests(unittest.TestCase):
    def test_cycle(self):
        with self.assertRaises(ValueError):
            collect(lambda _: {"items": [1], "next_cursor": "repeat"})

    def test_empty_terminates(self):
        calls = []
        def fetch(cursor):
            calls.append(cursor)
            return {"items": [], "next_cursor": "unused"}
        self.assertEqual(collect(fetch), [])
        self.assertEqual(calls, [None])

    def test_preserves_duplicates(self):
        pages = {None: {"items": [1, 1], "next_cursor": "x"}, "x": {"items": [1], "next_cursor": None}}
        self.assertEqual(collect(pages.__getitem__), [1, 1, 1])


if __name__ == "__main__":
    unittest.main()
