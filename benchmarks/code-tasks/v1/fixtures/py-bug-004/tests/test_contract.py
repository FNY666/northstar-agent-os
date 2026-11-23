import unittest
from unittest.mock import patch
from pagination import collect


class ContractTests(unittest.TestCase):
    def test_page_boundaries(self):
        pages = {None: {"items": [1, 2], "next_cursor": "a"}, "a": {"items": [3], "next_cursor": None}}
        self.assertEqual(collect(pages.__getitem__), [1, 2, 3])

    def test_single(self):
        self.assertEqual(collect(lambda _: {"items": [0], "next_cursor": None}), [0])


if __name__ == "__main__":
    unittest.main()
