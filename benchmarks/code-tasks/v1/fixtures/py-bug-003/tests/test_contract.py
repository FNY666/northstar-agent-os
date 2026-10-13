import unittest
from unittest.mock import patch
from csv_summary import summarize


class ContractTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(summarize(""), {"count": 0, "total": 0})
        self.assertEqual(summarize("name,amount\n"), {"count": 0, "total": 0})

    def test_regular(self):
        self.assertEqual(summarize("name,amount\na,2\nb,3\n"), {"count": 2, "total": 5})


if __name__ == "__main__":
    unittest.main()
