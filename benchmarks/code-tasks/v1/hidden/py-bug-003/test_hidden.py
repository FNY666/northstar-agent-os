import unittest
from unittest.mock import patch
from csv_summary import summarize


class ContractTests(unittest.TestCase):
    def test_blank_records(self):
        self.assertEqual(summarize("name,amount\n , \n\na,1.5\n"), {"count": 1, "total": 1.5})

    def test_quoted(self):
        self.assertEqual(summarize('name,amount\n"a,b",2\n"multi\nline",3\n'), {"count": 2, "total": 5})

    def test_negative(self):
        self.assertEqual(summarize("name,amount\na,-2\nb,0\n"), {"count": 2, "total": -2})


if __name__ == "__main__":
    unittest.main()
