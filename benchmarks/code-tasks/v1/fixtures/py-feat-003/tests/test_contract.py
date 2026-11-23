import unittest
from unittest.mock import patch
from jsonl_summary import summarize


class ContractTests(unittest.TestCase):
    def test_total(self):
        self.assertEqual(summarize(['{"value":2}\n', "\n", '{"value":3}']), {"records": 2, "total": 5})

    def test_invalid_line(self):
        with self.assertRaisesRegex(ValueError, "line 2"):
            summarize(['{"value":1}', "broken"])


if __name__ == "__main__":
    unittest.main()
