import unittest
from unittest.mock import patch
from config import merge_config


class ContractTests(unittest.TestCase):
    def test_precedence(self):
        self.assertEqual(merge_config({"port": 1}, {"port": 2}, {"port": 3}, {"port": 4}), {"port": 4})

    def test_omitted(self):
        self.assertEqual(merge_config({"enabled": True}), {"enabled": True})


if __name__ == "__main__":
    unittest.main()
