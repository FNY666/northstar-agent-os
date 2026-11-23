import unittest
from unittest.mock import patch
from timestamps import stamp


class ContractTests(unittest.TestCase):
    def test_legacy(self):
        with patch("timestamps.time.time", return_value=10):
            self.assertEqual(stamp("hello"), {"message": "hello", "created_at": 10})

    def test_injected(self):
        self.assertEqual(stamp("hello", clock=lambda: 20), {"message": "hello", "created_at": 20})


if __name__ == "__main__":
    unittest.main()
