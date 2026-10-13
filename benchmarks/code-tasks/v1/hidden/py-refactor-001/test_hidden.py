import unittest
from unittest.mock import patch
from timestamps import stamp


class ContractTests(unittest.TestCase):
    def test_no_global_patch(self):
        calls = []
        def clock():
            calls.append(1)
            return 0
        with patch("timestamps.time.time", side_effect=AssertionError("global clock used")):
            self.assertEqual(stamp("", clock=clock), {"message": "", "created_at": 0})
        self.assertEqual(calls, [1])

    def test_default_none(self):
        with patch("timestamps.time.time", return_value=1.25):
            self.assertEqual(stamp("x", clock=None)["created_at"], 1.25)


if __name__ == "__main__":
    unittest.main()
