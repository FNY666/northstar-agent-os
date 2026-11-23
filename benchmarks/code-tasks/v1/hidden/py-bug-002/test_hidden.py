import unittest
from unittest.mock import patch
from cache import Cache


class ContractTests(unittest.TestCase):
    def test_zero(self):
        cache = Cache(clock=lambda: 2.0)
        cache.set("key", "value", 0)
        with self.assertRaises(KeyError):
            cache.get("key")

    def test_monotonic(self):
        with patch("cache.time.time", side_effect=AssertionError("wall clock forbidden")):
            cache = Cache()
            cache.set("key", False, 100)
            self.assertIs(cache.get("key"), False)

    def test_overwrite(self):
        now = [1.0]
        cache = Cache(clock=lambda: now[0])
        cache.set("key", "old", 2)
        cache.set("key", "new", 4)
        now[0] = 3.0
        self.assertEqual(cache.get("key"), "new")


if __name__ == "__main__":
    unittest.main()
