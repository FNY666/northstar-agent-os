import unittest
from unittest.mock import patch
from cache import Cache


class ContractTests(unittest.TestCase):
    def test_boundary(self):
        now = [10.0]
        cache = Cache(clock=lambda: now[0])
        cache.set("key", "value", 2)
        now[0] = 12.0
        with self.assertRaises(KeyError):
            cache.get("key")

    def test_before(self):
        cache = Cache(clock=lambda: 5.0)
        cache.set("key", 0, 1)
        self.assertEqual(cache.get("key"), 0)


if __name__ == "__main__":
    unittest.main()
