import unittest
from unittest.mock import patch
from config import merge_config


class ContractTests(unittest.TestCase):
    def test_unknown(self):
        for layers in (({"bad": 1}, None, None), (None, {"bad": 1}, None), (None, None, {"bad": 1})):
            with self.assertRaises(ValueError):
                merge_config({"ok": 1}, *layers)

    def test_immutability(self):
        original = {"nested": [1]}
        result = merge_config(original)
        result["nested"].append(2)
        self.assertEqual(original, {"nested": [1]})

    def test_falsy(self):
        self.assertEqual(merge_config({"value": 1}, {"value": 2}, {"value": 3}, {"value": None}), {"value": None})
        self.assertEqual(merge_config({"value": True}, overrides={"value": False}), {"value": False})


if __name__ == "__main__":
    unittest.main()
