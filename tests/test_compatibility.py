"""Static cross-component compatibility matrix tests."""
from __future__ import annotations

import unittest

try:
    from compatibility import compatibility_errors
except ModuleNotFoundError:  # direct `python -m unittest tests.test_compatibility`
    from tests.compatibility import compatibility_errors


class CompatibilityMatrixTests(unittest.TestCase):
    def test_packaging_and_cross_runtime_contracts_are_aligned(self):
        self.assertEqual(compatibility_errors(), [])


if __name__ == "__main__":
    unittest.main()
