"""Tests for the path a record stores.

The same sample reached through an absolute path and through a relative one
is the same sample. Two records that differ only in how the command was
invoked would be two records of one thing, and would not compare equal.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from record_swe_bench_integrity import _stored_path  # noqa: E402


class StoredPathTests(unittest.TestCase):
    def test_a_relative_path_is_stored_as_it_is(self):
        self.assertEqual(
            _stored_path(Path("benchmarks/swe-bench/verified-50.json")),
            "benchmarks/swe-bench/verified-50.json",
        )

    def test_an_absolute_path_inside_the_repository_is_stored_relative(self):
        root = Path(__file__).resolve().parent.parent
        absolute = root / "benchmarks" / "swe-bench" / "verified-50.json"
        self.assertEqual(
            _stored_path(absolute), "benchmarks/swe-bench/verified-50.json"
        )

    def test_both_ways_of_reaching_a_sample_give_the_same_stored_path(self):
        root = Path(__file__).resolve().parent.parent
        absolute = root / "benchmarks" / "swe-bench" / "verified-50.json"
        relative = Path("benchmarks/swe-bench/verified-50.json")
        self.assertEqual(_stored_path(absolute), _stored_path(relative))

    def test_a_path_outside_the_repository_is_stored_as_it_is(self):
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "elsewhere.json"
            self.assertEqual(_stored_path(outside), outside.as_posix())


if __name__ == "__main__":
    unittest.main()
