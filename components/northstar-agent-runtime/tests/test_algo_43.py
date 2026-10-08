"""Tests for algo_43: longest common subsequence (string + length)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import algo_43 as a43
from algo_43 import lcs, lcs_length


def _is_subsequence(sub: str, s: str) -> bool:
    it = iter(s)
    return all(c in it for c in sub)


def test_version_pin_and_stdlib_only():
    assert a43.ALGO_43_VERSION == "algo-43.v1"
    assert a43.stdlib_only() is True


def test_lcs_classic():
    assert lcs_length("ABCBDAB", "BDCABA") == 4
    got = lcs("ABCBDAB", "BDCABA")
    assert len(got) == 4
    assert _is_subsequence(got, "ABCBDAB")
    assert _is_subsequence(got, "BDCABA")


def test_lcs_edge_cases():
    assert lcs("", "abc") == ""
    assert lcs("abc", "") == ""
    assert lcs_length("", "") == 0
    assert lcs("abc", "xyz") == ""
    assert lcs_length("abc", "xyz") == 0


def test_lcs_identical_and_known():
    assert lcs("abc", "abc") == "abc"
    assert lcs_length("abc", "abc") == 3
    assert lcs_length("AGGTAB", "GXTXAYB") == 4
