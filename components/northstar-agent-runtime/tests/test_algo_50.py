"""Tests for algo_50: word break (boolean + one segmentation)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import algo_50 as a50
from algo_50 import word_break, word_break_all


def test_version_pin_and_stdlib_only():
    assert a50.ALGO_50_VERSION == "algo-50.v1"
    assert a50.stdlib_only() is True


def test_word_break_classic():
    assert word_break("leetcode", ["leet", "code"]) is True
    assert word_break_all("leetcode", ["leet", "code"]) == ["leet", "code"]


def test_word_break_impossible():
    words = ["cats", "dog", "sand", "and", "cat"]
    assert word_break("catsandog", words) is False
    assert word_break_all("catsandog", words) is None


def test_word_break_edge_cases():
    assert word_break("", []) is True
    assert word_break_all("", []) == []
    assert word_break("a", []) is False
    seg = word_break_all("applepenapple", ["apple", "pen"])
    assert seg is not None
    assert "".join(seg) == "applepenapple"
    assert all(w in ("apple", "pen") for w in seg)
