"""Tests for algo_34: trie."""

import importlib.util
from pathlib import Path

import pytest

from algo_34 import Trie


def _load(name):
    path = Path(__file__).resolve().parent.parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


algo_34 = _load("algo_34")


def test_version_and_stdlib_only():
    assert algo_34.ALGO_34_VERSION == "algo-34.v1"
    assert algo_34.stdlib_only() is True


def test_insert_search_starts_with_normal():
    t = Trie()
    words = ["apple", "app", "apricot", "banana", "band"]
    for w in words:
        t.insert(w)
    for w in words:
        assert t.search(w) is True
    assert t.search("appl") is False  # prefix only, not a word
    assert t.search("application") is False
    assert t.search("orange") is False
    assert t.starts_with("app") is True
    assert t.starts_with("ban") is True
    assert t.starts_with("") is True
    assert t.starts_with("z") is False
    assert t.starts_with("applepie") is False


def test_edge_cases_empty_single_duplicate():
    t = Trie()
    assert t.search("a") is False
    assert t.starts_with("a") is False
    assert len(t) == 0
    t.insert("a")
    assert t.search("a") is True
    assert t.starts_with("a") is True
    assert len(t) == 1
    t.insert("a")
    assert len(t) == 1
    t.insert("")  # empty word is storable
    assert t.search("") is True
    assert len(t) == 2


def test_invalid_words_rejected():
    t = Trie()
    with pytest.raises(ValueError):
        t.insert("Hello")
    with pytest.raises(ValueError):
        t.insert("abc123")
    with pytest.raises(ValueError):
        t.search("UPPER")
    with pytest.raises(TypeError):
        t.insert(123)


def test_words_with_prefix():
    t = Trie()
    for w in ["cat", "car", "cart", "dog"]:
        t.insert(w)
    assert t.words_with_prefix("ca") == ["car", "cart", "cat"]
    assert t.words_with_prefix("dog") == ["dog"]
    assert t.words_with_prefix("z") == []
