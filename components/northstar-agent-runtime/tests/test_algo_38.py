"""Tests for algo_38: Huffman coding."""

import importlib.util
from pathlib import Path

import pytest

from algo_38 import build_huffman, decode, encode


def _load(name):
    path = Path(__file__).resolve().parent.parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


algo_38 = _load("algo_38")


def test_version_and_stdlib_only():
    assert algo_38.ALGO_38_VERSION == "algo-38.v1"
    assert algo_38.stdlib_only() is True


def test_round_trip_sample_text():
    text = "the quick brown fox jumps over the lazy dog 1234567890"
    codes, root = build_huffman(text)
    assert set(codes) == set(text)
    bits = encode(text, codes)
    assert set(bits) <= {"0", "1"}
    assert len(bits) < len(text) * 8  # actually compresses
    assert decode(bits, root) == text


def test_prefix_free_invariant():
    text = "aaabbbccddeeffgghhiijj"
    codes, _ = build_huffman(text)
    vals = sorted(codes.values())
    for i, c in enumerate(vals):
        for other in vals[i + 1 :]:
            assert not other.startswith(c), (c, other)
    # Frequent chars get shorter-or-equal codes.
    assert len(codes["a"]) <= len(codes["j"])


def test_edge_cases_empty_single_char():
    codes, root = build_huffman("")
    assert codes == {}
    assert root is None
    assert encode("", codes) == ""
    assert decode("", root) == ""
    codes1, root1 = build_huffman("zzzz")
    assert set(codes1) == {"z"}
    assert decode(encode("zzzz", codes1), root1) == "zzzz"
    codes2, root2 = build_huffman("q")
    assert decode(encode("q", codes2), root2) == "q"


def test_two_chars_round_trip():
    text = "ababababab"
    codes, root = build_huffman(text)
    assert decode(encode(text, codes), root) == text
    assert set(codes) == {"a", "b"}
    assert sorted(codes.values()) == ["0", "1"]


def test_decode_invalid_bits():
    _, root = build_huffman("aaabbc")
    with pytest.raises(ValueError):
        decode("010", root)  # truncated bitstring
