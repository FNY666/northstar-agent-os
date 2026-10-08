"""Run-length encoding: lossless run compression.

Encodes runs as char+count; decodes back exactly (digits in input are not supported).

What this IS: a real RLE codec.
What this IS NOT: digit-safe escaping; out of scope.
"""

from __future__ import annotations

import ast

#: Module version.
STR_18_VERSION = "str-rle.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-run-length-encoding.v1"


class StrError(Exception):
    """Fail-closed."""


def rle_encode(s: str) -> str:
    """Encode runs: 'aaabbc' -> 'a3b2c1'."""
    if not s:
        return ""
    out = []
    count = 1
    for i in range(1, len(s)):
        if s[i] == s[i - 1]:
            count += 1
        else:
            out.append("%s%d" % (s[i - 1], count))
            count = 1
    out.append("%s%d" % (s[-1], count))
    return "".join(out)


def rle_decode(s: str) -> str:
    """Decode an RLE string back to the original."""
    out = []
    i = 0
    while i < len(s):
        ch = s[i]
        i += 1
        num = []
        while i < len(s) and s[i].isdigit():
            num.append(s[i])
            i += 1
        if not num:
            raise StrError("malformed RLE: missing count")
        out.append(ch * int("".join(num)))
    return "".join(out)


def test_rle_encode():
    assert rle_encode("aaabbc") == "a3b2c1"


def test_rle_roundtrip():
    assert rle_decode(rle_encode("aaabbbcccaaa")) == "aaabbbcccaaa"


def test_rle_empty():
    assert rle_encode("") == ""
    assert rle_decode("") == ""


def test_rle_single():
    assert rle_encode("z") == "z1"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    test_rle_encode()
    test_rle_roundtrip()
    test_rle_empty()
    test_rle_single()
    assert stdlib_only()
    print("str-18 OK: rle")


if __name__ == "__main__":
    main()
