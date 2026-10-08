"""LZW compression: dictionary coder.

Classic LZW with 256-entry ASCII init; compress emits codes, decompress rebuilds the dictionary in lockstep.

What this IS: a real LZW codec.
What this IS NOT: variable-width code packing.
"""

from __future__ import annotations

import ast

#: Module version.
STR_20_VERSION = "str-lzw.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-lzw-compression.v1"


class StrError(Exception):
    """Fail-closed."""


def lzw_compress(s: str) -> list:
    """Compress to a list of integer codes."""
    if not s:
        return []
    table = {chr(i): i for i in range(256)}
    next_code = 256
    w = ""
    out = []
    for ch in s:
        wc = w + ch
        if wc in table:
            w = wc
        else:
            out.append(table[w])
            table[wc] = next_code
            next_code += 1
            w = ch
    if w:
        out.append(table[w])
    return out


def lzw_decompress(codes: list) -> str:
    """Decompress a list of integer codes."""
    if not codes:
        return ""
    table = {i: chr(i) for i in range(256)}
    next_code = 256
    w = table[codes[0]]
    out = [w]
    for k in codes[1:]:
        if k in table:
            entry = table[k]
        elif k == next_code:
            entry = w + w[0]
        else:
            raise StrError("bad LZW code")
        out.append(entry)
        table[next_code] = w + entry[0]
        next_code += 1
        w = entry
    return "".join(out)


def test_lzw_roundtrip():
    s = "TOBEORNOTTOBEORTOBEORNOT"
    assert lzw_decompress(lzw_compress(s)) == s


def test_lzw_empty():
    assert lzw_compress("") == []
    assert lzw_decompress([]) == ""


def test_lzw_single():
    assert lzw_decompress(lzw_compress("a")) == "a"


def test_lzw_codes_int():
    assert all(isinstance(c, int) for c in lzw_compress("ababab"))


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
    test_lzw_roundtrip()
    test_lzw_empty()
    test_lzw_single()
    test_lzw_codes_int()
    assert stdlib_only()
    print("str-20 OK: lzw")


if __name__ == "__main__":
    main()
