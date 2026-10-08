"""string_compression_inplace (two-pointer), run-length compress a char list in place. IS: in-place run-length encoding (read/write pointers), returns the new length. IS NOT: a string-join compressor or a multi-pass encoder."""
from __future__ import annotations

import ast

VERSION = "twop-44.v1"


def string_compression_inplace(chars: list[str]) -> int:
    """Compress chars in place with run-length encoding; return the new length."""
    if not isinstance(chars, list):
        raise ValueError("chars must be a list")
    for ch in chars:
        if not isinstance(ch, str) or len(ch) != 1:
            raise ValueError("chars must contain only single-character strings")
    write = 0
    read = 0
    n = len(chars)
    while read < n:
        c = chars[read]
        count = 0
        while read < n and chars[read] == c:
            read += 1
            count += 1
        chars[write] = c
        write += 1
        if count > 1:
            for digit in str(count):
                chars[write] = digit
                write += 1
    return write


def stdlib_only() -> bool:
    """AST-parse this file; return False if any import outside the allowed set appears."""
    import pathlib
    src = pathlib.Path(__file__).read_text()
    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    chars = ["a", "a", "b", "b", "c", "c", "c"]
    k = string_compression_inplace(chars)
    assert k == 6 and chars[:k] == ["a", "2", "b", "2", "c", "3"], (k, chars[:k])
    chars = ["a"]
    assert string_compression_inplace(chars) == 1 and chars[:1] == ["a"]
    chars = ["b"] * 12
    k = string_compression_inplace(chars)
    assert k == 3 and chars[:k] == ["b", "1", "2"], (k, chars[:k])  # edge: multi-digit count
    chars = []
    assert string_compression_inplace(chars) == 0
    try:
        string_compression_inplace(["ab", "c"])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for multi-char element")
    assert stdlib_only()
    print("string_compression_inplace OK")


if __name__ == "__main__":
    main()
