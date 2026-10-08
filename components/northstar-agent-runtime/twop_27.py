"""Reverse Words In String (two-pointer), reverse word order and collapse extra spaces. IS: scans the string with two pointers to collect whitespace-separated words, then joins them in reverse order with single spaces. IS NOT: a character-level reversal; word order is reversed but each word's spelling is unchanged."""
from __future__ import annotations

import ast

VERSION = "twop-27.v1"


def reverse_words_in_string(s: str) -> str:
    """Reverse the order of words, collapsing runs of whitespace to single spaces."""
    if not isinstance(s, str):
        raise ValueError("input must be a string")
    words: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        while i < n and s[i].isspace():
            i += 1
        j = i
        while j < n and not s[j].isspace():
            j += 1
        if j > i:
            words.append(s[i:j])
        i = j
    words.reverse()
    return " ".join(words)


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name.split(".")[0] not in allowed for alias in node.names):
                return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert stdlib_only()
    assert reverse_words_in_string("  hello   world  ") == "world hello"
    assert reverse_words_in_string("a") == "a"
    assert reverse_words_in_string("") == ""
    assert reverse_words_in_string("   ") == ""
    assert reverse_words_in_string("the sky is blue") == "blue is sky the"
    try:
        reverse_words_in_string(123)  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non-string input")
    print("twop-27 OK")


if __name__ == "__main__":
    main()
