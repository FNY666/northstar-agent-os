"""Backtracking: restore IP addresses.

IS: given a digit string, enumerate all ways to place 3 dots so the four
segments form a valid IPv4 address (LeetCode 93): 1-3 digits per segment,
no leading zeros unless the segment is exactly "0", each segment in
[0, 255]. The search branches over segment lengths 1..3 and prunes
invalid segments immediately.

IS NOT: IPv6, CIDR parsing, or validating an already-dotted address -
the input is a bare digit string and the output is the set of valid
restorations.

Self-test harness: run ``python backtrack_14.py``.
"""

from typing import List

VERSION = "backtrack_14.v1"

_ALLOWED_IMPORTS = frozenset({"typing", "dataclasses", "itertools", "ast"})


def stdlib_only() -> bool:
    """Parse this file with ``ast``; True only if every import comes from the
    allowed stdlib set."""
    import ast

    with open(__file__, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=__file__)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in _ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0:
                return False
            if (node.module or "").split(".")[0] not in _ALLOWED_IMPORTS:
                return False
    return True


def _valid_segment(seg: str) -> bool:
    if not seg or len(seg) > 3:
        return False
    if len(seg) > 1 and seg.startswith("0"):
        return False
    return int(seg) <= 255


def restore_ip(s: str) -> List[str]:
    """All valid IPv4 addresses restorable from digit string s."""
    results: List[str] = []

    def dfs(start: int, parts: List[str]) -> None:
        if len(parts) == 4:
            if start == len(s):
                results.append(".".join(parts))
            return
        for end in range(start + 1, min(start + 4, len(s) + 1)):
            seg = s[start:end]
            if _valid_segment(seg):
                parts.append(seg)
                dfs(end, parts)
                parts.pop()

    dfs(0, [])
    return results


def _is_valid_ip(addr: str) -> bool:
    parts = addr.split(".")
    return len(parts) == 4 and all(_valid_segment(p) for p in parts)


def main() -> None:
    # Classic example.
    got = restore_ip("25525511135")
    assert sorted(got) == ["255.255.11.135", "255.255.111.35"], got
    # All zeros -> only 0.0.0.0 (leading zeros forbidden).
    assert restore_ip("0000") == ["0.0.0.0"]
    # Five known restorations.
    got = restore_ip("101023")
    assert sorted(got) == [
        "1.0.10.23",
        "1.0.102.3",
        "10.1.0.23",
        "10.10.2.3",
        "101.0.2.3",
    ], got
    # Every emitted address is valid and consumes the whole input.
    for addr in restore_ip("1111"):
        assert _is_valid_ip(addr)
        assert addr.replace(".", "") == "1111"
    # Too long for 4 segments -> nothing.
    assert restore_ip("1" * 13) == []
    assert stdlib_only() is True
    print("backtrack_14 OK")


if __name__ == "__main__":
    main()
