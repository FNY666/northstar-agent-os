"""Backtracking: cryptarithmetic solver (SEND + MORE = MONEY style).

IS: assigns distinct decimal digits to letters so that a sum of addend
words equals a result word, solved column-by-column from the least
significant digit with carry propagation; leading letters may not be
zero. IS NOT: a general equation solver - only addition of whole words,
no subtraction/multiplication, no multi-solution enumeration, and no
claim that a "nice" puzzle has a unique solution.
"""

import ast
from typing import Dict, List, Optional, Tuple

VERSION = "backtrack_22.v1"


def solve_cryptarithm(
    addends: List[str], result: str
) -> Optional[Dict[str, int]]:
    """Return a letter->digit mapping satisfying sum(addends) == result,
    or None if no mapping exists."""
    words = addends + [result]
    seen = set()
    letters: List[str] = []
    leading = set()
    for w in words:
        leading.add(w[0])
        for ch in w:
            if ch not in seen:
                seen.add(ch)
                letters.append(ch)
    if len(letters) > 10:
        return None
    maxlen = max(len(w) for w in words)
    cols: List[Tuple[List[Optional[str]], Optional[str]]] = []
    for i in range(maxlen):
        a = [w[-1 - i] if i < len(w) else None for w in addends]
        r = result[-1 - i] if i < len(result) else None
        cols.append((a, r))

    assign: Dict[str, int] = {}
    used = [False] * 10

    def try_column(col_letters: List[str], idx: int,
                   add_letters: List[Optional[str]],
                   res_letter: Optional[str], pos: int, carry: int) -> bool:
        if idx == len(col_letters):
            total = carry + sum(assign[ch] for ch in add_letters
                                if ch is not None)
            d, nc = total % 10, total // 10
            if res_letter is None:
                return d == 0 and dfs(pos + 1, nc)
            if res_letter in assign:
                return assign[res_letter] == d and dfs(pos + 1, nc)
            if used[d] or (d == 0 and res_letter in leading):
                return False
            assign[res_letter] = d
            used[d] = True
            if dfs(pos + 1, nc):
                return True
            del assign[res_letter]
            used[d] = False
            return False
        ch = col_letters[idx]
        for dg in range(10):
            if used[dg]:
                continue
            if dg == 0 and ch in leading:
                continue
            assign[ch] = dg
            used[dg] = True
            if try_column(col_letters, idx + 1, add_letters,
                           res_letter, pos, carry):
                return True
            del assign[ch]
            used[dg] = False
        return False

    def dfs(pos: int, carry: int) -> bool:
        if pos == maxlen:
            return carry == 0
        add_letters, res_letter = cols[pos]
        col_letters: List[str] = []
        for ch in add_letters:
            if ch is not None and ch not in assign and ch not in col_letters:
                col_letters.append(ch)
        return try_column(col_letters, 0, add_letters, res_letter, pos, carry)

    if dfs(0, 0):
        return dict(assign)
    return None


def _word_value(word: str, mapping: Dict[str, int]) -> int:
    return int("".join(str(mapping[ch]) for ch in word))


def stdlib_only(path: Optional[str] = None) -> bool:
    """Parse this file with ast; True iff every import is stdlib-allowed."""
    allowed = {"typing", "dataclasses", "itertools", "ast"}
    with open(path or __file__, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod and mod not in allowed:
                return False
    return True


def main() -> None:
    assert stdlib_only()
    # Classic: SEND + MORE = MONEY.
    m = solve_cryptarithm(["SEND", "MORE"], "MONEY")
    assert m is not None
    assert len(set(m.values())) == len(m)
    assert all(m[w[0]] != 0 for w in ("SEND", "MORE", "MONEY"))
    assert _word_value("SEND", m) + _word_value("MORE", m) == _word_value("MONEY", m)
    assert (_word_value("SEND", m), _word_value("MORE", m), _word_value("MONEY", m)) == (9567, 1085, 10652)
    # Tiny solvable case.
    m2 = solve_cryptarithm(["A", "B"], "C")
    assert m2 is not None
    assert m2["A"] + m2["B"] == m2["C"]
    assert m2["A"] != 0 and m2["B"] != 0 and m2["C"] != 0
    # 3-digit word can never equal a 2-digit word -> unsolvable.
    assert solve_cryptarithm(["ABC"], "AB") is None
    # More letters than digits -> unsolvable.
    assert solve_cryptarithm(["ABCDEFGHIJK"], "A") is None
    print("backtrack_22 OK")


if __name__ == "__main__":
    main()
