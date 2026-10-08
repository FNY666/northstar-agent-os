"""Backtracking: crossword-fill on a small blocked grid.

IS: fills every maximal horizontal/vertical slot (length >= 2) of a tiny
grid with words from a caller-supplied word list, respecting pre-filled
letters and crossing constraints; each word is used at most once.
IS NOT: a real crossword generator - no clue semantics, no symmetry
rules, no dictionary beyond the given list, and no claim about solution
uniqueness or puzzle quality.
"""

import ast
from typing import Dict, List, Optional, Tuple

VERSION = "backtrack_21.v1"


def _find_slots(board: List[List[str]]) -> List[List[Tuple[int, int]]]:
    rows = len(board)
    cols = len(board[0])
    slots: List[List[Tuple[int, int]]] = []
    for r in range(rows):
        c = 0
        while c < cols:
            if board[r][c] != "#":
                start = c
                while c < cols and board[r][c] != "#":
                    c += 1
                if c - start >= 2:
                    slots.append([(r, cc) for cc in range(start, c)])
            else:
                c += 1
    for c in range(cols):
        r = 0
        while r < rows:
            if board[r][c] != "#":
                start = r
                while r < rows and board[r][c] != "#":
                    r += 1
                if r - start >= 2:
                    slots.append([(rr, c) for rr in range(start, r)])
            else:
                r += 1
    return slots


def solve_crossword(grid: List[str], words: List[str]) -> Optional[List[str]]:
    """Fill the grid; '#' = block, '.' = empty, letter = pre-filled.

    Returns the filled grid as a list of strings, or None if unsolvable.
    """
    board = [list(row) for row in grid]
    slots = _find_slots(board)
    by_len: Dict[int, List[int]] = {}
    for i, w in enumerate(words):
        by_len.setdefault(len(w), []).append(i)
    used = [False] * len(words)

    def fits(slot: List[Tuple[int, int]], wi: int) -> bool:
        w = words[wi]
        for (r, c), ch in zip(slot, w):
            b = board[r][c]
            if b != "." and b != ch:
                return False
        return True

    def place(slot: List[Tuple[int, int]], wi: int) -> List[str]:
        saved = []
        for (r, c), ch in zip(slot, words[wi]):
            saved.append(board[r][c])
            board[r][c] = ch
        return saved

    def unplace(slot: List[Tuple[int, int]], saved: List[str]) -> None:
        for (r, c), ch in zip(slot, saved):
            board[r][c] = ch

    order = sorted(range(len(slots)), key=lambda s: len(slots[s]))

    def dfs(k: int) -> bool:
        if k == len(order):
            return True
        slot = slots[order[k]]
        for wi in by_len.get(len(slot), []):
            if used[wi] or not fits(slot, wi):
                continue
            used[wi] = True
            saved = place(slot, wi)
            if dfs(k + 1):
                return True
            unplace(slot, saved)
            used[wi] = False
        return False

    if dfs(0):
        return ["".join(row) for row in board]
    return None


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
    # 2x3: rows and crossing columns must all come from the word list.
    got = solve_crossword(["...", "..."], ["cat", "dog", "cd", "ao", "tg"])
    assert got == ["cat", "dog"]
    # Pre-filled letter respected.
    assert solve_crossword(["a."], ["ab"]) == ["ab"]
    # No word of matching length -> unsolvable.
    assert solve_crossword(["..."], ["ab", "cd"]) is None
    # Blocked cell splits slots; crossings must agree.
    assert solve_crossword(["a#c", "..."], ["bab", "ab", "cb"]) == ["a#c", "bab"]
    print("backtrack_21 OK")


if __name__ == "__main__":
    main()
