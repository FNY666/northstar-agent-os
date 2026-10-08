"""intv_42: Minimum clips to cover [0, time] (video_stitching).

Greedy: repeatedly extend coverage with the clip reaching farthest.

Time complexity: O(n log n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys

INTV_42 = "intv-42.v1"


def video_stitching(clips, time):
    """Min clips covering [0, time]; -1 when impossible."""
    clips = sorted(clips)
    used = 0
    cur_end = 0
    i = 0
    n = len(clips)
    while cur_end < time:
        best = cur_end
        while i < n and clips[i][0] <= cur_end:
            if clips[i][1] > best:
                best = clips[i][1]
            i += 1
        if best == cur_end:
            return -1
        used += 1
        cur_end = best
    return used

def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every import is a used stdlib module."""
    with open(__file__, encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node.module or "").split(".")[0]
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
    for alias, top in imported.items():
        assert top in sys.stdlib_module_names, "non-stdlib import: %s" % top
        assert alias in used, "imported but unused: %s" % alias
    return True


def main() -> None:
    assert video_stitching([[0, 2], [4, 6], [8, 10], [1, 9], [1, 5], [5, 9]], 10) == 3
    assert video_stitching([[0, 1], [1, 2]], 5) == -1
    assert video_stitching([[0, 1], [6, 8], [0, 2], [5, 6], [0, 4], [0, 3], [6, 7], [1, 3], [4, 7], [1, 4], [2, 5], [2, 6], [3, 4], [4, 5], [5, 7], [6, 9]], 9) == 3
    assert video_stitching([[0, 5]], 5) == 1
    assert video_stitching([], 1) == -1
    assert stdlib_only()
    print("intv_42 OK")


if __name__ == "__main__":
    main()
