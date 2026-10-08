"""intv_37: Exclusive time of functions from logs (exclusive_time).

Stack of running functions; credit elapsed time to the stack top.

Time complexity: O(n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_37 = "intv-37.v1"


def exclusive_time(n, logs):
    """Exclusive CPU time per function id from start/end logs."""
    res = [0] * n
    stack = []
    prev = 0
    for log in logs:
        fid, typ, ts = log.split(":")
        fid, ts = int(fid), int(ts)
        if typ == "start":
            if stack:
                res[stack[-1]] += ts - prev
            stack.append(fid)
            prev = ts
        else:
            res[stack.pop()] += ts - prev + 1
            prev = ts + 1
    return res

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
    assert exclusive_time(2, ["0:start:0", "1:start:2", "1:end:5", "0:end:6"]) == [3, 4]
    assert exclusive_time(1, ["0:start:0", "0:start:2", "0:end:5", "0:start:6", "0:end:6", "0:end:7"]) == [8]
    assert exclusive_time(1, ["0:start:0", "0:end:0"]) == [1]
    assert exclusive_time(3, ["0:start:0", "0:end:1", "1:start:2", "1:end:3", "2:start:4", "2:end:5"]) == [2, 2, 2]
    assert exclusive_time(2, ["0:start:0", "0:end:5"]) == [6, 0]
    assert stdlib_only()
    print("intv_37 OK")


if __name__ == "__main__":
    main()
