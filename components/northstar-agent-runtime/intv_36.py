"""intv_36: Asteroid collision via stack (asteroid_collision).

Right-moving asteroids stack up; left-moving ones collide with the stack top.

Time complexity: O(n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_36 = "intv-36.v1"


def asteroid_collision(asteroids):
    """Simulate collisions; return survivors."""
    stack = []
    for a in asteroids:
        while stack and a < 0 < stack[-1]:
            if stack[-1] < -a:
                stack.pop()
                continue
            if stack[-1] == -a:
                stack.pop()
            break
        else:
            stack.append(a)
    return stack

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
    assert asteroid_collision([5, 10, -5]) == [5, 10]
    assert asteroid_collision([8, -8]) == []
    assert asteroid_collision([10, 2, -5]) == [10]
    assert asteroid_collision([-2, -1, 1, 2]) == [-2, -1, 1, 2]
    assert asteroid_collision([1, -2, -2, -2]) == [-2, -2, -2]
    assert stdlib_only()
    print("intv_36 OK")


if __name__ == "__main__":
    main()
