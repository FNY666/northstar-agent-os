"""Asteroid Collision: survivors after pairwise impacts. IS: a stack where right-moving asteroids wait and left-moving ones collide. IS NOT: a physics simulation; sizes are integers and ties destroy both."""

from __future__ import annotations

import ast

VERSION = "stack-08.v1"

def _req_rocks(asteroids: object) -> list[int]:
    if not isinstance(asteroids, list):
        raise ValueError("asteroids must be a list")
    for a in asteroids:
        if isinstance(a, bool) or not isinstance(a, int) or a == 0:
            raise ValueError("asteroids must be non-zero ints")
    return list(asteroids)


def asteroid_collision(asteroids: list[int]) -> list[int]:
    """State after all collisions. Fail-closed on bad input."""
    rocks = _req_rocks(asteroids)
    stack: list[int] = []
    for a in rocks:
        alive = True
        while alive and a < 0 < (stack[-1] if stack else 0):
            top = stack[-1]
            if top < -a:
                stack.pop()
            elif top == -a:
                stack.pop()
                alive = False
            else:
                alive = False
        if alive:
            stack.append(a)
    return stack

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert asteroid_collision([5, 10, -5]) == [5, 10]
    assert asteroid_collision([8, -8]) == []
    assert asteroid_collision([10, 2, -5]) == [10]
    assert asteroid_collision([-2, -1, 1, 2]) == [-2, -1, 1, 2]
    assert asteroid_collision([]) == []
    try:
        asteroid_collision([0, 5])
    except ValueError:
        pass
    else:
        raise AssertionError("zero asteroid must raise ValueError")
    assert stdlib_only()
    print("stack_08 OK")


if __name__ == "__main__":
    main()
