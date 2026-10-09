"""Round Robin Util (AI-U-038), Simulated."""
from __future__ import annotations
VERSION = "ai_38.v1"

def round_robin(items, n):
    return [items[i % len(items)] for i in range(n)]

def main() -> None:
    assert round_robin(['a', 'b'], 5) == ['a', 'b', 'a', 'b', 'a']
    assert round_robin(['x'], 3) == ['x', 'x', 'x']
    print(f"ai_38 OK")
if __name__ == "__main__": main()
