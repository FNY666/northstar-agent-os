"""MatVec Multiply Util (AI-U-031), Simulated."""
from __future__ import annotations
VERSION = "ai_31.v1"

def matvec(m, v):
    return [sum(x * y for x, y in zip(row, v)) for row in m]

def main() -> None:
    assert matvec([[1, 2], [3, 4]], [1, 1]) == [3, 7]
    assert matvec([], [1]) == []
    print(f"ai_31 OK")
if __name__ == "__main__": main()
