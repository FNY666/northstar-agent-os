"""Unique Ordered Util (AI-U-046), Simulated."""
from __future__ import annotations
VERSION = "ai_46.v1"

def unique_ordered(xs):
    seen, out = set(), []
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def main() -> None:
    assert unique_ordered([3, 1, 3, 2, 1]) == [3, 1, 2]
    assert unique_ordered([]) == []
    print(f"ai_46 OK")
if __name__ == "__main__": main()
