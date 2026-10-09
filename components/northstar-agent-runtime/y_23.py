"""Y-module: common_prefix -- Longest common prefix of strings."""
from __future__ import annotations
VERSION = "y_23.v1"
def common_prefix(ss: list) -> str:
    if not ss: return ""
    p = ss[0]
    for s in ss[1:]:
        while not s.startswith(p): p = p[:-1]
    return p

def main() -> None:
    assert common_prefix(["flower", "flow", "flight"]) == "fl"
    assert common_prefix(["a"]) == "a"
    print("y_23 common_prefix OK")
if __name__ == "__main__": main()
