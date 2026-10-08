"""X-module: rle -- Run-length encode a string."""
from __future__ import annotations
VERSION = "x_20.v1"
def rle(s: str) -> str:
    if not s: return ""
    out, cnt = [], 1
    for i in range(1, len(s)):
        if s[i] == s[i-1]: cnt += 1
        else: out.append(f"{s[i-1]}{cnt}"); cnt = 1
    out.append(f"{s[-1]}{cnt}")
    return "".join(out)

def main() -> None:
    assert rle("aaabbc") == "a3b2c1"
    assert rle("") == ""
    assert rle("x") == "x1"
    print("x_20 rle OK")
if __name__ == "__main__": main()
