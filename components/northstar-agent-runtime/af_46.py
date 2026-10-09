"""AF-module: mask_middle -- Keep first/last chars, mask the middle with '*'."""
from __future__ import annotations
VERSION = "af_46"
def mask_middle(s: str, keep: int = 1) -> str:
    if len(s) <= keep * 2:
        return s
    return s[:keep] + '*' * (len(s) - keep * 2) + s[-keep:]

def main() -> None:
    assert mask_middle('password', 1) == 'p******d'
    assert mask_middle('ab', 1) == 'ab'
    assert mask_middle('abcdef', 2) == 'ab**ef'
    print("af_46 mask_middle OK")
if __name__ == "__main__": main()
