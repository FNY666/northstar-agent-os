"""AD-module: is_alpha_str -- Check if a string is all letters."""
from __future__ import annotations
VERSION = "ad_16.v1"
def is_alpha_str(s: str) -> bool:
    return len(s) > 0 and s.isalpha()

def main() -> None:
    assert is_alpha_str("abc") is True
    assert is_alpha_str("a1") is False
    assert is_alpha_str("") is False
    print("ad_16 is_alpha_str OK")
if __name__ == "__main__": main()
