"""AD-module: is_digit_str -- Check if a string is all digits."""
from __future__ import annotations
VERSION = "ad_15.v1"
def is_digit_str(s: str) -> bool:
    return len(s) > 0 and s.isdigit()

def main() -> None:
    assert is_digit_str("123") is True
    assert is_digit_str("12a") is False
    assert is_digit_str("") is False
    print("ad_15 is_digit_str OK")
if __name__ == "__main__": main()
