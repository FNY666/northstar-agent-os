"""X-module: safe_int -- Parse int, return default on failure."""
from __future__ import annotations
VERSION = "x_17.v1"
def safe_int(s, default: int = 0) -> int:
    try: return int(str(s).strip())
    except (ValueError, TypeError): return default

def main() -> None:
    assert safe_int("42") == 42
    assert safe_int("abc") == 0
    assert safe_int("abc", -1) == -1
    print("x_17 safe_int OK")
if __name__ == "__main__": main()
