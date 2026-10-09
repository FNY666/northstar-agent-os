"""Y-module: is_power_of_two -- Check if n is a power of two."""
from __future__ import annotations
VERSION = "y_12.v1"
def is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0

def main() -> None:
    assert is_power_of_two(16) is True
    assert is_power_of_two(18) is False
    print("y_12 is_power_of_two OK")
if __name__ == "__main__": main()
