"""Y-module: celsius_to_fahrenheit -- Convert Celsius to Fahrenheit."""
from __future__ import annotations
VERSION = "y_03.v1"
def celsius_to_fahrenheit(c: float) -> float:
    return c * 9 / 5 + 32

def main() -> None:
    assert celsius_to_fahrenheit(0) == 32
    assert celsius_to_fahrenheit(100) == 212
    print("y_03 celsius_to_fahrenheit OK")
if __name__ == "__main__": main()
