"""AD-module: celsius_to_f -- Convert Celsius to Fahrenheit."""
from __future__ import annotations
VERSION = "ad_43.v1"
def celsius_to_f(c: float) -> float:
    return c * 9 / 5 + 32

def main() -> None:
    assert celsius_to_f(0) == 32.0
    assert celsius_to_f(100) == 212.0
    assert celsius_to_f(-40) == -40.0
    print("ad_43 celsius_to_f OK")
if __name__ == "__main__": main()
