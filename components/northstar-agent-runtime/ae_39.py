"""AE-module: c_to_f -- Celsius to Fahrenheit."""
from __future__ import annotations
VERSION = "ae_39.v1"
def c_to_f(c: float) -> float:
    return c * 9 / 5 + 32

def main() -> None:
    assert c_to_f(0) == 32.0
    assert c_to_f(100) == 212.0
    assert c_to_f(-40) == -40.0
    print("ae_39 c_to_f OK")
if __name__ == "__main__": main()
