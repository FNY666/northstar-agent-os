"""AE-module: f_to_c -- Fahrenheit to Celsius."""
from __future__ import annotations
VERSION = "ae_40.v1"
def f_to_c(f: float) -> float:
    return (f - 32) * 5 / 9

def main() -> None:
    assert f_to_c(32) == 0.0
    assert f_to_c(212) == 100.0
    assert f_to_c(-40) == -40.0
    print("ae_40 f_to_c OK")
if __name__ == "__main__": main()
