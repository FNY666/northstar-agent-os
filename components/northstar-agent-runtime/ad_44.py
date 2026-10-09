"""AD-module: f_to_celsius -- Convert Fahrenheit to Celsius."""
from __future__ import annotations
VERSION = "ad_44.v1"
def f_to_celsius(f: float) -> float:
    return (f - 32) * 5 / 9

def main() -> None:
    assert f_to_celsius(32) == 0.0
    assert f_to_celsius(212) == 100.0
    assert abs(f_to_celsius(98.6) - 37.0) < 1e-9
    print("ad_44 f_to_celsius OK")
if __name__ == "__main__": main()
