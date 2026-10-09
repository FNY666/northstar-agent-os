"""AD-module: km_to_miles -- Convert kilometers to miles."""
from __future__ import annotations
VERSION = "ad_45.v1"
def km_to_miles(km: float) -> float:
    return km * 0.621371

def main() -> None:
    assert abs(km_to_miles(1) - 0.621371) < 1e-9
    assert km_to_miles(0) == 0.0
    assert km_to_miles(10) == 6.21371
    print("ad_45 km_to_miles OK")
if __name__ == "__main__": main()
