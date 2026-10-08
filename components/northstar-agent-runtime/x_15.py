"""X-module: human_bytes -- Bytes to human readable size."""
from __future__ import annotations
VERSION = "x_15.v1"
def human_bytes(n: int) -> str:
    if n < 0: raise ValueError("n must be >= 0")
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB": return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024

def main() -> None:
    assert human_bytes(0) == "0 B"
    assert human_bytes(2048) == "2.0 KB"
    print("x_15 human_bytes OK")
if __name__ == "__main__": main()
