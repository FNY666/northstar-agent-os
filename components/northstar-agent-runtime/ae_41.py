"""AE-module: human_bytes -- Byte count as human-readable string."""
from __future__ import annotations
VERSION = "ae_41.v1"
def human_bytes(n: int) -> str:
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    v = float(n)
    for u in units:
        if v < 1024 or u == 'TB':
            return f'{v:.1f} {u}'
        v /= 1024
    return f'{v:.1f} TB'

def main() -> None:
    assert human_bytes(0) == "0.0 B"
    assert human_bytes(1024) == "1.0 KB"
    assert human_bytes(1536) == "1.5 KB"
    print("ae_41 human_bytes OK")
if __name__ == "__main__": main()
