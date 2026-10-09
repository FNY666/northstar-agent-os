"""AJ-29: Hex dump."""
from __future__ import annotations
VERSION = "aj_29.v1"


def hexdump(data: bytes, width=16):
    lines = []
    for i in range(0, len(data), width):
        lines.append(f'{i:04x}  {data[i:i+width].hex(" ")}')
    return lines

def main() -> None:
    assert hexdump(b'AB') == ['0000  41 42']
    assert hexdump(b'') == []
    print(f"aj_29 OK")
if __name__ == "__main__": main()
