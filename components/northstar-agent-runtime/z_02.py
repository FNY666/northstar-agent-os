"""z_02: chunk_str."""
from __future__ import annotations
VERSION = "z_02.v1"
def chunk_str(s, n):
    return [s[i:i+n] for i in range(0, len(s), n)]

def main() -> None:
    assert chunk_str('abcdef', 2) == ['ab','cd','ef']
    assert chunk_str('abc', 5) == ['abc']
    print('z_02 chunk_str OK')

if __name__ == "__main__": main()
