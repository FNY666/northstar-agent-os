"""AJ-30: Checksum sha256."""
from __future__ import annotations
VERSION = "aj_30.v1"


import hashlib
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def main() -> None:
    assert sha256_hex(b'abc') == hashlib.sha256(b'abc').hexdigest()
    assert len(sha256_hex(b'')) == 64
    print(f"aj_30 OK")
if __name__ == "__main__": main()
