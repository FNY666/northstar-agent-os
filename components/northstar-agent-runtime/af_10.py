"""AF-module: sha256_hex -- SHA-256 hex digest of a string."""
from __future__ import annotations
VERSION = "af_10"
import hashlib
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def main() -> None:
    assert sha256_hex('abc') == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    assert len(sha256_hex('')) == 64
    assert sha256_hex('abc') != sha256_hex('abd')
    print("af_10 sha256_hex OK")
if __name__ == "__main__": main()
