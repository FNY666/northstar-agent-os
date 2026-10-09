"""AJ-28: URL-safe base64."""
from __future__ import annotations
VERSION = "aj_28.v1"


import base64
def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')
def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

def main() -> None:
    assert b64d(b64e(b'hello')) == b'hello'
    assert b64e(b'') == ''
    print(f"aj_28 OK")
if __name__ == "__main__": main()
