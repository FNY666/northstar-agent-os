"""AF-module: b64url_encode -- URL-safe base64 encode a string (no padding)."""
from __future__ import annotations
VERSION = "af_09"
import base64
def b64url_encode(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip('=')

def main() -> None:
    assert b64url_encode('hello') == 'aGVsbG8'
    assert b64url_encode('') == ''
    assert b64url_encode('>>>?') == 'Pj4-Pw'
    print("af_09 b64url_encode OK")
if __name__ == "__main__": main()
