"""AF-module: short_id -- Random 8-char hex id from UUID4."""
from __future__ import annotations
VERSION = "af_50"
import uuid
def short_id() -> str:
    return uuid.uuid4().hex[:8]

def main() -> None:
    s = short_id()
    assert len(s) == 8
    assert all(c in '0123456789abcdef' for c in s)
    assert short_id() != short_id()
    print("af_50 short_id OK")
if __name__ == "__main__": main()
