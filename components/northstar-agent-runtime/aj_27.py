"""AJ-27: Slugify."""
from __future__ import annotations
VERSION = "aj_27.v1"


import re
def slugify(s):
    return re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-')

def main() -> None:
    assert slugify('Hello, World! 42') == 'hello-world-42'
    assert slugify('  A__B ') == 'a-b'
    print(f"aj_27 OK")
if __name__ == "__main__": main()
