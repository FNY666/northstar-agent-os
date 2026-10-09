"""AF-module: slugify -- Lowercase text, replace non-alphanumerics with hyphens."""
from __future__ import annotations
VERSION = "af_07"
import re
def slugify(s: str) -> str:
    return re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-')

def main() -> None:
    assert slugify('Hello World!') == 'hello-world'
    assert slugify('  A--B  ') == 'a-b'
    assert slugify('') == ''
    print("af_07 slugify OK")
if __name__ == "__main__": main()
