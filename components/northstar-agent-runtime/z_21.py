"""z_21: slugify."""
from __future__ import annotations
VERSION = "z_21.v1"
def slugify(s):
    import re
    return re.sub(r'[^a-z0-9]+','-',s.lower()).strip('-')

def main() -> None:
    assert slugify('Hello World!')=='hello-world'
    assert slugify('A__B')=='a-b'
    print('z_21 slugify OK')

if __name__ == "__main__": main()
