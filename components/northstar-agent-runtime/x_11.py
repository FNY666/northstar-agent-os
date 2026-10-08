"""X-module: slugify -- Basic slugify to lowercase dashes."""
from __future__ import annotations
VERSION = "x_11.v1"
import re
def slugify(s: str) -> str:
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")

def main() -> None:
    assert slugify("Hello World!") == "hello-world"
    assert slugify("  a__b  ") == "a-b"
    print("x_11 slugify OK")
if __name__ == "__main__": main()
