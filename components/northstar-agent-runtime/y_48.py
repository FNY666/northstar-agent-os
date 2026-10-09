"""Y-module: strip_punct -- Remove ASCII punctuation."""
from __future__ import annotations
VERSION = "y_48.v1"
def strip_punct(s: str) -> str:
    import string
    return s.translate(str.maketrans("", "", string.punctuation))

def main() -> None:
    assert strip_punct("hi!") == "hi"
    assert strip_punct("a,b.c") == "abc"
    print("y_48 strip_punct OK")
if __name__ == "__main__": main()
