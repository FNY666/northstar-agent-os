"""Y-module: word_freq -- Word frequency dict (lowercased)."""
from __future__ import annotations
VERSION = "y_49.v1"
def word_freq(s: str) -> dict:
    d = {}
    for w in s.lower().split(): d[w] = d.get(w, 0) + 1
    return d

def main() -> None:
    assert word_freq("a a b") == {"a": 2, "b": 1}
    assert word_freq("") == {}
    print("y_49 word_freq OK")
if __name__ == "__main__": main()
