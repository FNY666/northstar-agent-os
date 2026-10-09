"""AE-module: capitalize_words -- First letter of each word uppercased."""
from __future__ import annotations
VERSION = "ae_14.v1"
def capitalize_words(s: str) -> str:
    return ' '.join(w[:1].upper() + w[1:] for w in s.split(' '))

def main() -> None:
    assert capitalize_words("hello world") == "Hello World"
    assert capitalize_words("") == ""
    assert capitalize_words("a b") == "A B"
    print("ae_14 capitalize_words OK")
if __name__ == "__main__": main()
