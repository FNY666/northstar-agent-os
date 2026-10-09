"""Y-module: title_words -- Capitalize each word."""
from __future__ import annotations
VERSION = "y_21.v1"
def title_words(s: str) -> str:
    return " ".join(w.capitalize() for w in s.split())

def main() -> None:
    assert title_words("hello world") == "Hello World"
    assert title_words("") == ""
    print("y_21 title_words OK")
if __name__ == "__main__": main()
