"""AF-module: split_sentences -- Split text into sentences on . ! ? boundaries."""
from __future__ import annotations
VERSION = "af_44"
import re
def split_sentences(s: str) -> list:
    return [t for t in re.split(r'(?<=[.!?])\s+', s.strip()) if t]

def main() -> None:
    assert split_sentences('Hi! How are you? Fine.') == ['Hi!', 'How are you?', 'Fine.']
    assert split_sentences('') == []
    assert split_sentences('No punct') == ['No punct']
    print("af_44 split_sentences OK")
if __name__ == "__main__": main()
