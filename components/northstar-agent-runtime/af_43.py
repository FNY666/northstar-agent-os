"""AF-module: word_stats -- Count words, chars, and lines in text."""
from __future__ import annotations
VERSION = "af_43"
def word_stats(s: str) -> dict:
    return {'words': len(s.split()), 'chars': len(s), 'lines': s.count(chr(10)) + 1 if s else 0}

def main() -> None:
    assert word_stats('a bb\nccc') == {'words': 3, 'chars': 8, 'lines': 2}
    assert word_stats('') == {'words': 0, 'chars': 0, 'lines': 0}
    assert word_stats('one') == {'words': 1, 'chars': 3, 'lines': 1}
    print("af_43 word_stats OK")
if __name__ == "__main__": main()
