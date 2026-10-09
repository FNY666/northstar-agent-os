"""TF-IDF Term Freq Util (AI-U-017), Simulated."""
from __future__ import annotations
VERSION = "ai_17.v1"

def term_freq(tokens):
    from collections import Counter
    c = Counter(tokens)
    n = len(tokens)
    return {t: c[t] / n for t in c}

def main() -> None:
    assert term_freq(['a', 'a', 'b']) == {'a': 2/3, 'b': 1/3}
    assert term_freq([]) == {}
    print(f"ai_17 OK")
if __name__ == "__main__": main()
