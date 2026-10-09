"""at_25: join_words -- Join words with sep."""
from __future__ import annotations
VERSION = "at_25.v1"
def join_words(ws, sep=' '):
    return sep.join(ws)

def main() -> None:
    assert join_words(['a', 'b']) == 'a b'
    assert join_words(['a', 'b'], '-') == 'a-b'
    print("at_25 join_words OK")
if __name__ == "__main__": main()
