"""z_26: rot13."""
from __future__ import annotations
VERSION = "z_26.v1"
def rot13(s):
    import codecs
    return codecs.encode(s,'rot13')

def main() -> None:
    assert rot13('hello')=='uryyb'
    assert rot13('uryyb')=='hello'
    print('z_26 rot13 OK')

if __name__ == "__main__": main()
