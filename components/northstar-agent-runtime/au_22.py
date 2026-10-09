"""au_22: ROT13 encode/decode."""
def rot13(s):
    """Apply ROT13 to s."""
    out = []
    for ch in s:
        b = ord('a') if 'a' <= ch <= 'z' else ord('A') if 'A' <= ch <= 'Z' else None
        out.append(chr((ord(ch)-b+13) % 26 + b) if b is not None else ch)
    return ''.join(out)

def _run_tests():
    assert rot13('hello') == 'uryyb'
    assert rot13(rot13('abc')) == 'abc'

if __name__ == "__main__":
    _run_tests()
    print("au_22 OK")
