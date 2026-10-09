"""au_04: Caesar-shift letters."""
def caesar_cipher(s, shift):
    """Shift A-Z/a-z letters by shift positions."""
    out = []
    for ch in s:
        if 'a' <= ch <= 'z':
            out.append(chr((ord(ch)-97+shift) % 26 + 97))
        elif 'A' <= ch <= 'Z':
            out.append(chr((ord(ch)-65+shift) % 26 + 65))
        else:
            out.append(ch)
    return ''.join(out)

def _run_tests():
    assert caesar_cipher('abc', 1) == 'bcd'
    assert caesar_cipher('XYZ', 2) == 'ZAB'

if __name__ == "__main__":
    _run_tests()
    print("au_04 OK")
