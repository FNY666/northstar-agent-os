"""ak_21: Caesar cipher."""

def caesar(s, shift):
    out = []
    for c in s:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            out.append(chr((ord(c) - base + shift) % 26 + base))
        else: out.append(c)
    return ''.join(out)

if __name__ == '__main__':
    assert caesar('abc', 1) == 'bcd'
    assert caesar('XYZ', 2) == 'ZAB'
    print('ok')
