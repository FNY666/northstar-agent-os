"""Tiny utility: aq_45."""

caesar = lambda s, k: ''.join(chr(97+(ord(c)-97+k)%26) if 'a' <= c <= 'z' else c for c in s)

def self_test():
    assert caesar('abc',1) == 'bcd'
    assert caesar('xyz',3) == 'abc'
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
