"""ak_29: Pangram check."""

def is_pangram(s):
    import string
    return set(string.ascii_lowercase) <= set(s.lower())

if __name__ == '__main__':
    assert is_pangram('The quick brown fox jumps over the lazy dog')
    assert not is_pangram('hello')
    print('ok')
