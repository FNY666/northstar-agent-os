"""Tiny utility: aq_44."""

is_pangram = lambda s: set('abcdefghijklmnopqrstuvwxyz') <= set(s.lower())

def self_test():
    assert is_pangram('The quick brown fox jumps over the lazy dog')
    assert not is_pangram('hello')
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
