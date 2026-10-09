"""Tiny utility: aq_43."""

anagram = lambda a, b: sorted(a) == sorted(b)

def self_test():
    assert anagram('abc','cba')
    assert not anagram('abc','abd')
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
