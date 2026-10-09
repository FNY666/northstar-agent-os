"""Tiny utility: ar_20 (is anagram)."""

def is_anagram(a,b):
    return sorted(a.replace(' ','').lower())==sorted(b.replace(' ','').lower())

def self_test():
    assert is_anagram('listen','silent')
    assert not is_anagram('a','b')
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
