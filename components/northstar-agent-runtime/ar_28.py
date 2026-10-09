"""Tiny utility: ar_28 (count vowels)."""

def count_vowels(s):
    return sum(c in 'aeiouAEIOU' for c in s)

def self_test():
    assert count_vowels('hello')==2
    assert count_vowels('xyz')==0
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
