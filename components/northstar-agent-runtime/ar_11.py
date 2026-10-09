"""Tiny utility: ar_11 (reverse words)."""

def rev_words(s):
    return ' '.join(s.split()[::-1])

def self_test():
    assert rev_words('a b c')=='c b a'
    assert rev_words('  x  y ')== 'y x'
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
