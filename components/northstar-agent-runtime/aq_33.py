"""Tiny utility: aq_33."""

median = lambda xs: _med(sorted(xs))

def _med(s):
    n = len(s)
    return (s[n//2-1]+s[n//2])/2 if n % 2 == 0 else s[n//2]

def self_test():
    assert median([1,3,2]) == 2
    assert median([1,2,3,4]) == 2.5
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
