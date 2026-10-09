"""Tiny utility: aq_21."""

gcd_all = lambda xs: __import__('functools').reduce(__import__('math').gcd, xs)

def self_test():
    assert gcd_all([12,18,24]) == 6
    assert gcd_all([7]) == 7
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
