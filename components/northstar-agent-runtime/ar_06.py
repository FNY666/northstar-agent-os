"""Tiny utility: ar_06 (lcm)."""

def lcm(a,b):
    from math import gcd
    return abs(a*b)//gcd(a,b) if a and b else 0

def self_test():
    assert lcm(4,6)==12
    assert lcm(0,5)==0
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
