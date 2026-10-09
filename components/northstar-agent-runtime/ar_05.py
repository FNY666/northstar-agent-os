"""Tiny utility: ar_05 (gcd)."""

def gcd(a,b):
    while b:
        a,b=b,a%b
    return abs(a)

def self_test():
    assert gcd(12,18)==6
    assert gcd(7,13)==1
    assert gcd(0,5)==5
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
