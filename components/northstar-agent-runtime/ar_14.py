"""Tiny utility: ar_14 (median)."""

def median(xs):
    s=sorted(xs);n=len(s);m=n//2
    return s[m] if n%2 else (s[m-1]+s[m])/2

def self_test():
    assert median([3,1,2])==2
    assert median([1,2,3,4])==2.5
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
