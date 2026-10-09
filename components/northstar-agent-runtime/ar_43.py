"""Tiny utility: ar_43 (nth)."""

def nth(n,xs,default=None):
    xs=list(xs)
    return xs[n] if 0<=n<len(xs) else default

def self_test():
    assert nth(1,[5,6])==6
    assert nth(5,[1]) is None
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
