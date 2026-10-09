"""Tiny utility: ar_49 (zip with index)."""

def zindex(xs):
    return list(enumerate(xs))

def self_test():
    assert zindex(['a','b'])==[(0,'a'),(1,'b')]
    assert zindex([])==[]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
