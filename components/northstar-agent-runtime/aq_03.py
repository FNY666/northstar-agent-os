"""Tiny utility: aq_03."""

rotate = lambda xs, k: xs[k % len(xs):] + xs[:k % len(xs)]

def self_test():
    assert rotate([1,2,3,4],1) == [2,3,4,1]
    assert rotate([1,2,3],3) == [1,2,3]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
