"""Tiny utility: ar_46 (range of)."""

def rng(xs):
    return max(xs)-min(xs)

def self_test():
    assert rng([1,5,3])==4
    assert rng([7])==0
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
