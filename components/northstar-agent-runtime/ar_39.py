"""Tiny utility: ar_39 (is sorted)."""

def is_sorted(xs):
    return all(a<=b for a,b in zip(xs,xs[1:]))

def self_test():
    assert is_sorted([1,2,2,3])
    assert not is_sorted([2,1])
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
