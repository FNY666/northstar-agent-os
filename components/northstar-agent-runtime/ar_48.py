"""Tiny utility: ar_48 (all equal)."""

def all_eq(xs):
    xs=list(xs)
    return all(x==xs[0] for x in xs)

def self_test():
    assert all_eq([2,2,2])
    assert not all_eq([1,2])
    assert all_eq([])
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
