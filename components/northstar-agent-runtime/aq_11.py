"""Tiny utility: aq_11."""

pad = lambda xs, n, v=0: xs + [v] * max(0, n - len(xs))

def self_test():
    assert pad([1,2],4) == [1,2,0,0]
    assert pad([1,2,3],2) == [1,2,3]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
