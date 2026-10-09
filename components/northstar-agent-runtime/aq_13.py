"""Tiny utility: aq_13."""

mirror = lambda xs: xs + xs[::-1]

def self_test():
    assert mirror([1,2]) == [1,2,2,1]
    assert mirror([]) == []
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
