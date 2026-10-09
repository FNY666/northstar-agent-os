"""Tiny utility: aq_05."""

pairwise = lambda xs: list(zip(xs, xs[1:]))

def self_test():
    assert pairwise([1,2,3]) == [(1,2),(2,3)]
    assert pairwise([1]) == []
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
