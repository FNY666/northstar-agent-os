"""Tiny utility: aq_09."""

topn = lambda xs, n: sorted(xs, reverse=True)[:n]

def self_test():
    assert topn([3,1,2],2) == [3,2]
    assert topn([1],5) == [1]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
