"""Tiny utility: aq_06."""

sliding = lambda xs, n: [xs[i:i+n] for i in range(len(xs)-n+1)]

def self_test():
    assert sliding([1,2,3,4],2) == [[1,2],[2,3],[3,4]]
    assert sliding([1],2) == []
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
