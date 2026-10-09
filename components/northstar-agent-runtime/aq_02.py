"""Tiny utility: aq_02."""

chunk = lambda xs, n: [xs[i:i+n] for i in range(0, len(xs), n)]

def self_test():
    assert chunk([1,2,3,4,5],2) == [[1,2],[3,4],[5]]
    assert chunk([],3) == []
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
