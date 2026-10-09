"""Tiny utility: aq_39."""

diff_seq = lambda xs: [b-a for a, b in zip(xs, xs[1:])]

def self_test():
    assert diff_seq([1,3,6]) == [2,3]
    assert diff_seq([5]) == []
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
