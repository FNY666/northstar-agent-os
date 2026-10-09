"""Tiny utility: aq_10."""

botn = lambda xs, n: sorted(xs)[:n]

def self_test():
    assert botn([3,1,2],2) == [1,2]
    assert botn([1],5) == [1]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
