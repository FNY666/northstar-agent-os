"""Tiny utility: aq_35."""

variance = lambda xs: sum((x-sum(xs)/len(xs))**2 for x in xs)/len(xs)

def self_test():
    assert variance([2,4,4,4,5,5,7,9]) == 4.0
    assert variance([3,3]) == 0.0
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
