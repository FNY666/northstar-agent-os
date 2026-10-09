"""Tiny utility: aq_36."""

stddev = lambda xs: (sum((x-sum(xs)/len(xs))**2 for x in xs)/len(xs))**0.5

def self_test():
    assert stddev([2,4,4,4,5,5,7,9]) == 2.0
    assert stddev([3,3]) == 0.0
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
