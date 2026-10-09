"""Tiny utility: aq_34."""

mean = lambda xs: sum(xs)/len(xs)

def self_test():
    assert mean([1,2,3]) == 2.0
    assert mean([5]) == 5.0
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
