"""Tiny utility: ar_16 (variance)."""

def variance(xs):
    m=sum(xs)/len(xs)
    return sum((x-m)**2 for x in xs)/len(xs)

def self_test():
    assert variance([2,4,4,4,5,5,7,9])==4.0
    assert variance([1,1])==0.0
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
