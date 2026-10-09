"""Tiny utility: ar_17 (stddev)."""

def stddev(xs):
    m=sum(xs)/len(xs)
    return (sum((x-m)**2 for x in xs)/len(xs))**0.5

def self_test():
    assert abs(stddev([2,4,4,4,5,5,7,9])-2.0)<1e-9
    assert stddev([5,5])==0.0
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
