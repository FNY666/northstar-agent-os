"""Tiny utility: aq_37."""

normalize = lambda xs: [(x-min(xs))/(max(xs)-min(xs)) for x in xs] if max(xs) != min(xs) else [0.0]*len(xs)

def self_test():
    assert normalize([1,2,3]) == [0.0,0.5,1.0]
    assert normalize([5,5]) == [0.0,0.0]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
