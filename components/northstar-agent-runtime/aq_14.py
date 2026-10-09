"""Tiny utility: aq_14."""

window_sum = lambda xs, n: [sum(xs[i:i+n]) for i in range(len(xs)-n+1)]

def self_test():
    assert window_sum([1,2,3,4],2) == [3,5,7]
    assert window_sum([1],2) == []
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
