"""Tiny utility: aq_38."""

cum_sum = lambda xs: _cs(xs)

def _cs(xs):
    t = 0
    r = []
    for x in xs:
        t += x
        r.append(t)
    return r

def self_test():
    assert cum_sum([1,2,3]) == [1,3,6]
    assert cum_sum([]) == []
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
