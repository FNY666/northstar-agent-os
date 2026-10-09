"""Tiny utility: aq_08."""

counts = lambda xs: {x: xs.count(x) for x in set(xs)}

def self_test():
    assert counts([1,1,2]) == {1:2,2:1}
    assert counts([]) == {}
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
