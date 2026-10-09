"""Tiny utility: aq_01."""

flatten = lambda xs: [i for x in xs for i in (flatten(x) if isinstance(x, list) else [x])]

def self_test():
    assert flatten([1,[2,[3]],4]) == [1,2,3,4]
    assert flatten([]) == []
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
