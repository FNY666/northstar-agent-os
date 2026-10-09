"""Tiny utility: aq_12."""

stripnone = lambda xs: [x for x in xs if x is not None]

def self_test():
    assert stripnone([1,None,2]) == [1,2]
    assert stripnone([None]) == []
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
