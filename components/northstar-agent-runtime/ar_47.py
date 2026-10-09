"""Tiny utility: ar_47 (product)."""

def prod(xs):
    r=1
    for x in xs:r*=x
    return r

def self_test():
    assert prod([2,3,4])==24
    assert prod([])==1
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
