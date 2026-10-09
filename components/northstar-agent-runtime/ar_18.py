"""Tiny utility: ar_18 (dot product)."""

def dot(a,b):
    return sum(x*y for x,y in zip(a,b))

def self_test():
    assert dot([1,2,3],[4,5,6])==32
    assert dot([],[])==0
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
