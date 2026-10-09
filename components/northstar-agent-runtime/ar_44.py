"""Tiny utility: ar_44 (flatten one level)."""

def flat1(xs):
    return [i for x in xs for i in (x if isinstance(x,(list,tuple)) else [x])]

def self_test():
    assert flat1([[1,2],[3]]) == [1,2,3]
    assert flat1([1,2])==[1,2]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
