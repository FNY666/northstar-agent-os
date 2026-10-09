"""Tiny utility: ar_37 (partition)."""

def partition(xs,pred):
    t,f=[],[]
    for x in xs:(t if pred(x) else f).append(x)
    return t,f

def self_test():
    assert partition([1,2,3,4],lambda x:x%2==0)==([2,4],[1,3])
    assert partition([],bool)==([],[])
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
