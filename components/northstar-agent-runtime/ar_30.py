"""Tiny utility: ar_30 (binary search)."""

def bsearch(xs,x):
    lo,hi=0,len(xs)-1
    while lo<=hi:
        m=(lo+hi)//2
        if xs[m]==x:return m
        lo,hi=(m+1,hi) if xs[m]<x else (lo,m-1)
    return -1

def self_test():
    assert bsearch([1,2,3,4],3)==2
    assert bsearch([1,2,3],5)==-1
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
