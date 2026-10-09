"""Tiny utility: ar_36 (interleave)."""

def interleave(a,b):
    out=[]
    for x,y in zip(a,b):out+=[x,y]
    return out+list(a[len(b):])+list(b[len(a):])

def self_test():
    assert interleave([1,3],[2,4])==[1,2,3,4]
    assert interleave([1],[2,3])==[1,2,3]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
