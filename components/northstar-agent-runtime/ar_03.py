"""Tiny utility: ar_03 (clamp)."""

def clamp(x,lo,hi):
    return max(lo,min(hi,x))

def self_test():
    assert clamp(5,0,10)==5
    assert clamp(-3,0,10)==0
    assert clamp(99,0,10)==10
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
