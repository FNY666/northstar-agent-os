"""Tiny utility: ar_04 (linear interpolation)."""

def lerp(a,b,t):
    return a+(b-a)*t

def self_test():
    assert lerp(0,10,0.5)==5.0
    assert lerp(2,4,0)==2
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
