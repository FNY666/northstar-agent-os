"""Tiny utility: aq_50."""

clamp = lambda v, lo, hi: max(lo, min(hi, v))

def self_test():
    assert clamp(5,0,10) == 5
    assert clamp(15,0,10) == 10
    assert clamp(-1,0,10) == 0
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
