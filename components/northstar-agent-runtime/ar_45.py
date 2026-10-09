"""Tiny utility: ar_45 (count occurrences)."""

def count_eq(xs,v):
    return sum(1 for x in xs if x==v)

def self_test():
    assert count_eq([1,2,1,1],1)==3
    assert count_eq([],0)==0
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
