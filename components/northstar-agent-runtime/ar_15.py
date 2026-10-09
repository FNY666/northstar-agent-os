"""Tiny utility: ar_15 (mode)."""

def mode(xs):
    return max(set(xs),key=xs.count)

def self_test():
    assert mode([1,2,2,3])==2
    assert mode(['a','b','a'])=='a'
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
