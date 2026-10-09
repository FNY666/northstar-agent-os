"""Tiny utility: aq_32."""

mode = lambda xs: max(set(xs), key=xs.count)

def self_test():
    assert mode([1,2,2,3]) == 2
    assert mode([5]) == 5
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
