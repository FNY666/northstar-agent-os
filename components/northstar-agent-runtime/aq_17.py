"""Tiny utility: aq_17."""

row_sums = lambda m: [sum(r) for r in m]

def self_test():
    assert row_sums([[1,2],[3,4]]) == [3,7]
    assert row_sums([[]]) == [0]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
