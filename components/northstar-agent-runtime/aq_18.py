"""Tiny utility: aq_18."""

col_sums = lambda m: [sum(c) for c in zip(*m)]

def self_test():
    assert col_sums([[1,2],[3,4]]) == [4,6]
    assert col_sums([[]]) == []
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
