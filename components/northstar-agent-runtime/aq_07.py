"""Tiny utility: aq_07."""

interleave = lambda a, b: [x for t in zip(a, b) for x in t]

def self_test():
    assert interleave([1,3],[2,4]) == [1,2,3,4]
    assert interleave([1],[]) == []
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
