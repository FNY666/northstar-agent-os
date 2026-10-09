"""Tiny utility: aq_20."""

trace = lambda m: sum(m[i][i] for i in range(min(len(m), len(m[0]) if m else 0))) if m else 0

def self_test():
    assert trace([[1,2],[3,4]]) == 5
    assert trace([]) == 0
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
