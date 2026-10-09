"""Tiny utility: aq_19."""

diag = lambda m: [m[i][i] for i in range(min(len(m), len(m[0]) if m else 0))] if m else []

def self_test():
    assert diag([[1,2],[3,4]]) == [1,4]
    assert diag([]) == []
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
