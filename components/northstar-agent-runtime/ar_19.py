"""Tiny utility: ar_19 (matrix transpose)."""

def transpose(m):
    return [list(r) for r in zip(*m)]

def self_test():
    assert transpose([[1,2],[3,4]])==[[1,3],[2,4]]
    assert transpose([[1,2,3]])==[[1],[2],[3]]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
