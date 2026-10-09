"""Dot product of two equal-length vectors."""
def dot(a, b):
    if len(a) != len(b):
        raise ValueError("length mismatch")
    return sum(x * y for x, y in zip(a, b))
if __name__ == "__main__":
    assert dot([1, 2, 3], [4, 5, 6]) == 32
    assert dot([], []) == 0
    assert dot([2], [3]) == 6
    print("ok")
