"""Rotate a sequence left by k positions."""
def rotate(seq, k):
    if not seq:
        return list(seq)
    k %= len(seq)
    return list(seq[k:]) + list(seq[:k])
if __name__ == "__main__":
    assert rotate([1, 2, 3, 4], 1) == [2, 3, 4, 1]
    assert rotate([1, 2, 3], 0) == [1, 2, 3]
    assert rotate([1, 2], 3) == [2, 1]
    print("ok")
