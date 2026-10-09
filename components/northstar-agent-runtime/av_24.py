"""Hamming distance between equal-length sequences."""
def hamming(a, b):
    if len(a) != len(b):
        raise ValueError("length mismatch")
    return sum(x != y for x, y in zip(a, b))
if __name__ == "__main__":
    assert hamming("karolin", "kathrin") == 3
    assert hamming("abc", "abc") == 0
    assert hamming([1, 2], [1, 3]) == 1
    print("ok")
