"""Sliding windows of size k over a sequence."""
def sliding_window(seq, k):
    seq = list(seq)
    return [seq[i:i + k] for i in range(len(seq) - k + 1)]
if __name__ == "__main__":
    assert sliding_window([1, 2, 3, 4], 2) == [[1, 2], [2, 3], [3, 4]]
    assert sliding_window([1], 2) == []
    assert sliding_window([1, 2, 3], 3) == [[1, 2, 3]]
    print("ok")
