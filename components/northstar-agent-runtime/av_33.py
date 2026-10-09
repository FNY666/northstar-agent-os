"""Interleave multiple sequences, stopping at shortest."""
def interleave(*seqs):
    return [x for tup in zip(*seqs) for x in tup]
if __name__ == "__main__":
    assert interleave([1, 2], "ab") == [1, "a", 2, "b"]
    assert interleave([1, 2, 3], [9]) == [1, 9]
    assert interleave([], []) == []
    print("ok")
