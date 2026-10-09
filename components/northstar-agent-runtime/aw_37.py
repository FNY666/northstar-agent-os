"""nth smallest (0-indexed)."""
def nth_smallest(xs, n):
    return sorted(xs)[n]
if __name__ == "__main__":
    assert nth_smallest([5,3,4,1,2], 0) == 1
    assert nth_smallest([5,3,4,1,2], 4) == 5
    assert nth_smallest([2,2,1], 1) == 2
    print("ok")
