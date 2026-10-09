"""Right-rotate a list by k positions."""
def rotate_right(xs, k):
    k %= len(xs)
    return xs[-k:] + xs[:-k] if k else xs[:]
if __name__ == "__main__":
    assert rotate_right([1,2,3,4], 1) == [4,1,2,3]
    assert rotate_right([1,2,3,4], 0) == [1,2,3,4]
    assert rotate_right([1,2,3,4], 4) == [1,2,3,4]
    print("ok")
