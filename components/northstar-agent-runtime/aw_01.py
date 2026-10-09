"""Left-rotate a list by k positions."""
def rotate_left(xs, k):
    k %= len(xs)
    return xs[k:] + xs[:k]
if __name__ == "__main__":
    assert rotate_left([1,2,3,4], 1) == [2,3,4,1]
    assert rotate_left([1,2,3,4], 4) == [1,2,3,4]
    assert rotate_left([1,2,3,4], 5) == [2,3,4,1]
    print("ok")
