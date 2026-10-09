"""Zip with fillvalue for unequal lengths."""
def zip_long(xs, ys, fill=None):
    n = max(len(xs), len(ys))
    return [(xs[i] if i < len(xs) else fill, ys[i] if i < len(ys) else fill) for i in range(n)]
if __name__ == "__main__":
    assert zip_long([1,2],[3]) == [(1,3),(2,None)]
    assert zip_long([],[]) == []
    assert zip_long([1],[2,3],0) == [(1,2),(0,3)]
    print("ok")
