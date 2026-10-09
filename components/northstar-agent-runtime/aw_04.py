"""Sliding windows of width n over a list."""
def sliding(xs, n):
    return [xs[i:i+n] for i in range(len(xs)-n+1)]
if __name__ == "__main__":
    assert sliding([1,2,3,4], 2) == [[1,2],[2,3],[3,4]]
    assert sliding([1,2], 3) == []
    assert sliding([1,2,3], 1) == [[1],[2],[3]]
    print("ok")
