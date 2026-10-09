"""Split a list into chunks of size n."""
def chunks(xs, n):
    return [xs[i:i+n] for i in range(0, len(xs), n)]
if __name__ == "__main__":
    assert chunks([1,2,3,4,5], 2) == [[1,2],[3,4],[5]]
    assert chunks([], 3) == []
    assert chunks([1], 5) == [[1]]
    print("ok")
