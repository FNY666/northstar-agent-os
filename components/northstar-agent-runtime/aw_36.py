"""k largest items."""
def top_k(xs, k):
    return sorted(xs, reverse=True)[:k]
if __name__ == "__main__":
    assert top_k([3,1,4,1,5], 2) == [5,4]
    assert top_k([1], 5) == [1]
    assert top_k([], 3) == []
    print("ok")
