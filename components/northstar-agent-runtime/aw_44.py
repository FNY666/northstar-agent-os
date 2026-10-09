"""Split into (true_items, false_items)."""
def partition(xs, pred):
    t, f = [], []
    for x in xs:
        (t if pred(x) else f).append(x)
    return t, f
if __name__ == "__main__":
    assert partition([1,2,3,4], lambda x: x % 2) == ([1,3],[2,4])
    assert partition([], bool) == ([],[])
    assert partition([1], lambda x: True) == ([1],[])
    print("ok")
