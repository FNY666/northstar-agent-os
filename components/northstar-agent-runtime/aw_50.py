"""Insert x into sorted list."""
def insert_sorted(xs, x):
    xs = list(xs); i = 0
    while i < len(xs) and xs[i] < x:
        i += 1
    return xs[:i] + [x] + xs[i:]
if __name__ == "__main__":
    assert insert_sorted([1,3,5], 4) == [1,3,4,5]
    assert insert_sorted([], 2) == [2]
    assert insert_sorted([1], 0) == [0,1]
    print("ok")
