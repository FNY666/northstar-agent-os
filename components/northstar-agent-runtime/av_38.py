"""Manhattan distance between two points."""
def manhattan(a, b):
    return sum(abs(x - y) for x, y in zip(a, b))
if __name__ == "__main__":
    assert manhattan((0, 0), (3, 4)) == 7
    assert manhattan([1, 2], [1, 2]) == 0
    assert manhattan((1,), (4,)) == 3
    print("ok")
