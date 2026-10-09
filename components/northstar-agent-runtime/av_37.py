"""Euclidean distance between two points."""
import math
def euclid(a, b):
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))
if __name__ == "__main__":
    assert euclid((0, 0), (3, 4)) == 5.0
    assert euclid([1], [1]) == 0.0
    assert abs(euclid((0, 0), (1, 1)) - math.sqrt(2)) < 1e-9
    print("ok")
